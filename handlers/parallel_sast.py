"""
Parallel SAST Analyzer

High-performance static analysis using parallel agents.
Supports multiple parallelization strategies:
1. AsyncIO batching (local, fast)
2. Multi-agent orchestration (distributed)
3. Cursor Background Agents API (cloud-scale)
"""

import asyncio
import aiohttp
import os
import time
import json
from pathlib import Path
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import logging

from handlers.sast_analyzer import SASTAnalyzer, Finding
from handlers.codebase_detector import CodebaseDetector, CodebaseContext, CodebaseType

logger = logging.getLogger(__name__)


@dataclass
class BatchResult:
    """Result from a parallel batch"""
    batch_id: int
    files: List[str]
    findings: List[Finding]
    execution_time: float
    error: Optional[str] = None


@dataclass
class ParallelStats:
    """Statistics from parallel execution"""
    total_files: int
    total_batches: int
    total_findings: int
    total_time: float
    parallel_time: float
    speedup: float
    files_per_second: float
    cost: float = 0.0


class ParallelSASTAnalyzer:
    """
    Parallel SAST analyzer using multiple strategies.
    
    Strategies:
    - asyncio: Local async batching (5-10x speedup)
    - multiprocess: CPU-bound parallelization
    - cursor_agents: Cursor Background Agents API (up to 256 agents)
    
    Usage:
        analyzer = ParallelSASTAnalyzer(max_workers=8)
        results = await analyzer.analyze_parallel(repo_path)
    """
    
    def __init__(
        self,
        max_workers: int = 8,
        batch_size: int = 5,
        model: str = "gpt4o-mini",
        api_key: Optional[str] = None,
        strategy: str = "asyncio"  # asyncio, multiprocess, cursor_agents
    ):
        """
        Initialize parallel analyzer.
        
        Args:
            max_workers: Maximum parallel workers/agents
            batch_size: Files per batch
            model: LLM model to use
            api_key: API key for LLM
            strategy: Parallelization strategy
        """
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.model = model
        self.api_key = api_key
        self.strategy = strategy
        
        # Create base analyzer for sequential fallback and context detection
        self.base_analyzer = SASTAnalyzer(
            model=model,
            api_key=api_key,
            use_openrouter=True
        )
        
        # Stats tracking
        self.stats = {
            'batches_completed': 0,
            'total_findings': 0,
            'errors': 0,
            'start_time': None
        }
    
    async def analyze_parallel(
        self,
        repo_path: str,
        scope: str = "full_codebase",
        changed_files: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> tuple[List[Finding], ParallelStats]:
        """
        Analyze codebase in parallel.
        
        Args:
            repo_path: Path to repository
            scope: Analysis scope
            changed_files: Optional list of changed files
            progress_callback: Optional callback(completed, total)
            
        Returns:
            Tuple of (findings, stats)
        """
        start_time = time.time()
        self.stats['start_time'] = start_time
        
        logger.info(f"🚀 Starting parallel SAST analysis")
        logger.info(f"   Strategy: {self.strategy}")
        logger.info(f"   Workers: {self.max_workers}")
        logger.info(f"   Batch size: {self.batch_size}")
        
        # Step 1: Detect codebase context (done once)
        logger.info("📊 Detecting codebase context...")
        self.base_analyzer.codebase_context = self.base_analyzer.codebase_detector.analyze(repo_path)
        context = self.base_analyzer.codebase_context
        logger.info(f"   Type: {context.codebase_type.value}")
        
        # Step 2: Collect files
        files = self.base_analyzer._collect_files(repo_path, scope, changed_files)
        logger.info(f"📁 Files to analyze: {len(files)}")
        
        if not files:
            return [], ParallelStats(0, 0, 0, 0, 0, 1.0, 0)
        
        # Step 3: Create batches
        batches = self._create_batches(files)
        logger.info(f"📦 Created {len(batches)} batches")
        
        # Step 4: Execute based on strategy
        if self.strategy == "asyncio":
            results = await self._execute_asyncio(batches, progress_callback)
        elif self.strategy == "multiprocess":
            results = await self._execute_multiprocess(batches, progress_callback)
        elif self.strategy == "cursor_agents":
            results = await self._execute_cursor_agents(batches, repo_path, progress_callback)
        else:
            raise ValueError(f"Unknown strategy: {self.strategy}")
        
        # Step 5: Aggregate and deduplicate
        all_findings = []
        for batch_result in results:
            if batch_result.findings:
                all_findings.extend(batch_result.findings)
        
        # Apply false positive filters
        filtered_findings = self.base_analyzer.apply_false_positive_filters(all_findings)
        
        # Calculate stats
        end_time = time.time()
        total_time = end_time - start_time
        parallel_time = max(r.execution_time for r in results) if results else 0
        sequential_estimate = sum(r.execution_time for r in results)
        speedup = sequential_estimate / parallel_time if parallel_time > 0 else 1.0
        
        stats = ParallelStats(
            total_files=len(files),
            total_batches=len(batches),
            total_findings=len(filtered_findings),
            total_time=total_time,
            parallel_time=parallel_time,
            speedup=speedup,
            files_per_second=len(files) / total_time if total_time > 0 else 0,
            cost=self._estimate_cost(results)
        )
        
        logger.info(f"✅ Parallel analysis complete:")
        logger.info(f"   Total time: {total_time:.1f}s")
        logger.info(f"   Speedup: {speedup:.1f}x")
        logger.info(f"   Findings: {len(filtered_findings)}")
        logger.info(f"   Files/sec: {stats.files_per_second:.1f}")
        
        return filtered_findings, stats
    
    def export_findings(self, findings: List[Finding], output_path: str, format: str = "json"):
        """Export findings to file (delegates to base analyzer)"""
        return self.base_analyzer.export_findings(findings, output_path, format)

    def _create_batches(self, files: List[str]) -> List[List[str]]:
        """Create file batches for parallel processing"""
        batches = []
        for i in range(0, len(files), self.batch_size):
            batch = files[i:i + self.batch_size]
            batches.append(batch)
        return batches
    
    async def _execute_asyncio(
        self,
        batches: List[List[str]],
        progress_callback: Optional[Callable]
    ) -> List[BatchResult]:
        """Execute using asyncio with semaphore-limited concurrency"""
        
        semaphore = asyncio.Semaphore(self.max_workers)
        results = []
        completed = 0
        
        async def analyze_batch(batch_id: int, files: List[str]) -> BatchResult:
            nonlocal completed
            async with semaphore:
                start = time.time()
                try:
                    # Run analysis in thread pool to avoid blocking
                    loop = asyncio.get_event_loop()
                    findings = await loop.run_in_executor(
                        None,
                        self._analyze_batch_sync,
                        batch_id,
                        files
                    )
                    
                    elapsed = time.time() - start
                    completed += 1
                    
                    if progress_callback:
                        progress_callback(completed, len(batches))
                    
                    logger.debug(f"   Batch {batch_id}: {len(findings)} findings in {elapsed:.1f}s")
                    
                    return BatchResult(
                        batch_id=batch_id,
                        files=files,
                        findings=findings,
                        execution_time=elapsed
                    )
                    
                except Exception as e:
                    logger.error(f"   Batch {batch_id} error: {e}")
                    return BatchResult(
                        batch_id=batch_id,
                        files=files,
                        findings=[],
                        execution_time=time.time() - start,
                        error=str(e)
                    )
        
        # Create all tasks
        tasks = [
            analyze_batch(i, batch)
            for i, batch in enumerate(batches)
        ]
        
        # Execute all in parallel (limited by semaphore)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for r in results:
            if isinstance(r, BatchResult):
                valid_results.append(r)
            elif isinstance(r, Exception):
                logger.error(f"Batch failed: {r}")
        
        return valid_results
    
    def _analyze_batch_sync(self, batch_id: int, files: List[str]) -> List[Finding]:
        """Synchronous batch analysis (runs in thread pool)"""
        findings = []
        
        for file_path in files:
            try:
                file_findings = self.base_analyzer._analyze_file(file_path, None)
                findings.extend(file_findings)
            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
        
        return findings
    
    async def _execute_multiprocess(
        self,
        batches: List[List[str]],
        progress_callback: Optional[Callable]
    ) -> List[BatchResult]:
        """Execute using multiprocessing for CPU-bound work"""
        
        from concurrent.futures import ProcessPoolExecutor
        import multiprocessing
        
        # Use min of max_workers and CPU count
        workers = min(self.max_workers, multiprocessing.cpu_count())
        
        loop = asyncio.get_event_loop()
        results = []
        
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = []
            
            for i, batch in enumerate(batches):
                # Submit to process pool
                future = loop.run_in_executor(
                    executor,
                    self._analyze_batch_process,
                    i,
                    batch,
                    self.model,
                    self.api_key
                )
                futures.append(future)
            
            # Wait for all to complete
            results = await asyncio.gather(*futures, return_exceptions=True)
        
        # Convert to BatchResult
        batch_results = []
        for i, r in enumerate(results):
            if isinstance(r, dict):
                batch_results.append(BatchResult(
                    batch_id=i,
                    files=batches[i],
                    findings=[Finding(**f) for f in r.get('findings', [])],
                    execution_time=r.get('time', 0)
                ))
            elif isinstance(r, Exception):
                batch_results.append(BatchResult(
                    batch_id=i,
                    files=batches[i],
                    findings=[],
                    execution_time=0,
                    error=str(r)
                ))
        
        return batch_results
    
    @staticmethod
    def _analyze_batch_process(
        batch_id: int,
        files: List[str],
        model: str,
        api_key: str
    ) -> Dict:
        """Static method for multiprocess execution"""
        start = time.time()
        
        # Create new analyzer in this process
        analyzer = SASTAnalyzer(model=model, api_key=api_key, use_openrouter=True)
        
        findings = []
        for file_path in files:
            try:
                file_findings = analyzer._analyze_file(file_path, None)
                findings.extend([f.to_dict() for f in file_findings])
            except Exception as e:
                pass
        
        return {
            'findings': findings,
            'time': time.time() - start
        }
    
    async def _execute_cursor_agents(
        self,
        batches: List[List[str]],
        repo_path: str,
        progress_callback: Optional[Callable]
    ) -> List[BatchResult]:
        """
        Execute using Cursor Background Agents API.
        
        Requires CURSOR_API_KEY environment variable.
        Supports up to 256 concurrent agents.
        """
        cursor_api_key = os.environ.get('CURSOR_API_KEY')
        if not cursor_api_key:
            logger.warning("CURSOR_API_KEY not set, falling back to asyncio")
            return await self._execute_asyncio(batches, progress_callback)
        
        logger.info(f"🔷 Using Cursor Background Agents API")
        
        # API endpoint
        api_base = "https://api.cursor.com/v1"
        
        results = []
        agent_ids = []
        
        async with aiohttp.ClientSession() as session:
            # Step 1: Create agents for each batch
            for i, batch in enumerate(batches[:self.max_workers]):  # Limit to max_workers
                agent_id = await self._create_cursor_agent(
                    session, api_base, cursor_api_key,
                    batch_id=i,
                    files=batch,
                    repo_path=repo_path
                )
                if agent_id:
                    agent_ids.append((i, agent_id, batch))
            
            logger.info(f"   Created {len(agent_ids)} Cursor agents")
            
            # Step 2: Poll for completion
            pending = set(agent_ids)
            while pending:
                completed_agents = []
                
                for batch_id, agent_id, files in list(pending):
                    status = await self._check_cursor_agent(
                        session, api_base, cursor_api_key, agent_id
                    )
                    
                    if status.get('status') == 'completed':
                        findings = self._parse_cursor_output(status.get('output', ''))
                        results.append(BatchResult(
                            batch_id=batch_id,
                            files=files,
                            findings=findings,
                            execution_time=status.get('duration', 0)
                        ))
                        completed_agents.append((batch_id, agent_id, files))
                    elif status.get('status') == 'failed':
                        results.append(BatchResult(
                            batch_id=batch_id,
                            files=files,
                            findings=[],
                            execution_time=0,
                            error=status.get('error', 'Unknown error')
                        ))
                        completed_agents.append((batch_id, agent_id, files))
                
                for agent in completed_agents:
                    pending.discard(agent)
                
                if pending:
                    await asyncio.sleep(2)  # Poll every 2 seconds
        
        return results
    
    async def _create_cursor_agent(
        self,
        session: aiohttp.ClientSession,
        api_base: str,
        api_key: str,
        batch_id: int,
        files: List[str],
        repo_path: str
    ) -> Optional[str]:
        """Create a Cursor background agent"""
        
        # Build analysis prompt
        files_list = "\n".join(files)
        prompt = f"""Analyze these files for security vulnerabilities:

{files_list}

Focus on:
- SQL/NoSQL injection
- XSS vulnerabilities
- Authentication/authorization flaws
- Sensitive data exposure

Return findings as JSON array.
"""
        
        try:
            async with session.post(
                f"{api_base}/agents",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "repository": repo_path,
                    "prompt": prompt,
                    "model": "claude-3.5-sonnet"
                }
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('agent_id')
                else:
                    logger.error(f"Failed to create agent: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Error creating Cursor agent: {e}")
            return None
    
    async def _check_cursor_agent(
        self,
        session: aiohttp.ClientSession,
        api_base: str,
        api_key: str,
        agent_id: str
    ) -> Dict:
        """Check status of a Cursor agent"""
        
        try:
            async with session.get(
                f"{api_base}/agents/{agent_id}",
                headers={"Authorization": f"Bearer {api_key}"}
            ) as response:
                if response.status == 200:
                    return await response.json()
                return {'status': 'unknown'}
        except Exception as e:
            logger.error(f"Error checking agent {agent_id}: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _parse_cursor_output(self, output: str) -> List[Finding]:
        """Parse Cursor agent output into findings"""
        import re
        
        findings = []
        try:
            json_match = re.search(r'\[.*\]', output, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(0))
                for item in data:
                    findings.append(Finding(
                        id=f"CURSOR-{len(findings)}",
                        severity=item.get('severity', 'MEDIUM'),
                        category=item.get('category', 'Unknown'),
                        cwe=item.get('cwe'),
                        owasp=item.get('owasp'),
                        file=item.get('file', ''),
                        line=item.get('line'),
                        code_snippet=item.get('code_snippet', ''),
                        description=item.get('description', ''),
                        impact=item.get('impact', ''),
                        remediation=item.get('remediation', ''),
                        references=item.get('references', []),
                        cvss_score=item.get('cvss_score'),
                        confidence=item.get('confidence', 'MEDIUM')
                    ))
        except Exception as e:
            logger.error(f"Error parsing Cursor output: {e}")
        
        return findings
    
    def _estimate_cost(self, results: List[BatchResult]) -> float:
        """Estimate API cost from results"""
        # Rough estimate based on typical token usage
        # ~1000 tokens per file, $0.15 per 1M input tokens
        total_files = sum(len(r.files) for r in results)
        estimated_tokens = total_files * 1000
        return (estimated_tokens / 1_000_000) * 0.15


# Convenience function
async def parallel_sast_scan(
    repo_path: str,
    max_workers: int = 8,
    batch_size: int = 5,
    strategy: str = "asyncio"
) -> tuple[List[Finding], ParallelStats]:
    """
    Run parallel SAST scan on a repository.
    
    Args:
        repo_path: Path to repository
        max_workers: Number of parallel workers
        batch_size: Files per batch
        strategy: asyncio, multiprocess, or cursor_agents
        
    Returns:
        Tuple of (findings, stats)
    """
    analyzer = ParallelSASTAnalyzer(
        max_workers=max_workers,
        batch_size=batch_size,
        strategy=strategy
    )
    
    return await analyzer.analyze_parallel(repo_path)

