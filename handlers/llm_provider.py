"""
LLM Provider Abstraction Layer

High-level interface for LLM operations with automatic model selection,
fallback handling, and response formatting.
"""

import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from handlers.openrouter_client import OpenRouterClient


class TaskType(Enum):
    """Types of security analysis tasks"""
    SAST = "sast"  # Static Application Security Testing
    SEMANTIC_ANALYSIS = "semantic_analysis"  # Deep code understanding
    PATTERN_MATCHING = "pattern_matching"  # Simple pattern detection
    VALIDATION = "validation"  # Vulnerability validation
    POC_GENERATION = "poc_generation"  # Proof-of-concept generation
    SIMPLE_SCAN = "simple_scan"  # Quick scan
    BUSINESS_LOGIC = "business_logic"  # Business logic flaws
    ARCHITECTURE = "architecture"  # Architecture review


@dataclass
class AnalysisResult:
    """Result from LLM analysis"""
    findings: List[Dict[str, Any]]
    model_used: str
    tokens_used: int
    cost: float
    raw_response: Optional[str] = None
    error: Optional[str] = None


class LLMProvider:
    """
    High-level abstraction for LLM operations.
    
    Handles:
    - Automatic model selection based on task type
    - Fallback to secondary model on failure
    - Response parsing and formatting
    - Cost optimization
    - Error handling
    
    Example:
        provider = LLMProvider()
        result = provider.analyze_code(
            code='SELECT * FROM users WHERE id = ' + user_id,
            context={'language': 'python'},
            task='sast'
        )
    """
    
    # Task-specific model selection strategies
    MODEL_SELECTION = {
        TaskType.SAST: 'claude-3.7-sonnet',  # Best for deep semantic analysis + fastest
        TaskType.SEMANTIC_ANALYSIS: 'claude-3.7-sonnet',  # Complex reasoning
        TaskType.PATTERN_MATCHING: 'gpt4o',  # Fast pattern detection
        TaskType.VALIDATION: 'gpt4o-mini',  # Cost-effective validation
        TaskType.POC_GENERATION: 'claude-3.7-sonnet',  # Good balance
        TaskType.SIMPLE_SCAN: 'gpt4o-mini',  # Fast and cheap
        TaskType.BUSINESS_LOGIC: 'claude-3.7-sonnet',  # Requires deep understanding
        TaskType.ARCHITECTURE: 'claude-3.7-sonnet',  # Complex analysis
    }
    
    def __init__(
        self,
        primary_model: Optional[str] = None,
        fallback_model: str = 'gpt4o',
        api_key: Optional[str] = None
    ):
        """
        Initialize LLM provider.
        
        Args:
            primary_model: Primary model to use (None = auto-select by task)
            fallback_model: Fallback model if primary fails
            api_key: OpenRouter API key
        """
        self.client = OpenRouterClient(api_key=api_key)
        self.primary_model = primary_model
        self.fallback_model = fallback_model
        
    def analyze_code(
        self,
        code: str,
        context: Dict[str, Any],
        task: str = 'sast',
        custom_prompt: Optional[str] = None
    ) -> AnalysisResult:
        """
        Analyze code for security issues.
        
        Args:
            code: Source code to analyze
            context: Context dict with language, file_path, etc.
            task: Task type (sast, validation, etc.)
            custom_prompt: Optional custom prompt override
            
        Returns:
            AnalysisResult with findings and metadata
        """
        # Select model based on task
        model = self._select_model(task)
        
        # Build messages
        messages = self._build_messages(code, context, task, custom_prompt)
        
        # Try primary model
        try:
            response = self.client.chat_completion(
                messages=messages,
                model=model,
                temperature=0.0,
                max_tokens=4096
            )
            return self._parse_response(response, model)
            
        except Exception as primary_error:
            # Try fallback model
            print(f"[LLM] Primary model {model} failed: {primary_error}")
            print(f"[LLM] Falling back to {self.fallback_model}")
            
            try:
                response = self.client.chat_completion(
                    messages=messages,
                    model=self.fallback_model,
                    temperature=0.0,
                    max_tokens=4096
                )
                return self._parse_response(response, self.fallback_model)
                
            except Exception as fallback_error:
                # Both failed
                return AnalysisResult(
                    findings=[],
                    model_used='none',
                    tokens_used=0,
                    cost=0.0,
                    error=f"Primary: {primary_error}, Fallback: {fallback_error}"
                )
    
    def _select_model(self, task: str) -> str:
        """
        Select optimal model for task.
        
        Args:
            task: Task type string
            
        Returns:
            Model alias
        """
        # If primary model is set, always use it
        if self.primary_model:
            return self.primary_model
        
        # Convert task string to enum
        try:
            task_enum = TaskType(task.lower())
            return self.MODEL_SELECTION.get(task_enum, 'claude')
        except (ValueError, AttributeError):
            # Unknown task, use Claude as default
            return 'claude'
    
    def _build_messages(
        self,
        code: str,
        context: Dict[str, Any],
        task: str,
        custom_prompt: Optional[str]
    ) -> List[Dict[str, str]]:
        """
        Build chat messages for LLM.
        
        Args:
            code: Source code
            context: Analysis context
            task: Task type
            custom_prompt: Optional custom prompt
            
        Returns:
            List of message dicts
        """
        if custom_prompt:
            # Use custom prompt if provided
            system_prompt = custom_prompt
        else:
            # Build default prompt based on task
            system_prompt = self._build_default_prompt(task, context)
        
        # Build user message with code
        language = context.get('language', 'unknown')
        file_path = context.get('file_path', 'unknown')
        
        user_message = f"""Analyze this {language} code for security vulnerabilities:

File: {file_path}

```{language}
{code}
```

Provide findings in JSON format:
{{
  "findings": [
    {{
      "category": "vulnerability category",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "detailed description",
      "line": line_number,
      "code_snippet": "vulnerable code",
      "remediation": "how to fix",
      "cwe": "CWE-XX",
      "confidence": "HIGH|MEDIUM|LOW"
    }}
  ]
}}
"""
        
        return [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_message}
        ]
    
    def _build_default_prompt(self, task: str, context: Dict) -> str:
        """
        Build default system prompt for task.
        
        Args:
            task: Task type
            context: Analysis context
            
        Returns:
            System prompt string
        """
        base_prompt = """You are an expert security engineer performing code security analysis.
Focus on finding real vulnerabilities, not theoretical issues.
Be precise and provide actionable remediation guidance."""
        
        task_lower = task.lower()
        
        if task_lower == 'sast':
            return base_prompt + """

Focus on these vulnerability categories:
- SQL/NoSQL Injection
- Cross-Site Scripting (XSS)
- Authentication/Authorization flaws
- Sensitive data exposure
- Cryptographic weaknesses
- Command injection
- Path traversal
- Insecure deserialization

For each finding, provide:
1. Precise vulnerability description
2. Affected code location
3. Security impact
4. Concrete remediation steps
5. CWE classification"""
        
        elif task_lower == 'validation':
            return base_prompt + """

Validate if the reported vulnerability is real and exploitable.
Consider false positive indicators:
- Proper input validation
- Use of safe APIs
- Correct security controls"""
        
        elif task_lower == 'poc_generation':
            return base_prompt + """

Generate a proof-of-concept exploit that demonstrates the vulnerability.
Include:
- Step-by-step reproduction
- Payload/exploit code
- Expected vs actual behavior
- Impact demonstration"""
        
        else:
            return base_prompt
    
    def _parse_response(
        self,
        response: Dict[str, Any],
        model: str
    ) -> AnalysisResult:
        """
        Parse LLM response into structured result.
        
        Args:
            response: Raw API response
            model: Model used
            
        Returns:
            AnalysisResult
        """
        # Extract content
        try:
            content = response['choices'][0]['message']['content']
        except (KeyError, IndexError):
            return AnalysisResult(
                findings=[],
                model_used=model,
                tokens_used=0,
                cost=0.0,
                error="Invalid response structure"
            )
        
        # Parse JSON from content
        findings = self._extract_findings(content)
        
        # Get usage stats
        usage = response.get('usage', {})
        tokens_used = usage.get('total_tokens', 0)
        
        # Calculate approximate cost (will be tracked by client)
        cost = 0.0  # Actual cost tracked by OpenRouterClient
        
        return AnalysisResult(
            findings=findings,
            model_used=model,
            tokens_used=tokens_used,
            cost=cost,
            raw_response=content
        )
    
    def _extract_findings(self, content: str) -> List[Dict[str, Any]]:
        """
        Extract findings from LLM response content.
        
        Args:
            content: Response content (may contain JSON)
            
        Returns:
            List of finding dicts
        """
        try:
            # Try to parse as pure JSON
            data = json.loads(content)
            return data.get('findings', [])
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON from markdown code blocks
        import re
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                return data.get('findings', [])
            except json.JSONDecodeError:
                pass
        
        # If no JSON found, return empty findings
        # In production, might want to log this for debugging
        return []
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get usage statistics from underlying client.
        
        Returns:
            Stats dict with requests, costs, tokens, etc.
        """
        return self.client.get_stats()
    
    def get_model_for_task(self, task: str) -> str:
        """
        Get recommended model for a task type.
        
        Args:
            task: Task type string
            
        Returns:
            Recommended model alias
        """
        return self._select_model(task)
    
    def reset_stats(self) -> None:
        """Reset usage statistics."""
        self.client.reset_stats()
