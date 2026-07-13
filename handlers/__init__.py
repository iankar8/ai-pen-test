"""
ai-pen-test - Handler Modules

LLM-backed semantic SAST engine. Exports the analysis, provider, aggregation,
and reporting handlers.
"""

from .sast_analyzer import (
    SASTAnalyzer,
    Finding,
    Severity,
    VulnerabilityCategory,
)
from .llm_provider import LLMProvider, TaskType, AnalysisResult
from .openrouter_client import OpenRouterClient, ModelConfig
from .finding_aggregator import FindingAggregator, AttackChain
from .report_generator import ReportGenerator
from .parallel_sast import ParallelSASTAnalyzer, BatchResult, ParallelStats
from .codebase_detector import (
    CodebaseDetector,
    CodebaseContext,
    CodebaseType,
    Framework,
    FileContext,
)
from .crypto_analyzer import CryptoAnalyzer, CryptoSmell
from .xpath_analyzer import XPathAnalyzer, XPathVulnerability

__all__ = [
    'SASTAnalyzer',
    'Finding',
    'Severity',
    'VulnerabilityCategory',
    'LLMProvider',
    'TaskType',
    'AnalysisResult',
    'OpenRouterClient',
    'ModelConfig',
    'FindingAggregator',
    'AttackChain',
    'ReportGenerator',
    'ParallelSASTAnalyzer',
    'BatchResult',
    'ParallelStats',
    'CodebaseDetector',
    'CodebaseContext',
    'CodebaseType',
    'Framework',
    'FileContext',
    'CryptoAnalyzer',
    'CryptoSmell',
    'XPathAnalyzer',
    'XPathVulnerability',
]

__version__ = '0.1.0'
