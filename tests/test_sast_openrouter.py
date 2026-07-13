"""
Unit tests for SAST analyzer with OpenRouter integration
"""

import unittest
import sys
from unittest.mock import patch, Mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from handlers.sast_analyzer import SASTAnalyzer
from handlers.llm_provider import AnalysisResult


class TestSASTAnalyzerOpenRouter(unittest.TestCase):
    """Test cases for SAST analyzer with OpenRouter"""
    
    @patch('handlers.llm_provider.OpenRouterClient')
    def test_init_with_openrouter(self, mock_client_class):
        """Test analyzer initialization with OpenRouter"""
        analyzer = SASTAnalyzer(
            model='claude',
            api_key='test-key',
            use_openrouter=True
        )
        
        # Should use LLM provider
        self.assertIsNotNone(analyzer.llm)
        self.assertIsNone(analyzer.client)
        self.assertTrue(analyzer.use_openrouter)
    
    def test_init_without_openrouter(self):
        """Test analyzer initialization without OpenRouter (legacy)"""
        analyzer = SASTAnalyzer(
            model='claude-opus-4-1-20250805',
            api_key='test-key',
            use_openrouter=False
        )
        
        # Should use legacy Anthropic client
        self.assertIsNone(analyzer.llm)
        self.assertIsNotNone(analyzer.client)
        self.assertFalse(analyzer.use_openrouter)
    
    @patch('handlers.llm_provider.OpenRouterClient')
    def test_get_llm_stats_with_openrouter(self, mock_client_class):
        """Test getting LLM stats when using OpenRouter"""
        # Mock the LLM provider's get_stats
        mock_llm = Mock()
        mock_llm.get_stats.return_value = {
            'requests': 5,
            'total_cost': 1.23,
            'total_tokens': 1000
        }
        
        analyzer = SASTAnalyzer(api_key='test-key', use_openrouter=True)
        analyzer.llm = mock_llm
        
        stats = analyzer.get_llm_stats()
        
        self.assertIsNotNone(stats)
        self.assertEqual(stats['requests'], 5)
        self.assertEqual(stats['total_cost'], 1.23)
    
    def test_get_llm_stats_without_openrouter(self):
        """Test getting LLM stats when using legacy client"""
        analyzer = SASTAnalyzer(api_key='test-key', use_openrouter=False)
        
        stats = analyzer.get_llm_stats()
        
        # Should return None for legacy client
        self.assertIsNone(stats)
    
    @patch('handlers.llm_provider.OpenRouterClient')
    def test_call_claude_analysis_with_openrouter(self, mock_client_class):
        """Test analysis using OpenRouter"""
        # Mock LLM response
        mock_result = AnalysisResult(
            findings=[
                {
                    'category': 'SQL Injection',
                    'severity': 'CRITICAL',
                    'line': 10,
                    'code_snippet': 'SELECT * FROM users',
                    'description': 'SQL injection vulnerability',
                    'remediation': 'Use parameterized queries',
                    'cwe': 'CWE-89',
                    'confidence': 'HIGH'
                }
            ],
            model_used='claude',
            tokens_used=150,
            cost=0.01,
            raw_response='[{"category": "SQL Injection", "severity": "CRITICAL"}]'
        )
        
        mock_llm = Mock()
        mock_llm.analyze_code.return_value = mock_result
        
        analyzer = SASTAnalyzer(api_key='test-key', use_openrouter=True)
        analyzer.llm = mock_llm
        
        # Call the analysis method
        response = analyzer._call_claude_analysis(
            prompt='Test prompt',
            code_content='test code'
        )
        
        # Verify it used the LLM provider
        mock_llm.analyze_code.assert_called_once()
        self.assertEqual(response, mock_result.raw_response)
    
    @patch('handlers.llm_provider.OpenRouterClient')
    def test_call_claude_analysis_error_handling(self, mock_client_class):
        """Test error handling in OpenRouter analysis"""
        # Mock LLM error response
        mock_result = AnalysisResult(
            findings=[],
            model_used='none',
            tokens_used=0,
            cost=0.0,
            error='API call failed'
        )
        
        mock_llm = Mock()
        mock_llm.analyze_code.return_value = mock_result
        
        analyzer = SASTAnalyzer(api_key='test-key', use_openrouter=True)
        analyzer.llm = mock_llm
        
        # Should raise RuntimeError on error
        with self.assertRaises(RuntimeError) as context:
            analyzer._call_claude_analysis(
                prompt='Test prompt',
                code_content='test code'
            )
        
        self.assertIn('LLM analysis failed', str(context.exception))
    
    @patch('handlers.llm_provider.OpenRouterClient')
    def test_model_selection(self, mock_client_class):
        """Test that different models can be selected"""
        # Test with different models
        for model in ['claude', 'gpt4o', 'gpt4o-mini']:
            analyzer = SASTAnalyzer(
                model=model,
                api_key='test-key',
                use_openrouter=True
            )
            self.assertEqual(analyzer.model, model)
            self.assertIsNotNone(analyzer.llm)


if __name__ == '__main__':
    unittest.main()
