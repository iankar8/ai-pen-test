"""
Unit tests for LLM Provider abstraction
"""

import unittest
import sys
from unittest.mock import patch, Mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from handlers.llm_provider import LLMProvider, TaskType, AnalysisResult


class TestLLMProvider(unittest.TestCase):
    """Test cases for LLM provider"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_api_key = "test-api-key"
    
    @patch('handlers.llm_provider.OpenRouterClient')
    def test_init(self, mock_client_class):
        """Test provider initialization"""
        provider = LLMProvider(api_key=self.test_api_key)
        mock_client_class.assert_called_once_with(api_key=self.test_api_key)
        self.assertEqual(provider.fallback_model, 'gpt4o')
    
    def test_model_selection_sast(self):
        """Test that SAST tasks use Claude"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(api_key=self.test_api_key)
            model = provider._select_model('sast')
            self.assertEqual(model, 'claude-3.7-sonnet')
    
    def test_model_selection_validation(self):
        """Test that validation tasks use GPT-4o mini"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(api_key=self.test_api_key)
            model = provider._select_model('validation')
            self.assertEqual(model, 'gpt4o-mini')
    
    def test_model_selection_pattern_matching(self):
        """Test that pattern matching uses GPT-4o"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(api_key=self.test_api_key)
            model = provider._select_model('pattern_matching')
            self.assertEqual(model, 'gpt4o')
    
    def test_model_selection_unknown_task(self):
        """Test that unknown tasks default to Claude"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(api_key=self.test_api_key)
            model = provider._select_model('unknown_task')
            self.assertEqual(model, 'claude')
    
    def test_primary_model_override(self):
        """Test that primary model overrides task-based selection"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(
                primary_model='gpt4',
                api_key=self.test_api_key
            )
            # Should always use gpt4, regardless of task
            self.assertEqual(provider._select_model('sast'), 'gpt4')
            self.assertEqual(provider._select_model('validation'), 'gpt4')
    
    @patch('handlers.llm_provider.OpenRouterClient')
    def test_analyze_code_success(self, mock_client_class):
        """Test successful code analysis"""
        # Mock successful response
        mock_client = Mock()
        mock_client.chat_completion.return_value = {
            'choices': [{
                'message': {
                    'content': '''```json
{
  "findings": [
    {
      "category": "SQL Injection",
      "severity": "CRITICAL",
      "description": "SQL injection vulnerability",
      "line": 10,
      "code_snippet": "SELECT * FROM users",
      "remediation": "Use parameterized queries",
      "cwe": "CWE-89",
      "confidence": "HIGH"
    }
  ]
}
```'''
                }
            }],
            'usage': {
                'total_tokens': 150
            }
        }
        mock_client_class.return_value = mock_client
        
        provider = LLMProvider(api_key=self.test_api_key)
        result = provider.analyze_code(
            code='SELECT * FROM users',
            context={'language': 'python'},
            task='sast'
        )
        
        # Verify result
        self.assertIsInstance(result, AnalysisResult)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0]['category'], 'SQL Injection')
        self.assertEqual(result.findings[0]['severity'], 'CRITICAL')
        self.assertEqual(result.model_used, 'claude-3.7-sonnet')
        self.assertEqual(result.tokens_used, 150)
        self.assertIsNone(result.error)
    
    @patch('handlers.llm_provider.OpenRouterClient')
    def test_analyze_code_with_fallback(self, mock_client_class):
        """Test fallback to secondary model on primary failure"""
        # Mock client where first call fails, second succeeds
        mock_client = Mock()
        mock_client.chat_completion.side_effect = [
            Exception("Primary model failed"),
            {
                'choices': [{
                    'message': {
                        'content': '{"findings": []}'
                    }
                }],
                'usage': {'total_tokens': 50}
            }
        ]
        mock_client_class.return_value = mock_client
        
        provider = LLMProvider(api_key=self.test_api_key)
        result = provider.analyze_code(
            code='safe code',
            context={'language': 'python'},
            task='sast'
        )
        
        # Should have fallen back to gpt4o
        self.assertEqual(result.model_used, 'gpt4o')
        self.assertEqual(mock_client.chat_completion.call_count, 2)
    
    @patch('handlers.llm_provider.OpenRouterClient')
    def test_analyze_code_both_models_fail(self, mock_client_class):
        """Test when both primary and fallback models fail"""
        # Mock both calls failing
        mock_client = Mock()
        mock_client.chat_completion.side_effect = Exception("All models failed")
        mock_client_class.return_value = mock_client
        
        provider = LLMProvider(api_key=self.test_api_key)
        result = provider.analyze_code(
            code='test',
            context={'language': 'python'},
            task='sast'
        )
        
        # Should return error result
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.model_used, 'none')
        self.assertIsNotNone(result.error)
    
    def test_extract_findings_pure_json(self):
        """Test extracting findings from pure JSON"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(api_key=self.test_api_key)
            content = '{"findings": [{"category": "XSS", "severity": "HIGH"}]}'
            findings = provider._extract_findings(content)
            
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]['category'], 'XSS')
    
    def test_extract_findings_from_markdown(self):
        """Test extracting findings from markdown code block"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(api_key=self.test_api_key)
            content = '''Here are the findings:

```json
{
  "findings": [
    {"category": "SQLi", "severity": "CRITICAL"}
  ]
}
```

Let me know if you need more details.'''
            
            findings = provider._extract_findings(content)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]['category'], 'SQLi')
    
    def test_extract_findings_no_json(self):
        """Test handling of response with no JSON"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(api_key=self.test_api_key)
            content = 'No vulnerabilities found in this code.'
            findings = provider._extract_findings(content)
            
            # Should return empty list
            self.assertEqual(len(findings), 0)
    
    def test_build_messages_sast(self):
        """Test message building for SAST task"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(api_key=self.test_api_key)
            messages = provider._build_messages(
                code='test code',
                context={'language': 'python', 'file_path': 'test.py'},
                task='sast',
                custom_prompt=None
            )
            
            # Should have system and user messages
            self.assertEqual(len(messages), 2)
            self.assertEqual(messages[0]['role'], 'system')
            self.assertEqual(messages[1]['role'], 'user')
            
            # System message should mention vulnerability categories
            self.assertIn('SQL', messages[0]['content'])
            self.assertIn('XSS', messages[0]['content'])
            
            # User message should contain code
            self.assertIn('test code', messages[1]['content'])
            self.assertIn('test.py', messages[1]['content'])
    
    def test_build_messages_custom_prompt(self):
        """Test message building with custom prompt"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(api_key=self.test_api_key)
            custom = "Custom security analysis prompt"
            messages = provider._build_messages(
                code='code',
                context={'language': 'js'},
                task='sast',
                custom_prompt=custom
            )
            
            # Should use custom prompt
            self.assertEqual(messages[0]['content'], custom)
    
    @patch('handlers.llm_provider.OpenRouterClient')
    def test_get_stats(self, mock_client_class):
        """Test getting usage statistics"""
        mock_client = Mock()
        mock_client.get_stats.return_value = {
            'requests': 5,
            'total_cost': 1.23,
            'total_tokens': 1000
        }
        mock_client_class.return_value = mock_client
        
        provider = LLMProvider(api_key=self.test_api_key)
        stats = provider.get_stats()
        
        self.assertEqual(stats['requests'], 5)
        self.assertEqual(stats['total_cost'], 1.23)
    
    def test_get_model_for_task(self):
        """Test getting recommended model for task"""
        with patch('handlers.llm_provider.OpenRouterClient'):
            provider = LLMProvider(api_key=self.test_api_key)
            
            # SAST should recommend Claude
            self.assertEqual(provider.get_model_for_task('sast'), 'claude-3.7-sonnet')
            
            # Validation should recommend gpt4o-mini
            self.assertEqual(provider.get_model_for_task('validation'), 'gpt4o-mini')


if __name__ == '__main__':
    unittest.main()
