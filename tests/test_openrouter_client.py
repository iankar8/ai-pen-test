"""
Unit tests for OpenRouter client
"""

import unittest
import os
import sys
from unittest.mock import patch, Mock, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from handlers.openrouter_client import OpenRouterClient, ModelConfig


class TestOpenRouterClient(unittest.TestCase):
    """Test cases for OpenRouter client"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock API key for testing
        self.test_api_key = "test-api-key-12345"
        
    def test_init_with_api_key(self):
        """Test client initialization with API key"""
        client = OpenRouterClient(api_key=self.test_api_key)
        self.assertEqual(client.api_key, self.test_api_key)
        self.assertEqual(client.request_count, 0)
        self.assertEqual(client.total_cost, 0.0)
    
    def test_init_from_env_var(self):
        """Test client initialization from environment variable"""
        with patch.dict(os.environ, {'OPENROUTER_API_KEY': self.test_api_key}):
            client = OpenRouterClient()
            self.assertEqual(client.api_key, self.test_api_key)
    
    def test_init_without_api_key_raises_error(self):
        """Test that missing API key raises ValueError"""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError) as context:
                OpenRouterClient()
            self.assertIn("API key required", str(context.exception))
    
    def test_model_alias_resolution(self):
        """Test that model aliases resolve to full IDs"""
        client = OpenRouterClient(api_key=self.test_api_key)
        
        # Test known aliases
        self.assertEqual(
            client.MODELS['claude'],
            'anthropic/claude-3.7-sonnet'
        )
        self.assertEqual(
            client.MODELS['gpt4o'],
            'openai/gpt-4o'
        )
        self.assertEqual(
            client.MODELS['llama'],
            'meta-llama/llama-3.1-70b-instruct'
        )
    
    @patch('handlers.openrouter_client.requests.post')
    def test_chat_completion_success(self, mock_post):
        """Test successful chat completion"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [
                {
                    'message': {
                        'role': 'assistant',
                        'content': 'Test response'
                    }
                }
            ],
            'usage': {
                'prompt_tokens': 10,
                'completion_tokens': 5,
                'total_tokens': 15
            },
            'model': 'anthropic/claude-3.5-sonnet'
        }
        mock_post.return_value = mock_response
        
        client = OpenRouterClient(api_key=self.test_api_key)
        response = client.chat_completion(
            messages=[{'role': 'user', 'content': 'Hello'}],
            model='claude'
        )
        
        # Verify response
        self.assertIn('choices', response)
        self.assertEqual(response['choices'][0]['message']['content'], 'Test response')
        
        # Verify request was made
        mock_post.assert_called_once()
        
        # Verify tracking
        self.assertEqual(client.request_count, 1)
        self.assertEqual(client.total_input_tokens, 10)
        self.assertEqual(client.total_output_tokens, 5)
        self.assertGreater(client.total_cost, 0)
    
    @patch('handlers.openrouter_client.requests.post')
    def test_cost_tracking(self, mock_post):
        """Test that costs are tracked correctly"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{'message': {'content': 'Test'}}],
            'usage': {
                'prompt_tokens': 1000,
                'completion_tokens': 500,
                'total_tokens': 1500
            }
        }
        mock_post.return_value = mock_response
        
        client = OpenRouterClient(api_key=self.test_api_key)
        
        # Make request with Claude (3.00 input, 15.00 output per 1M tokens)
        client.chat_completion(
            messages=[{'role': 'user', 'content': 'Test'}],
            model='claude'
        )
        
        # Expected cost: (1000/1M * 3.00) + (500/1M * 15.00)
        # = 0.003 + 0.0075 = 0.0105
        expected_cost = 0.0105
        self.assertAlmostEqual(client.total_cost, expected_cost, places=4)
    
    @patch('handlers.openrouter_client.requests.post')
    @patch('handlers.openrouter_client.time.sleep')
    def test_retry_on_network_error(self, mock_sleep, mock_post):
        """Test that client retries on network errors"""
        # First two attempts fail, third succeeds
        mock_post.side_effect = [
            requests.exceptions.ConnectionError("Network error"),
            requests.exceptions.Timeout("Timeout"),
            Mock(
                status_code=200,
                json=lambda: {
                    'choices': [{'message': {'content': 'Success'}}],
                    'usage': {'prompt_tokens': 5, 'completion_tokens': 3}
                }
            )
        ]
        
        client = OpenRouterClient(api_key=self.test_api_key)
        response = client.chat_completion(
            messages=[{'role': 'user', 'content': 'Test'}]
        )
        
        # Should have retried twice
        self.assertEqual(mock_post.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)
        
        # Should succeed on third attempt
        self.assertIn('choices', response)
    
    @patch('handlers.openrouter_client.requests.post')
    def test_retry_fails_after_max_attempts(self, mock_post):
        """Test that client fails after max retries"""
        # All attempts fail
        mock_post.side_effect = requests.exceptions.ConnectionError("Network error")
        
        client = OpenRouterClient(api_key=self.test_api_key)
        
        with self.assertRaises(RuntimeError) as context:
            client.chat_completion(
                messages=[{'role': 'user', 'content': 'Test'}],
                retry_count=3
            )
        
        self.assertIn("failed after 3 attempts", str(context.exception))
    
    @patch('handlers.openrouter_client.requests.post')
    def test_http_4xx_error_no_retry(self, mock_post):
        """Test that 4xx errors don't trigger retries"""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Bad request"
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError()
        mock_post.return_value = mock_response
        
        client = OpenRouterClient(api_key=self.test_api_key)
        
        with self.assertRaises(RuntimeError) as context:
            client.chat_completion(
                messages=[{'role': 'user', 'content': 'Test'}]
            )
        
        # Should only try once (no retries on 4xx)
        self.assertEqual(mock_post.call_count, 1)
        self.assertIn("400", str(context.exception))
    
    def test_get_stats(self):
        """Test getting usage statistics"""
        client = OpenRouterClient(api_key=self.test_api_key)
        
        # Initially empty
        stats = client.get_stats()
        self.assertEqual(stats['requests'], 0)
        self.assertEqual(stats['total_cost'], 0.0)
        self.assertEqual(stats['total_tokens'], 0)
    
    def test_reset_stats(self):
        """Test resetting statistics"""
        client = OpenRouterClient(api_key=self.test_api_key)
        
        # Manually set some stats
        client.request_count = 10
        client.total_cost = 5.0
        client.total_input_tokens = 1000
        client.total_output_tokens = 500
        
        # Reset
        client.reset_stats()
        
        # Verify reset
        self.assertEqual(client.request_count, 0)
        self.assertEqual(client.total_cost, 0.0)
        self.assertEqual(client.total_input_tokens, 0)
        self.assertEqual(client.total_output_tokens, 0)
    
    def test_get_model_config(self):
        """Test getting model configuration"""
        client = OpenRouterClient(api_key=self.test_api_key)
        
        # Get Claude config
        config = client.get_model_config('claude')
        self.assertIsInstance(config, ModelConfig)
        self.assertEqual(config.name, 'Claude 3.7 Sonnet')
        self.assertIn('SAST', config.recommended_for)
        
        # Non-existent model
        config = client.get_model_config('nonexistent')
        self.assertIsNone(config)
    
    @patch('handlers.openrouter_client.requests.post')
    def test_different_models(self, mock_post):
        """Test using different model aliases"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{'message': {'content': 'Test'}}],
            'usage': {'prompt_tokens': 5, 'completion_tokens': 3}
        }
        mock_post.return_value = mock_response
        
        client = OpenRouterClient(api_key=self.test_api_key)
        
        # Test different models
        for model in ['claude', 'gpt4o', 'llama']:
            response = client.chat_completion(
                messages=[{'role': 'user', 'content': 'Test'}],
                model=model
            )
            self.assertIn('choices', response)
        
        # Should have made 3 requests
        self.assertEqual(client.request_count, 3)
    
    def test_repr(self):
        """Test string representation"""
        client = OpenRouterClient(api_key=self.test_api_key)
        client.request_count = 5
        client.total_cost = 1.2345
        
        repr_str = repr(client)
        self.assertIn('5', repr_str)
        self.assertIn('1.2345', repr_str)


# Import requests for mocking
import requests


if __name__ == '__main__':
    unittest.main()
