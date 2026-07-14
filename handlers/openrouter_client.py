"""
OpenRouter Client for Multi-LLM Support

Provides unified access to multiple LLM providers through OpenRouter API.
Supports Claude, GPT-4, GPT-4o, Llama and other models.
"""

import os
import time
import requests
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json


@dataclass
class ModelConfig:
    """Configuration for a specific model"""
    id: str
    name: str
    provider: str
    input_cost: float  # Cost per 1M input tokens
    output_cost: float  # Cost per 1M output tokens
    context_length: int
    recommended_for: List[str] = field(default_factory=list)


class OpenRouterClient:
    """
    Unified client for accessing multiple LLMs through OpenRouter.
    
    Provides:
    - Multi-model support (Claude, GPT-4, GPT-4o, Llama)
    - Cost tracking per request
    - Automatic retry with exponential backoff
    - Request/response logging
    - Error handling
    
    Example:
        client = OpenRouterClient()
        response = client.chat_completion(
            messages=[{"role": "user", "content": "Hello"}],
            model="claude"
        )
    """
    
    BASE_URL = "https://openrouter.ai/api/v1"
    
    # Model mappings (alias -> full model ID)
    MODELS = {
        'claude': 'anthropic/claude-3.7-sonnet',  # Default to 3.7 Sonnet (best speed+accuracy)
        'claude-3.7-sonnet': 'anthropic/claude-3.7-sonnet',  # 100% accuracy, fastest
        'claude-3.5-sonnet': 'anthropic/claude-3.5-sonnet',
        'claude-3-sonnet': 'anthropic/claude-3-sonnet-20240229',
        'claude-opus-4.5': 'anthropic/claude-opus-4.5',  # Latest flagship
        'claude-sonnet-4.5': 'anthropic/claude-sonnet-4.5',
        'claude-opus-4': 'anthropic/claude-opus-4',
        'claude-sonnet-4': 'anthropic/claude-sonnet-4',
        'gpt-5.6-sol': 'openai/gpt-5.6-sol',  # OpenAI flagship (2026-07)
        'gpt4': 'openai/gpt-4-turbo',
        'gpt4o': 'openai/gpt-4o',
        'gpt4o-mini': 'openai/gpt-4o-mini',
        'llama': 'meta-llama/llama-3.1-70b-instruct',
        'llama-large': 'meta-llama/llama-3.1-405b-instruct',
    }
    
    # Cost per 1M tokens (input, output) - approximate pricing
    COSTS = {
        'anthropic/claude-3.7-sonnet': (3.00, 15.00),  # Default model
        'anthropic/claude-3.5-sonnet': (3.00, 15.00),
        'anthropic/claude-3-sonnet-20240229': (3.00, 15.00),
        'anthropic/claude-opus-4.5': (15.00, 75.00),
        'anthropic/claude-sonnet-4.5': (3.00, 15.00),
        'anthropic/claude-opus-4': (15.00, 75.00),
        'anthropic/claude-sonnet-4': (3.00, 15.00),
        'openai/gpt-5.6-sol': (5.00, 30.00),
        'openai/gpt-4-turbo': (10.00, 30.00),
        'openai/gpt-4o': (2.50, 10.00),
        'openai/gpt-4o-mini': (0.15, 0.60),
        'meta-llama/llama-3.1-70b-instruct': (0.88, 0.88),
        'meta-llama/llama-3.1-405b-instruct': (2.70, 2.70),
    }
    
    # Model configurations
    MODEL_CONFIGS = {
        'claude': ModelConfig(
            id='anthropic/claude-3.7-sonnet',
            name='Claude 3.7 Sonnet',
            provider='Anthropic',
            input_cost=3.00,
            output_cost=15.00,
            context_length=200000,
            recommended_for=['SAST', 'semantic_analysis', 'complex_reasoning', 'fastest']
        ),
        'claude-3.7-sonnet': ModelConfig(
            id='anthropic/claude-3.7-sonnet',
            name='Claude 3.7 Sonnet',
            provider='Anthropic',
            input_cost=3.00,
            output_cost=15.00,
            context_length=200000,
            recommended_for=['SAST', 'semantic_analysis', 'complex_reasoning', 'fastest']
        ),
        'gpt-5.6-sol': ModelConfig(
            id='openai/gpt-5.6-sol',
            name='GPT-5.6 Sol',
            provider='OpenAI',
            input_cost=5.00,
            output_cost=30.00,
            context_length=1050000,
            recommended_for=['SAST', 'semantic_analysis', 'complex_reasoning']
        ),
        'gpt4o': ModelConfig(
            id='openai/gpt-4o',
            name='GPT-4o',
            provider='OpenAI',
            input_cost=2.50,
            output_cost=10.00,
            context_length=128000,
            recommended_for=['fast_analysis', 'pattern_matching', 'balanced']
        ),
        'gpt4o-mini': ModelConfig(
            id='openai/gpt-4o-mini',
            name='GPT-4o Mini',
            provider='OpenAI',
            input_cost=0.15,
            output_cost=0.60,
            context_length=128000,
            recommended_for=['simple_scans', 'validation', 'cost_sensitive']
        ),
        'llama': ModelConfig(
            id='meta-llama/llama-3.1-70b-instruct',
            name='Llama 3.1 70B',
            provider='Meta',
            input_cost=0.88,
            output_cost=0.88,
            context_length=128000,
            recommended_for=['cost_effective', 'batch_processing']
        ),
    }
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        site_url: str = "https://github.com/iankar8/ai-pen-test",
        site_name: str = "ai-pen-test"
    ):
        """
        Initialize OpenRouter client.
        
        Args:
            api_key: OpenRouter API key (defaults to OPENROUTER_API_KEY env var)
            site_url: Your site URL for OpenRouter tracking
            site_name: Your site name for OpenRouter tracking
        """
        self.api_key = api_key or os.getenv('OPENROUTER_API_KEY')
        if not self.api_key:
            raise ValueError(
                "OpenRouter API key required. Set OPENROUTER_API_KEY environment "
                "variable or pass api_key parameter."
            )
        
        self.site_url = site_url
        self.site_name = site_name
        
        # Usage tracking
        self.total_cost = 0.0
        self.request_count = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.requests_history: List[Dict] = []
        
    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: str = 'claude',
        temperature: float = 0.0,
        max_tokens: int = 4096,
        top_p: float = 1.0,
        stream: bool = False,
        retry_count: int = 3
    ) -> Dict[str, Any]:
        """
        Send chat completion request to OpenRouter.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model alias (claude, gpt4, gpt4o, llama) or full model ID
            temperature: Sampling temperature (0.0 - 2.0)
            max_tokens: Maximum tokens to generate
            top_p: Nucleus sampling threshold
            stream: Whether to stream the response
            retry_count: Number of retries on failure
            
        Returns:
            Response dict with 'choices', 'usage', 'model', etc.
            
        Raises:
            ValueError: If model is invalid
            RuntimeError: If request fails after retries
        """
        # Resolve model alias to full ID
        model_id = self.MODELS.get(model, model)
        
        # Build request payload
        payload = {
            'model': model_id,
            'messages': messages,
            'temperature': temperature,
            'max_tokens': max_tokens,
            'top_p': top_p,
            'stream': stream
        }
        
        # Make request with retries
        response = self._make_request(
            endpoint='/chat/completions',
            payload=payload,
            retry_count=retry_count
        )
        
        # Track usage
        self._track_usage(response, model_id)
        
        return response
    
    def _make_request(
        self,
        endpoint: str,
        payload: Dict,
        retry_count: int = 3
    ) -> Dict[str, Any]:
        """
        Make HTTP request with retry logic.
        
        Args:
            endpoint: API endpoint (e.g., '/chat/completions')
            payload: Request payload
            retry_count: Number of retries
            
        Returns:
            Response JSON
            
        Raises:
            RuntimeError: If all retries fail
        """
        url = f"{self.BASE_URL}{endpoint}"
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'HTTP-Referer': self.site_url,
            'X-Title': self.site_name
        }
        
        last_error = None
        
        for attempt in range(retry_count):
            try:
                response = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=120
                )
                
                # Check for HTTP errors
                response.raise_for_status()
                
                return response.json()
                
            except requests.exceptions.HTTPError as e:
                last_error = e
                
                # Don't retry on 4xx errors (client errors)
                if 400 <= response.status_code < 500:
                    raise RuntimeError(
                        f"OpenRouter API error: {response.status_code} - {response.text}"
                    ) from e
                
                # Retry on 5xx errors (server errors)
                if attempt < retry_count - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    time.sleep(wait_time)
                    continue
                    
            except requests.exceptions.RequestException as e:
                last_error = e
                
                # Retry on network errors
                if attempt < retry_count - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                    continue
        
        # All retries failed
        raise RuntimeError(
            f"OpenRouter request failed after {retry_count} attempts: {last_error}"
        ) from last_error
    
    def _track_usage(self, response: Dict, model_id: str) -> None:
        """
        Track token usage and costs.
        
        Args:
            response: API response
            model_id: Full model ID
        """
        usage = response.get('usage', {})
        prompt_tokens = usage.get('prompt_tokens', 0)
        completion_tokens = usage.get('completion_tokens', 0)
        
        # Update token counts
        self.total_input_tokens += prompt_tokens
        self.total_output_tokens += completion_tokens
        self.request_count += 1
        
        # Calculate cost
        cost = 0.0
        if model_id in self.COSTS:
            input_cost, output_cost = self.COSTS[model_id]
            cost = (
                (prompt_tokens / 1_000_000) * input_cost +
                (completion_tokens / 1_000_000) * output_cost
            )
            self.total_cost += cost
        
        # Record request history
        self.requests_history.append({
            'timestamp': datetime.now().isoformat(),
            'model': model_id,
            'input_tokens': prompt_tokens,
            'output_tokens': completion_tokens,
            'cost': round(cost, 6)
        })
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get usage statistics.
        
        Returns:
            Dict with requests, tokens, costs, etc.
        """
        return {
            'requests': self.request_count,
            'total_cost': round(self.total_cost, 4),
            'total_input_tokens': self.total_input_tokens,
            'total_output_tokens': self.total_output_tokens,
            'total_tokens': self.total_input_tokens + self.total_output_tokens,
            'average_cost_per_request': (
                round(self.total_cost / self.request_count, 4)
                if self.request_count > 0 else 0.0
            ),
            'history': self.requests_history[-10:]  # Last 10 requests
        }
    
    def get_available_models(self) -> List[Dict[str, Any]]:
        """
        Get list of available models from OpenRouter.
        
        Returns:
            List of model dicts with id, name, pricing, etc.
        """
        try:
            response = requests.get(
                f"{self.BASE_URL}/models",
                headers={'Authorization': f'Bearer {self.api_key}'},
                timeout=30
            )
            response.raise_for_status()
            return response.json().get('data', [])
        except Exception as e:
            print(f"Error fetching models: {e}")
            return []
    
    def get_model_config(self, model: str) -> Optional[ModelConfig]:
        """
        Get configuration for a specific model.
        
        Args:
            model: Model alias or ID
            
        Returns:
            ModelConfig if found, None otherwise
        """
        return self.MODEL_CONFIGS.get(model)
    
    def reset_stats(self) -> None:
        """Reset usage statistics."""
        self.total_cost = 0.0
        self.request_count = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.requests_history = []
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"OpenRouterClient(requests={self.request_count}, "
            f"cost=${self.total_cost:.4f})"
        )
