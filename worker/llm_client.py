import requests
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class OllamaClient:
    """
    A client for interacting with the Ollama LLM service.
    """
    def __init__(self, model: str, api_url: str = "http://127.0.0.1:11434/api/generate"):
        self.model = model
        self.api_url = api_url
        self.timeout = 60  # seconds

    def is_available(self) -> bool:
        """Check if the Ollama service is running and available."""
        try:
            response = requests.head(self.api_url.replace("/api/generate", ""), timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def generate_response(self, prompt: str) -> Optional[str]:
        """
        Generate a response from the Ollama LLM.

        Args:
            prompt: The prompt to send to the LLM.

        Returns:
            The generated text response, or None if an error occurred.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False  # We want the full response at once
        }
        
        try:
            logger.info(f"Sending prompt to Ollama model: {self.model}")
            response = requests.post(self.api_url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            if "response" in data:
                logger.info("Received successful response from Ollama")
                return data["response"].strip()
            else:
                logger.error(f"Ollama response did not contain 'response' key: {data}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error(f"Request to Ollama timed out after {self.timeout} seconds.")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error communicating with Ollama: {e}")
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred in Ollama client: {e}")
            return None

    def ask_single_event(self, event: Dict[str, Any], prompt_template: str) -> Optional[str]:
        """
        Generate an analysis for a single security event.

        Args:
            event: The event dictionary.
            prompt_template: The prompt template to use.

        Returns:
            The LLM-generated analysis, or None on failure.
        """
        prompt = prompt_template.format(event=event)
        return self.generate_response(prompt)

    def generate_summary_report(self, events: list, prompt_template: str) -> Optional[str]:
        """
        Generate a summary report for a list of security events.

        Args:
            events: A list of event dictionaries.
            prompt_template: The prompt template to use.

        Returns:
            The LLM-generated summary report, or None on failure.
        """
        prompt = prompt_template.format(events=events)
        return self.generate_response(prompt)
