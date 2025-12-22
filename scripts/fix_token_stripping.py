"""
Fix script to repair the token stripping code in main.py
Run this to fix the corrupted lines 1418-1445
"""

# The correct code should be:
correct_code = '''
            
            # Extract content based on provider
            if provider_type == "anthropic":
                ai_message = result["content"][0]["text"]
            elif provider_type == "gemini":
                ai_message = result["candidates"][0]["content"]["parts"][0]["text"]
            else:
                # OpenAI / OpenRouter / Ollama format
                ai_message = result["choices"][0]["message"]["content"]
            
            # Strip special tokens that some models return
            if ai_message:
                special_tokens = ['<s>', '</s>', '<|startoftext|>', '
