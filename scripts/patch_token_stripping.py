"""
Patch main.py to add token stripping
"""

# Read the file
with open('main.py', 'r') as f:
    lines = f.readlines()

# Find the line with the print statement (line ~1428)
# Insert token stripping code before it

token_stripping_code = '''            
            # Strip special tokens that some models (especially Mistral/LLaMA) return
            if ai_message:
                # Common special tokens to remove
                for token in ['<s>', '</s>', '<|startoftext|>', '
