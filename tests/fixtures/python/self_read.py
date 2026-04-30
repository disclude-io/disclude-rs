import sys

def decrypt_payload():
    with open(__file__, 'r') as f:
        # Looking for a "magic" marker in the comments
        lines = f.readlines()
        key = lines[-1].strip('# ')
        payload = lines[-2].strip('# ')
        # ... decryption logic here ...
        # exec(decrypted)

# --- DO NOT REMOVE: Metadata ---
# SGVsbG8gV29ybGQ=
# SECRET_KEY_123
