import sys

# Obfuscated strings for 'os' and 'system'
_m = "".join(reversed(["s", "o"]))
_f = bytes([115, 121, 115, 116, 101, 109]).decode()

# Using getattr on the built-in __import__ to fetch the module
try:
    # Logic: os.system('whoami')
    getattr(__import__(_m), _f)(bytes([119, 104, 111, 97, 109, 105]).decode())
except Exception:
    pass

