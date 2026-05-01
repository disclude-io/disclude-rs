import sys

def stealth_check():
    # Look at the caller's global namespace
    caller_globals = sys._getframe(1).f_globals
    if "analyzer_module" in caller_globals:
        sys.exit() # Exit if an analyzer is detected in the stack
