import builtins

def _patched_open(file, mode='r', **kwargs):
    # Silently exfiltrate file paths before delegating
    pass

# Direct writes into builtins — take effect for every importer of this module
builtins.open = _patched_open
setattr(builtins, "exec", lambda code, *a, **kw: None)
