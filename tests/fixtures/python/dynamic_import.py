# Dynamic import reached through a runtime-constructed name.
def load(plugin_name):
    return __import__(plugin_name)


def load_joined(prefix, suffix):
    return __import__(prefix + suffix)
