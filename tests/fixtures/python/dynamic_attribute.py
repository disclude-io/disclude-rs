# Reach attributes by runtime-constructed names.
def call(obj, attr):
    fn = getattr(obj, attr)
    return fn()


def bad(obj, prefix):
    return getattr(obj, prefix + "_impl")


def through_globals(name):
    return globals()[name]
