VERBOSE = False


def set_verbose(enabled):
    """Enable or disable verbose console logging."""
    global VERBOSE
    VERBOSE = enabled


def verbose_print(*args, **kwargs):
    """Print only when verbose mode is enabled."""
    if VERBOSE:
        print(*args, **kwargs)