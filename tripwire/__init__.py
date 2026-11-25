"""Tripwire — detect an inbound agent by behaviour."""
__version__ = "0.1.0"
from .canary import generate, load, match, revoke  # noqa: F401
from .detect import analyse  # noqa: F401
