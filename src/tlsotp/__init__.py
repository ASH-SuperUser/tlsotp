from .interface import *

try:
    from importlib.metadata import version
    __version__ = version("tlsotp")
except Exception:
    __version__ = "0.1.0"