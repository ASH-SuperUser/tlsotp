from .interface import *

try:
    from importlib.metadata import PackageNotFoundError, version
    __version__ = version("tlsotp")
except (PackageNotFoundError, ImportError):
    __version__ = "1.0.0"