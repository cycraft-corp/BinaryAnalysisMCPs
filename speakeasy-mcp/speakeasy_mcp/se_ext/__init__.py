from . import enterhook
from . import prehook
from .hooks import Speakeasy_EXT


# patches for SE internal
import speakeasy.winenv.defs.windows.windows as windefs
windefs.ERROR_BUFFER_OVERFLOW = 111