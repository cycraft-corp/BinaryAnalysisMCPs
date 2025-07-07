from speakeasy import Speakeasy
from functools import wraps
from typing import Callable, List, Tuple, Any
from inspect import signature, getmembers, isclass
from speakeasy.winenv.api.api import ApiHandler
import pkgutil
import importlib

# pre hook
NEW_REGISTER_APIS:List[Tuple[str, int, str, Callable]] = [] # dll, argc, orignal name, func

def prehook(dllname: str):
    '''
    used when there actually exist some incomplete implementation
    '''
    def decorator(func:Callable):
        global NEW_REGISTER_APIS
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(args[0], args[2], *args[-1])
        
        NEW_REGISTER_APIS.append((dllname, len(signature(func).parameters) - 1, func.__name__, wrapper))
        return wrapper
    
    return decorator

class Speakeasy_EXT(Speakeasy):
    def __init__(self, config=None, logger=None, argv=[], debug=False, exit_event=None):
        super().__init__(config, logger, argv, debug, exit_event)

    def init_ext(self):
        self.emu.command_line = " ".join([ self.emu.file_name ] + self.argv)
        #self.emu.max_api_count = 114514

        for dllname, argc, fn, func in NEW_REGISTER_APIS:
            self.add_api_hook(
                func, dllname, fn, argc
            )

# enter hook
def list_submodules_dll(package_name: str)->dict[str, Any]:
    package = importlib.import_module(package_name)
    res = {}
    for _, name, _ in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        module = importlib.import_module(name)
        
        for name, cls in getmembers(module, isclass):
            if cls.__module__ == module.__name__:
                res.update({name.lower():cls})
    return res

se_dlls_submods = list_submodules_dll("speakeasy.winenv.api.usermode")

def enterhook(dllname:str):
    '''
    an overwrite hook for overwritting original speakeasy classes.
    usually for fixing error in PE import parsing. 
    '''
    
    def decorator(func:Callable):
        target_dll = se_dlls_submods[dllname.lower()]
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(args[1], *args[2])
        
        ApiHandler.apihook(func.__name__, argc=len(signature(func).parameters) - 1)(wrapper)
        setattr(target_dll, func.__name__, wrapper)
        return wrapper

    return decorator