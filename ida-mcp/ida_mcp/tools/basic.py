import idaapi
from pathlib import Path
import idc

try:
    # only avaible in idalib
    import idapro
    import os
    from time import sleep

    def load_file(file_path: str) -> str:
        """
        Load a file into IDA
        """
        print(f"Loading file: {file_path}")
        
        if idaapi.get_input_file_path() is not None:
            idapro.close_database(False)
        
        if not Path(file_path).exists():
            raise ValueError(f"File not found: {file_path}")

        # detect if scattered database exist
        for suffix in [
            ".id0",
            ".id1",
            ".id2",
            ".nam",
            ".til"
        ]:
            if os.path.exists(file_path + suffix):
                os.remove(file_path + suffix)
        
        idapro.open_database(file_path, True)
        
        # wait for auto-analysis to complete
        idc.auto_wait()
        return "OK"


    def close_file(save=True) -> str:
        """
        Close the current database
        """
        idapro.close_database(save)
        return "OK"
except:
    pass

def get_imports() -> dict[str, list[str]]:
    """Get the imported function from exeternal library by binary"""
    tree = {}
    nimps = idaapi.get_import_module_qty()


    for i in range(0, nimps):
        name = idaapi.get_import_module_name(i)
        if not name:
            continue
        # Create a list for imported names
        items = []


        def imports_names_cb(ea, name, ord):
            nonlocal items
            items.append('' if not name else name)
            # True -> Continue enumeration
            return True


        # Enum imported entries in this module
        idaapi.enum_import_names(i, imports_names_cb)

        if name not in tree:
            tree[name] = []
        tree[name].extend(items)

    return tree

def ea_2_name(addr:int)->str:
    name = idc.get_name(addr)
    if name == "":
        return hex(addr)
    return name

def name_2_ea(name:str)->int:
    if name.startswith("0x"):
        return int(name[2:], 16)
    return idaapi.get_name_ea(0, name)