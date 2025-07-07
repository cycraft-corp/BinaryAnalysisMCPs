"""
IDA function-related operations module, used for handling function analysis and queries.
"""
import ida_funcs
import ida_hexrays
import idaapi
import idc
import idautils
import ida_entry
import ida_kernwin
import ida_lines
from .basic import name_2_ea, ea_2_name

def decompile_func(
    func_name: str, start_line: int = 0, end_line: int = 300
) -> str:
    """
    Get decompiled pseudocode for the function at the specified name
    """
    address = name_2_ea(func_name)
    cfunc = idaapi.decompile_func(address)
    sv = cfunc.get_pseudocode()
    pseudocode = ""
    for i, sl in enumerate(sv):
        if i < start_line:
            continue
        if i > end_line:
            continue
        
        sl: ida_kernwin.simpleline_t
        item = ida_hexrays.ctree_item_t()
        addr = None if i > 0 else cfunc.entry_ea
        if cfunc.get_line_item(sl.line, 0, False, None, item, None):
            ds = item.dstr().split(": ")
            if len(ds) == 2:
                try:
                    addr = int(ds[0], 16)
                except ValueError:
                    pass
        line = ida_lines.tag_remove(sl.line)
        if len(pseudocode) > 0:
            pseudocode += "\n"
        if not addr:
            pseudocode += f"/* line: {i} */ {line}"
        else:
            pseudocode += f"/* line: {i}, address: {hex(addr)} */ {line}"

    return pseudocode

def rename_func(ori_func_name: str, new_func_name: str) -> str:
    """
    Rename a function
    """
    func_ea = name_2_ea(ori_func_name)
    vu: ida_hexrays.vdui_t = idaapi.open_pseudocode(func_ea, 0)

    idaapi.set_name(
        idc.get_name_ea_simple(ori_func_name), new_func_name, idaapi.SN_FORCE
    )

    ida_funcs.reanalyze_function(
        ida_funcs.get_func(func_ea),
    )
    vu.refresh_ctext(True)
    idaapi.close_pseudocode(vu.ct)
    return "OK"

def get_entry_points() -> list[str]:
    """Get all entry points in the database"""
    result = [
        ea_2_name(func_ea)
        for func_ea in idautils.Functions() 
        if ea_2_name(func_ea).strip("_") in [
            "main",
            "winMain",
            "DllMain"
        ]
    ]

    if len(result) == 0:
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            address = ida_entry.get_entry(ordinal)
            if ida_funcs.get_func(address) is not None:
                result.append(ea_2_name(address))       
    return result
