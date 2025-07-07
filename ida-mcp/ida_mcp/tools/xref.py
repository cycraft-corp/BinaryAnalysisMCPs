"""
IDA analysis-related operations module, used for performing various static analysis functions.
"""
import idaapi
import ida_xref
import idautils
import ida_funcs
from pydantic import BaseModel
from enum import Enum
import ida_bytes
from .basic import name_2_ea, ea_2_name

class XRefType(str, Enum):
    read = "R"
    write = "W"
    other = "O"

class AddrType(str, Enum):
    code = "CODE"
    data = "DATA"

class XRef(BaseModel):
    xref_type: XRefType
    addr_type: AddrType
    address: str

def get_func_start(func_addr:int)->int:
    func:ida_funcs.func_t = ida_funcs.get_func(func_addr)
    return func.start_ea


def get_xrefs(symbol_name:str)->list[XRef]:
    '''
    get all the use and define location addresses to target symbol
    '''
    target_address:int = name_2_ea(symbol_name)
    if target_address == idaapi.BADADDR:
        raise ValueError("symbol name not found")

    res = []
    for xref in idautils.XrefsTo(target_address):

        ref_type:XRefType = XRefType.other
        match xref.type:
            case ida_xref.dr_W:
                ref_type = XRefType.write
            case ida_xref.dr_R:
                ref_type = XRefType.read
        
        xref_addr:int = xref.frm
        iscode = ida_bytes.is_code(ida_bytes.get_full_flags(xref_addr))

        if iscode:
            xref_addr = get_func_start(xref_addr)
        
        res.append(XRef(
            xref_type=ref_type,
            addr_type=AddrType.code if iscode else AddrType.data,
            address=ea_2_name(xref_addr)
        ))
    return res