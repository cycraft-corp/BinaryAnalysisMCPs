import idc
import ida_hexrays
import idaapi
import ida_typeinf
from .basic import ea_2_name, name_2_ea
from .utils import refresh_decompiler_ctext

class rename_visited(ida_hexrays.ctree_visitor_t):
    def __init__(self, target: str, new_name: str):
        self.target = target
        self.new_name = new_name
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

    def visit_insn(self, arg0):
        return 0

    def visit_expr(self, arg0: ida_hexrays.cexpr_t):
        if arg0.dstr() == self.target:
            idaapi.set_name(arg0.obj_ea, self.new_name)
            return 0
        return 0

class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    # ref: https://github.com/mrexodia/ida-pro-mcp/blob/709543078886b007d66904a6dcb307cd74071f46/src/ida_pro_mcp/mcp-plugin.py#L1289
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvars):
        for lvar_saved in lvars.lvvec:
            lvar_saved: ida_hexrays.lvar_saved_info_t
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False



def rename_var(
    func_name: str, 
    ori_var_name: str, 
    new_var_name: str
) -> str:
    """
    Rename a variable in a function
    """
    func_ea = name_2_ea(func_name)
    if ida_hexrays.rename_lvar(func_ea, ori_var_name, new_var_name):
        return

    dfunc = idaapi.decompile(func_ea)
    if rename_visited(ori_var_name, new_var_name).apply_to(dfunc.body, None) != 0:
        raise Exception(f"can not find {ori_var_name} in 0x{func_ea:x}")
    refresh_decompiler_ctext(func_ea)
    return "OK"

def retype_var(
    func_name: str, 
    var_name: str,
    new_type: str,
) -> str:
    '''
    Retype a variable in a function
    '''
    func_ea = name_2_ea(func_name)
    new_tif = ida_typeinf.tinfo_t()
    # parse_decl requires semicolon for the type
    if (
        ida_typeinf.parse_decl(
            new_tif, idaapi.cvar.idati, new_type + ";", ida_typeinf.PT_SIL
        )
        is None
    ):
        raise ValueError(f"can not find type {new_type}")

    # check if it's a global first
    ea = name_2_ea(var_name)
    if ea != idaapi.BADADDR:
        if not ida_typeinf.apply_tinfo(ea, new_tif, ida_typeinf.PT_SIL):
            raise ValueError(
                f"failed to apply {new_type} to {var_name} in {hex(func_ea)}"
            )
        return "OK"

    # then try to apply to local
    if not ida_hexrays.rename_lvar(func_ea, var_name, var_name):
        raise ValueError(f"Failed to find local variable: {var_name}")

    modifier = my_modifier_t(var_name, new_tif)
    if not ida_hexrays.modify_user_lvars(func_ea, modifier):
        raise ValueError(
            f"failed to modify local variable: {var_name} in {hex(func_ea)}"
        )
    return "OK"
