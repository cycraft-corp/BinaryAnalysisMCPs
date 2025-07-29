from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import StandardBreakpointType, HardwareBreakpointType, MemoryBreakpointType, RegDump
from mcp.server.fastmcp import FastMCP
from json import loads
from pefile import PE
from typing import Callable, Dict, List
from loguru import logger
from typing import Annotated, TypedDict
import inspect
import typing_inspection.introspection as intro
from pprint import pprint, pformat
from pathlib import Path
import os

mcp = FastMCP("x64dbg", host="0.0.0.0")
dbgClient:X64DbgClient = None
BITNESS = 64

def check_dbg_client_status(func:Callable):
    def wrap(*args, **kwargs):
        logger.info(f"{func.__name__} debuuger status {dbgClient.is_running()} {dbgClient.is_debugging()}")
        return func(*args, **kwargs)  
    return wrap  

class MemoryRegion(TypedDict):
    BaseAddress: Annotated[str, 'Base address of the memory region in hex']
    RegionSize: Annotated[str, 'Size of the memory region in hex']
    State: Annotated[int, 'Memory state (e.g., MEM_COMMIT, MEM_FREE)']
    Protect: Annotated[int, 'Protection flags']
    Type: Annotated[int, 'Type of memory (e.g., MEM_PRIVATE, MEM_MAPPED)']

def resolve_relavtive_call(addr:int)->str:
    resolved_addr = -1
    match BITNESS:
        case 32:
            resolved_addr = dbgClient.read_dword(addr)
        case 64:
            resolved_addr = dbgClient.read_qword(addr)
        case _:
            raise ValueError(f"unsupported bitness: {BITNESS}")
    
    sym = dbgClient.get_label_at(resolved_addr)
    if sym == "":
        raise ValueError(f"{hex(addr)} does not contains label")
    return sym

def dump_current_state()->str:
    dbgClient.wait_cmd_ready()
    # registers
    dump:RegDump = dbgClient.get_regs()

    # general purpose regs
    ## 32bit
    gpr_32 = ["eax", "ebx", "ecx", "edx", "ebp", "esp", "esi", "edi", "eip"]
    ## 64bit
    gpr_64 = ["rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi", "rip"] 
    
    def generate_reg_syntax(regname:str, regval:int):
        if regname in gpr_32 + gpr_64:
            symbol = dbgClient.get_label_at(regval)
            
            return hex(regval) + (f" -> {symbol}" if symbol != '' else "")
        else:
            return hex(regval)

    dump_dict = dump.model_dump()
    registers:dict[str, str] = {
        k:generate_reg_syntax(k, v)
        for k, v in dump_dict["context"].items()
        if k in [
            ## 32 bit
            "eflags",
        ] + gpr_32 +
        [
            ## 64 bit
            "rflags",
        ] + gpr_64 +
        [
            ## other purpose
            "gs", "fs", "cs", "ss"
        ]
    }
    
    # asm
    instrs:List[str] = []
    
    ip = dump_dict["context"]["eip" if "eax" in registers else "rip"]
    for i in range(20):
        instr = dbgClient.disassemble_at(ip)
        symbol = dbgClient.get_label_at(ip)
        
        if instr.instruction.startswith("call qword ptr ds:") or instr.instruction.startswith("call dword ptr ds:"): # relative call to data
            ori_instr = instr.instruction
            try:
                sym = resolve_relavtive_call(
                    int(ori_instr.split("[")[1][:-1][2:], 16)
                )
                ori_instr = ori_instr.split("[")[0] + f"[{sym}]"
            except ValueError:
                ori_instr = instr.instruction
            
            instrs.append(f"{hex(ip)} | {ori_instr}")
        else:
            instrs.append(f"{hex(ip)} | {instr.instruction}")
        ip += instr.instr_size

    # stack
    stk_view = []

    stk_btm:int = dump_dict["context"]["esp" if "eax" in registers else "rsp"]
    stk_top:int = dump_dict["context"]["ebp" if "eax" in registers else "rbp"]
    
    ptr_size = 4 if "eax" in registers else 8
    for i in range(min((stk_top - stk_btm) // ptr_size, 20)):
        raw_content = dbgClient.read_memory(
            stk_btm + i * ptr_size, 
            ptr_size
        )
        stk_content = raw_content[::-1].hex()
        symbol = dbgClient.get_label_at(int.from_bytes(raw_content, 'little'))
        stk_view.append(f"{hex(stk_btm + i * ptr_size)} | {stk_content}" + (f" -> {symbol}" if symbol != '' else ""))
    
    return "[registers]\n" + pformat(registers) + \
           "\n\n[assembly]\n"  + pformat(instrs) + \
           "\n\n[stack]\n"     + pformat(stk_view)
    


@mcp.tool()
def start_session(
    target: Annotated[str, "Path to the executable to launch"],
    cmdline: Annotated[str, "Command line arguments to pass to the executable (optional)"] = ""
) -> str:
    """
    Start a debugging session with a target executable and run until the entrypoint.
    """
    global dbgClient
    if dbgClient is not None:
        if target == "":
            raise ValueError("target is not provided")
        elif len(dbgClient.list_sessions()) != 0:
            dbgClient.terminate_session()

    is_rundll32 = Path(target) == Path(r"C:\\Windows\\System32\\rundll32.exe")

    def create_dbg_client(exe:PE):
        global dbgClient
        global BITNESS
        machine_type:int = exe.FILE_HEADER.Machine
        match machine_type: # ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
            case 0x8664: # IMAGE_FILE_MACHINE_AMD64
                logger.info("create 64 bit client")
                BITNESS = 64
                dbgClient = X64DbgClient("C:\\x64dbg\\release\\x64\\x64dbg.exe")
            case 0x014c: # IMAGE_FILE_MACHINE_I386
                logger.info("create 32 bit client")
                BITNESS = 32
                dbgClient = X64DbgClient("C:\\x64dbg\\release\\x32\\x32dbg.exe")
            case _:
                raise ValueError(f"unsupport machine type {machine_type}")

    if is_rundll32:
        exe = PE(cmdline.split(',')[0])
    else:
        exe = PE(target)
    
    create_dbg_client(exe)
        

    if exe.OPTIONAL_HEADER.DllCharacteristics & 64 != 0:
        exe.OPTIONAL_HEADER.DllCharacteristics = exe.OPTIONAL_HEADER.DllCharacteristics ^ 64

        if is_rundll32:
            dllname = cmdline.split(',')[0]
            logger.info(f"rewrite binary {dllname}")
            exe.write(dllname + ".dbg")
            logger.info(f"done rewrite binary {dllname}.dbg")
            cmdline = dllname + ".dbg" + cmdline.removeprefix(dllname)
        else:
            logger.info(f"rewrite binary {target}")
            target += ".dbg"
            exe.write(target)
            logger.info(f"done rewrite binary {target}")

    logger.info(f"run {target} {cmdline}")
    dbgClient.start_session(target_exe=target, cmdline=cmdline)
    if not dbgClient.go():
        raise Exception(f"can not launch {target} {cmdline}")
    dbgClient.wait_until_debugging(99999) # make sure item is in debuggable state
    dbgClient.clear_breakpoint()
    return "OK"

@mcp.tool()
def get_running_status() -> str:
    debugging = dbgClient.is_debugging()
    running = dbgClient.is_running()
    #logger.info(f"debugging: {debugging} running: {running}")
    
    return [
        [
            "idk",
            "program terminated"
        ],
        [
            "still executing",
            "step on breakpoint"
        ]
    ][int(debugging)][int(running)]

@mcp.tool()
def continue_execution(
    timeout: Annotated[int, 'Wait time for program execution, default 10 seconds'] = 10,
)->str:
    """
    Continue execution until the debuggee is halted.
    """
    if not dbgClient.is_debugging():
        raise Exception("not in debugging")
    
    dbgClient.wait_cmd_ready()
    if not dbgClient.go():
        raise Exception(get_running_status())
    
    dbgClient.wait_cmd_ready(timeout)
    return dump_current_state()

@mcp.tool()
def pause()->str:
    """
    Pause the debuggee. This method will block until the debuggee is in the stopped state.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.pause():
        raise Exception(get_running_status())
    return dump_current_state()

@mcp.tool()
def step_into(
    step_count: Annotated[int, "Number of instructions to step into. Default is 1"] = 1,
    pass_exceptions: Annotated[bool, "Whether to pass exceptions during stepping. Default is False"] = False,
    swallow_exceptions: Annotated[bool, "Whether to swallow exceptions during stepping. Default is False"] = False,
    wait_for_ready: Annotated[bool, "Whether to wait for the debuggee to be ready. Default is True"] = True,
    wait_timeout: Annotated[int, "Timeout in seconds to wait for the debuggee to be ready. Default is 2"] = 2
) -> str:
    """
    Step into the next instruction. This method will block until the debuggee is in the stopped state.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.stepi(
        step_count=step_count, 
        pass_exceptions=pass_exceptions, 
        swallow_exceptions=swallow_exceptions, 
        wait_for_ready=wait_for_ready,
        wait_timeout=wait_timeout
    ):
        raise Exception(get_running_status())
    return dump_current_state()

@mcp.tool()
def step_over(
    step_count: Annotated[int, "Number of instructions to step out. Default is 1"] = 1,
    pass_exceptions: Annotated[bool, "Whether to pass exceptions during stepping. Default is False"] = False,
    swallow_exceptions: Annotated[bool, "Whether to swallow exceptions during stepping. Default is False"] = False,
    wait_for_ready: Annotated[bool, "Whether to wait for the debuggee to be ready. Default is True"] = True,
    wait_timeout: Annotated[int, "Timeout in seconds to wait for the debuggee to be ready. Default is 2"] = 2
) -> str:
    """
    Step out of the current function. This method will block until the debuggee is in the stopped state.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.stepo(
        step_count=step_count, 
        pass_exceptions=pass_exceptions, 
        swallow_exceptions=swallow_exceptions, 
        wait_for_ready=wait_for_ready,
        wait_timeout=wait_timeout
    ):
        raise Exception(get_running_status())
    return dump_current_state()

@mcp.tool()
def skip(
    skip_count: Annotated[int, "Number of instructions to skip. Default is 1"] = 1,
    wait_for_ready: Annotated[bool, "Whether to wait for the debuggee to be ready. Default is True"] = True,
    wait_timeout: Annotated[int, "Timeout in seconds to wait for the debuggee to be ready. Default is 2"] = 2
) -> str:
    """
    Skip over N instructions.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.skip(
        skip_count=skip_count, 
        wait_for_ready=wait_for_ready,
        wait_timeout=wait_timeout
    ):
        raise Exception(get_running_status())
    return dump_current_state()

@mcp.tool()
def ret(
    frames: Annotated[int, "Number of stack frames to return from. Default is 1"] = 1,
    wait_timeout: Annotated[int, "Timeout in seconds to wait for the debuggee to be ready. Default is 2"] = 2
)->str:
    """
    Step until a return instruction is encountered.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.ret(
        frames=frames, 
        wait_timeout=wait_timeout
    ):
        raise Exception(get_running_status())
    return dump_current_state()

@mcp.tool()
def write_memory(
    address: Annotated[str, 'Address in the debuggee\'s memory to write to. Should begin with "0x"'],
    data: Annotated[bytes, "Data to write to the specified address"]
) -> None:
    """
    Write data to the debuggee's memory at the specified address.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.write_memory(int(address[2:], 16), data):
        raise Exception(get_running_status())

@mcp.tool()
def read_memory(
    address: Annotated[str, 'Address in the debuggee\'s memory to read from. Should begin with "0x"'],
    size: Annotated[int, "Number of bytes to read, 8 bytes maxium"]
) -> str:
    """
    Read data from the debuggee's memory at the specified address.
    """
    if size > 8:
        raise ValueError("Too large")
    
    dbgClient.wait_cmd_ready()

    return dbgClient.read_memory(int(address[2:], 16), size).hex()

@mcp.tool()
def get_memory_map() -> list[MemoryRegion]:
    """
    Get the memory map of the debuggee.

    Returns:
        list[MemoryRegion]: List of memory regions in the debuggee's address space.
    """
    dbgClient.wait_cmd_ready()
    mem_pages = dbgClient.memmap()
    return [MemoryRegion(
        BaseAddress=hex(mem_page.base_address),
        RegionSize=hex(mem_page.region_size),
        State=mem_page.state,
        Protect=mem_page.protect,
        Type=mem_page.type
    ) for mem_page in mem_pages]

@mcp.tool()
def set_breakpoint(
    address_or_symbol: Annotated[str, 'Address (starting with "0x") or symbol name to set the breakpoint at'],
    name: Annotated[str | None, 'Optional name for the breakpoint. Default is None'] = None,
    bp_type: Annotated[str, 'Type of breakpoint: short, ss (Singleshot), Long, Ud2. Default is "short"'] = "short"
) -> str:
    """
    Set a breakpoint at the specified address or symbol.
    """
    dbgClient.wait_cmd_ready()
    bp_type = StandardBreakpointType(bp_type)
    if bp_type is None:
        raise ValueError(f"Invalid breakpoint type: {bp_type}.")
    
    # check address exsist
    if address_or_symbol.startswith("0x"):
        if not dbgClient.check_valid_read_ptr(int(address_or_symbol[2:], 16)):
            raise ValueError(f"address {address_or_symbol} not exsist")
    else:
        addr, success = dbgClient.eval_sync(address_or_symbol)
        #print(f"at {hex(addr)}")
        if not success:
            raise ValueError(f"can not locate symbol {address_or_symbol}")

    dbgClient.set_breakpoint(
        address_or_symbol=int(address_or_symbol[2:], 16) if address_or_symbol.startswith("0x") else address_or_symbol, 
        name=name, 
        bp_type=bp_type
    )
    return "OK"

@mcp.tool()
def set_hardware_breakpoint(
    address_or_symbol: Annotated[str, 'Address (starting with "0x") or symbol name to set the hardware breakpoint at'],
    bp_type: Annotated[str, 'Type of hardware breakpoint: x (execute), r (read), w (write). Default is "x"'] = "x",
    size: Annotated[int, 'Size of the hardware breakpoint. Default is 1'] = 1
) -> str:
    """
    Set a hardware breakpoint at the specified address or symbol.
    """
    dbgClient.wait_cmd_ready()
    bp_type = HardwareBreakpointType(bp_type)
    if bp_type is None:
        raise ValueError(f"Invalid hardware breakpoint type: {bp_type}.")

    if not dbgClient.set_hardware_breakpoint(
        address_or_symbol=int(address_or_symbol[2:], 16) if address_or_symbol.startswith("0x") else address_or_symbol, 
        bp_type=bp_type, 
        size=size
    ):
        raise Exception(get_running_status())
    return "OK"

@mcp.tool()
def set_memory_breakpoint(
    address_or_symbol: Annotated[str, 'Address (starting with "0x") or symbol name to set the memory breakpoint at'],
    bp_type: Annotated[str, 'Type of memory breakpoint: a (access), r (read), w (write), x (execute). Default is "a"'] = "a",
    singleshoot: Annotated[bool, 'Whether to set the breakpoint as a singleshoot. Default is False'] = False
) -> str:
    """
    Set a memory breakpoint at the specified address or symbol.
    """
    dbgClient.wait_cmd_ready()
    bp_type = MemoryBreakpointType(bp_type)
    if bp_type is None:
        raise ValueError(f"Invalid memory breakpoint type: {bp_type}.")

    if not dbgClient.set_memory_breakpoint(
        address_or_symbol=int(address_or_symbol[2:], 16) if address_or_symbol.startswith("0x") else address_or_symbol, 
        bp_type=bp_type, 
        singleshoot=singleshoot
    ):
        raise Exception(get_running_status())
    return "OK"

@mcp.tool()
def clear_breakpoint(
    address_symbol_or_none: Annotated[str | None, 'Address (starting with "0x") or symbol name to clear the breakpoint at. If None, all breakpoints will be cleared'] = None
) -> str:
    """
    Clear a breakpoint at the specified address or symbol.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.clear_breakpoint(
        int(address_symbol_or_none[2:], 16)
        if type(address_symbol_or_none) == str and address_symbol_or_none.startswith("0x")
        else address_symbol_or_none
    ):
        raise Exception(get_running_status())
    return "OK"

@mcp.tool()
def clear_hardware_breakpoint(
    address_symbol_or_none: Annotated[str | None, 'Address (starting with "0x") to clear the hardware breakpoint at. If None, all breakpoints will be cleared'] = None
) -> str:
    """
    Clear a hardware breakpoint at the specified address or symbol.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.clear_hardware_breakpoint(
        int(address_symbol_or_none[2:], 16)
        if type(address_symbol_or_none) == str and address_symbol_or_none.startswith("0x")
        else address_symbol_or_none
    ):
        raise Exception(get_running_status())
    return "OK"

@mcp.tool()
def clear_memory_breakpoint(
    address_symbol_or_none: Annotated[str | None, 'Address (starting with "0x") or symbol name to clear the memory breakpoint at. If None, all memory breakpoints will be cleared'] = None
) -> str:
    """
    Clear a memory breakpoint at the specified address or symbol.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.clear_memory_breakpoint(
        int(address_symbol_or_none[2:], 16)
        if type(address_symbol_or_none) == str and address_symbol_or_none.startswith("0x")
        else address_symbol_or_none
    ):
        raise Exception(get_running_status())
    return "OK"

@mcp.tool()
def get_reg(
    reg_name: Annotated[str, 'Name of the register to get the value of']
) -> str:
    """
    Get the value of a register as a hex string.
    """
    dbgClient.wait_cmd_ready()
    return hex(dbgClient.get_reg(reg_name))

@mcp.tool()
def set_reg(
    reg_name: Annotated[str, 'Name of the register to set the value of'],
    value: Annotated[int, 'Value to set the register to']
) -> str:
    """
    Set the value of a register.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.set_reg(reg_name, value):
        raise Exception(get_running_status())
    return "OK"

@mcp.tool()
def hide_debugger_peb() -> str:
    """
    Hide the debugger in the debuggee's PEB (Process Environment Block).
    This is useful for anti-debugging techniques that check for the presence of a debugger.
    """
    dbgClient.wait_cmd_ready()
    if not dbgClient.hide_debugger_peb():
        raise Exception(get_running_status())
    return "OK"

@mcp.tool()
def dump_memory_to_file(
    start_addr:str,
    end_addr:str,
    dump_filename = "dump.bin"
):
    dbgClient.wait_cmd_ready()
    start_ea = int(start_addr[2:], 16)
    end_ea   = int(end_addr[2:]  , 16)
    if end_ea < start_ea:
        raise ValueError("end_addr is smaller than start_addr")
    
    dbgClient.cmd_sync(f"savedata {os.getcwd()}\\{dump_filename},{hex(start_ea)},{hex(end_ea - start_ea)}")
    return "OK"

def fixup_tool_argument_descriptions(mcp: FastMCP):
    # ref: https://github.com/mrexodia/ida-pro-mcp/blob/709543078886b007d66904a6dcb307cd74071f46/src/ida_pro_mcp/idalib_server.py#L21
    # In our tool definitions within `mcp-plugin.py`, we use `typing.Annotated` on function parameters
    # to attach documentation. For example:
    #
    #     def get_function_by_name(
    #         name: Annotated[str, "Name of the function to get"]
    #     ) -> Function:
    #         """Get a function by its name"""
    #         ...
    #
    # However, the interpretation of Annotated is left up to static analyzers and other tools.
    # FastMCP doesn't have any special handling for these comments, so we splice them into the
    # tool metadata ourselves here.
    #
    # Example, before:
    #
    #     tool.parameter={
    #       properties: {
    #         name: {
    #           title: "Name",
    #           type: "string"
    #         }
    #       },
    #       required: ["name"],
    #       title: "get_function_by_nameArguments",
    #       type: "object"
    #     }
    #
    # Example, after:
    #
    #     tool.parameter={
    #       properties: {
    #         name: {
    #           title: "Name",
    #           type: "string"
    #           description: "Name of the function to get"
    #         }
    #       },
    #       required: ["name"],
    #       title: "get_function_by_nameArguments",
    #       type: "object"
    #     }
    #
    # References:
    #   - https://docs.python.org/3/library/typing.html#typing.Annotated
    #   - https://fastapi.tiangolo.com/python-types/#type-hints-with-metadata-annotations

    # unfortunately, FastMCP.list_tools() is async, so we break with best practices and reach into `._tool_manager`
    # rather than spinning up an asyncio runtime just to fetch the (non-async) list of tools.
    for tool in mcp._tool_manager.list_tools():
        sig = inspect.signature(tool.fn)
        for name, parameter in sig.parameters.items():
            # this instance is a raw `typing._AnnotatedAlias` that we can't do anything with directly.
            # it renders like:
            #
            #      typing.Annotated[str, 'Name of the function to get']
            if not parameter.annotation:
                continue

            # this instance will look something like:
            #
            #     InspectedAnnotation(type=<class 'str'>, qualifiers=set(), metadata=['Name of the function to get'])
            #
            annotation = intro.inspect_annotation(
                                                  parameter.annotation,
                                                  annotation_source=intro.AnnotationSource.ANY
                                              )

            # for our use case, where we attach a single string annotation that is meant as documentation,
            # we extract that string and assign it to "description" in the tool metadata.
            if len(annotation.metadata) != 1:
                continue

            description = annotation.metadata[0]
            if not isinstance(description, str):
                continue

            logger.debug(f"adding parameter documentation {tool.name}({name}='{description}')")
            tool.parameters["properties"][name]["description"] = description

        
def list_tool_annotations(mcp: FastMCP):
    for tool in mcp._tool_manager.list_tools():
        from pprint import pprint
        pprint(tool.parameters)

def main():
    # https://github.com/modelcontextprotocol/python-sdk/issues/466
    fixup_tool_argument_descriptions(mcp)
    #list_tool_annotations(mcp)
    mcp.run(transport="sse")

if __name__ == "__main__":
    main()