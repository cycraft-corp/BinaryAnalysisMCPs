from mcp.server.fastmcp import FastMCP
import logging
from typing import Annotated, List
from types import MethodType
from loguru import logger
import inspect
import typing_inspection.introspection as intro
from dataclasses import dataclass
from speakeasy.windows.winemu import WindowsEmulator
from speakeasy.windows.win32 import Win32Emulator
from se_ext import Speakeasy_EXT

@dataclass
class EmuFile:
    real_path:str
    emu_path:str

@dataclass
class EmuConfig:
    main_exe: str
    additional_files: list[EmuFile]


@dataclass
class SpeakeasyLog:
    addr: int
    api: str
    args: str
    rv: str
    def __str__(self):
        return f'{hex(self.addr)}: {self.api}({self.args}) -> {self.rv}'

    def __eq__(self, value):
        if type(value) != SpeakeasyLog:
            raise ValueError(f"can not compare with type {type(value)}")
        
        return self.addr == value.addr and \
               self.api == value.api and \
               self.args == value.args and \
               self.rv == self.rv

# Initialize MCP instance
mcp = FastMCP("speakeasy", host="0.0.0.0")

# emu config, since speakeasy emulator does not support fully reset ... zzzz
emu_cfg = EmuConfig("", [])


def get_logger():
    """
    Get the default logger for speakeasy
    """
    logger = logging.getLogger('emu_exe')
    if not logger.handlers:
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.INFO)

    return logger


# Initialize Speakeasy emulator with custom logger
se = Speakeasy_EXT(logger=get_logger())
se_run_logs: list[SpeakeasyLog] = []
se_run_addr: set[int] = set()

@mcp.tool()
def emulator_add_file(
    input_filepath: Annotated[str, "Path to the physical file on disk"],
    mapped_filepath: Annotated[str, "Virtual file path to map within the emulator"]
) -> str:
    global emu_cfg
    logger.info(f"input_filepath: {input_filepath}")
    logger.info(f"mapped_filepath: {mapped_filepath}")

    emu_cfg.additional_files.append(EmuFile(input_filepath, mapped_filepath))
    return "OK"

@mcp.tool()
def emulator_create(
    binary_path: Annotated[str, "Path to the PE binary file to load into emulator"]
) -> str:
    global emu_cfg
    emu_cfg.main_exe = binary_path
    return "OK"

@mcp.tool()
def emulator_query_api(
    api_name: Annotated[str, "Name of the API function to search for in logs"]
) -> Annotated[str, "Newline-separated log entries containing the API name"]:
    return "\n".join([ 
        str(se_log)
        for se_log in se_run_logs
        if api_name.lower() in se_log.api.lower()
    ])

@mcp.tool()
def emulator_statisticize_invoked_api() -> Annotated[List[str], "List of unique API functions invoked during emulation"]:
    return list(set([ se_log.api for se_log in se_run_logs ]))

@mcp.tool()
def emulator_get_all_log() -> Annotated[str, "Full content of the emulator log buffer"]:
    return "\n".join([ 
        str(se_log)
        for se_log in se_run_logs
    ])

def log_api(self: WindowsEmulator, pc:int, imp_api:str, rv:str, argv:list):
    global se_run_logs
    global se_run_addr

    arg_str = ""
    for arg in argv:
        if isinstance(arg, int):
            arg_str += "0x%x" % (arg)
        elif isinstance(arg, str):
            arg_str += '"%s"' % (arg.replace("\n", "\\n"))
        elif isinstance(arg, bytes):
            arg_str += '"%s"' % (arg)
        arg_str += ", "
    if arg_str.endswith(", "):
        arg_str = arg_str[:-2]

    _rv = rv
    if _rv is not None:
        _rv = hex(rv)

    # remove some common apis
    if imp_api.split(".")[1] in [
        "MultiByteToWideChar",
        "WideCharToMultiByte",
        
        "InitializeCriticalSectionEx",
        "EnterCriticalSection",
        "LeaveCriticalSection",
        "InitializeCriticalSectionAndSpinCount",

        "SetLastError",
        "GetLastError",
        
        "HeapAlloc",
        "HeapFree",
        "HeapReAlloc",

        "FlsAlloc",
        "FlsGetValue",
        "FlsSetValue",
    ]:
        return
    data = SpeakeasyLog(addr=pc, api=imp_api, args=arg_str, rv=str(_rv))
    # log condensiing
    # remove the log if it's same with latest log
    if len(se_run_logs) == 0 or se_run_logs[-1] != data and pc not in se_run_addr:
        se_run_logs.append(data)
        se_run_addr.add(pc)

run_set:set[int] = set()
last_addr:int = 0

def runtime_trace(emu:Win32Emulator, addr:int, sz:int, _):
    global run_set
    global last_addr

    run_set.add(addr)
    last_addr = addr

@mcp.tool()
def emulator_run(
    timeout: Annotated[int, "Maximum emulation time in seconds, 10 by default"] = 10
) -> str:
    global se
    se_run_logs.clear()

    # Initialize Speakeasy emulator with custom logger
    se = Speakeasy_EXT(logger=get_logger())

    module = se.load_module(emu_cfg.main_exe)
    se.emu.timeout = timeout

    for emu_f in emu_cfg.additional_files: 
        with open(emu_f.real_path, "rb") as f:
            file_data = f.read()
        logger.info(f"add {emu_f.real_path} -> {emu_f.emu_path}")
        se.emu.fileman.add_existing_file(emu_f.emu_path, file_data)

    se.emu.log_api = MethodType(log_api, se.emu)
    #se.add_code_hook(runtime_trace)
    se.init_ext()
    se.run_module(module)
    '''
    for rs in run_set:
        print(hex(rs))
    logger.error(f"last addr: {hex(last_addr)}")
    '''
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


def main():
    fixup_tool_argument_descriptions(mcp)
    mcp.run(transport="sse")


if __name__ == "__main__":
    main()