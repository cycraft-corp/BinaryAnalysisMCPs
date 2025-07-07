"""
IDA MCP Server Main Module - Creates FastAPI application and registers MCP tools and resources.
"""

# need to import idapro first for other imports to work
import sys
import idapro
from mcp.server.fastmcp import FastMCP
import inspect
from typing import Callable

from .tools.basic import (
    load_file,
    close_file, 
    get_imports, 
)
from .tools.functions import (
    rename_func,
    decompile_func,
    get_entry_points
)
from .tools.variables import (
    rename_var,
    retype_var,
)
from .tools.xref import (
    get_xrefs
)
import logging
import functools

logging.basicConfig(level=logging.INFO)
mcp = FastMCP("IDA MCP", log_level="INFO", host="0.0.0.0", port=8744)

# basic tools
mcp.tool()(load_file)
mcp.tool()(close_file)
mcp.tool()(get_imports)

# variable tools
mcp.tool()(rename_var)
mcp.tool()(retype_var)

# function tools
mcp.tool()(rename_func)
mcp.tool()(decompile_func)
mcp.tool()(get_entry_points)

# xref tools
mcp.tool()(get_xrefs)

def main():
    mcp.run(transport="sse")
    
if __name__ == "__main__":
    main()