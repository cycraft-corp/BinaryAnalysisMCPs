"""
General utility functions module, used for handling address conversion, type checking, and other common operations.
"""

from typing import Any
import ida_hexrays

def paginate_results(
    items: list[Any], page: int = 0, page_size: int = 50
) -> dict[str, Any]:
    """
    Paginate a result set

    Args:
        items: List of items to paginate
        page: Page number (starting from 0)
        page_size: Number of items per page

    Returns:
        Dictionary containing pagination information and current page data
    """
    start_idx = page * page_size
    end_idx = start_idx + page_size

    return {
        "total": len(items),
        "page": page,
        "page_size": page_size,
        "items": items[start_idx:end_idx],
    }

def refresh_decompiler_ctext(function_address: int):
    # ref: https://github.com/mrexodia/ida-pro-mcp/blob/709543078886b007d66904a6dcb307cd74071f46/src/ida_pro_mcp/mcp-plugin.py#L1151
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(
        function_address, error, ida_hexrays.DECOMP_WARNINGS
    )
    if cfunc:
        cfunc.refresh_func_ctext()
