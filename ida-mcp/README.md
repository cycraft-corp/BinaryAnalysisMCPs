# IDA MCP
IDA MCP integrates IDA Pro with the Model Context Protocol (MCP), enabling streamlined automation and LLM-assisted workflows.

⚡ **Optimized for small local LLMs** — built for fast, efficient use with lightweight models like Gemma 3 and Qwen 3.

🧠 **LLM-friendly UX** — structured prompts and minimal context usage for smoother local model performance.

For more advanced malware reverse engineering or online models, see [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).

## ✅ Requirements
- IDA Pro **9.0 or later**
- Python 3.8+
- [`uv`](https://github.com/astral-sh/uv) (for dependency management)

## ⚙️ Installation & Usage
1. Install this package
    ```bash
    uv pip install -e --system .
    ```
2. Install [idalib](https://docs.hex-rays.com/user-guide/idalib)
    > ⚠️ Elevated privileges may be required if `idapro.egg-info` cannot be created.
    ```bash
    pip install <IDA Pro Dir>/idalib/python
    python '<IDA Pro Dir>/idalib/python/py-activate-idalib.py'
    ```
3. Run the MCP server
    ```
    ida-mcp
    ```


## 🙌 Credits
* [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
