# x64dbg MCP
**x64dbg MCP** is a modular control pipeline (MCP) server for automating and interacting with the [x64dbg](https://x64dbg.com) debugger. It enables programmatic control of debugging workflows, and enables integration with large language models (LLMs), and other reverse engineering tools.

## 📦 Installation & Usage
1. Install the package
   ```bash
   uv pip install --system -e .
   ```
2. Install [x64dbg automate Python client](https://dariushoule.github.io/x64dbg-automate-pyclient/installation/)
3. Start the x64dbg MCP server
   ```bash
   x64dbg-mcp
   ```

## 🙌 Credits & Inspiration
* This project is inspired by [x64dbg-mcp by CaptainNox](https://github.com/CaptainNox/x64dbg-mcp/tree/main)
* [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)