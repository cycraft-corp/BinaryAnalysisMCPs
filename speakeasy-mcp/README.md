# Speakeasy MCP
**Speakeasy MCP** is a **server-side emulation service** built on top of [Speakeasy](https://github.com/mandiant/speakeasy).
It provides **rich emulation results via a long-running backend**, designed to **enhance binary analysis workflows** by offering dynamic insights into Windows executables.

## 🔧 Features
- 🧩 **Modular architecture** – Plug in analysis routines, extractors, and output formats
- 🧠 **Emulation-as-a-service** – Persistent backend that handles emulation sessions on demand
- 📊 **Enhanced binary insights** – Generate structured API traces and behavioral logs suitable for LLM consumption
- 🔌 **Integration-ready** – Provide emulation results via **Server-Sent Events (SSE)**

## 🚀 Installation & Startup
1. Install the package using [uv](https://github.com/astral-sh/uv)
   ```bash
   uv pip install -e --system .
   ```
2. Start the Speakeasy MCP server
    ```bash
    speakeasy-mcp
    ```
