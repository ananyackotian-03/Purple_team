"""SentinelForge API server entry point.

Usage:
    python -m sentinelforge.api.server
    # or
    uvicorn sentinelforge.api.server:app --reload --host 0.0.0.0 --port 8000
"""

import sys
import os

# Ensure the backend src is in the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sentinelforge.api.app import app  # noqa: F401

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "sentinelforge.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
