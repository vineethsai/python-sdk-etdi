"""
ETDI server-side components for OAuth security and tool management
"""

# Import core components that don't depend on main MCP
from .middleware import OAuthSecurityMiddleware
from .token_manager import TokenManager

# Import MCP-dependent components only if available
try:
    from .secure_server import ETDISecureServer
    _mcp_available = True
except ImportError:
    _mcp_available = False

__all__ = [
    "OAuthSecurityMiddleware",
    "TokenManager",
]

if _mcp_available:
    __all__.extend([
        "ETDISecureServer",
    ])