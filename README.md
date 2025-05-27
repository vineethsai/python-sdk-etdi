# Model Context Protocol Python SDK with ETDI Security

A Python implementation of the Model Context Protocol (MCP) with Enhanced Tool Definition Interface (ETDI) security extensions that **seamlessly integrates** with existing MCP infrastructure.

## Overview

This SDK provides a secure implementation of MCP with OAuth 2.0-based security enhancements to prevent Tool Poisoning and Rug Pull attacks. ETDI adds cryptographic verification, immutable versioned definitions, and explicit permission management to the MCP ecosystem **while maintaining full compatibility** with existing MCP servers and clients.

## 🔄 **Seamless MCP Integration**

ETDI is designed for **zero-friction adoption** with existing MCP infrastructure:

### **✅ Backward Compatibility**
- **Existing MCP servers work unchanged** - ETDI clients can discover and use any MCP server
- **Existing MCP clients work unchanged** - ETDI servers are fully MCP-compatible
- **Gradual migration path** - Add security incrementally without breaking existing workflows
- **Optional security** - ETDI features are opt-in, not mandatory

### **🔌 Drop-in Integration**
```python
# Existing MCP server becomes ETDI-secured with one decorator
from mcp.server.fastmcp import FastMCP

app = FastMCP("My Server")

# Before: Regular MCP tool
@app.tool()
def my_tool(data: str) -> str:
    return f"Processed: {data}"

# After: ETDI-secured tool (existing code unchanged!)
@app.tool(etdi=True, etdi_permissions=['data:read'])
def my_tool(data: str) -> str:
    return f"Processed: {data}"  # Same logic, now cryptographically secured
```

### **🌐 Universal Discovery**
```python
# ETDI client discovers ALL MCP servers (ETDI and non-ETDI)
from mcp.etdi.client.etdi_client import ETDIClient

client = ETDIClient(config)
await client.connect_to_server(["python", "-m", "any_mcp_server"], "server-name")
tools = await client.discover_tools()  # Works with any MCP server!
```

## Features

### Core MCP Functionality
- **Client/Server Architecture**: Full MCP client and server implementations
- **Tool Management**: Register, discover, and invoke tools
- **Resource Access**: Secure access to external resources
- **Prompt Templates**: Reusable prompt templates for LLM interactions
- **🔄 Full MCP Compatibility**: Works with any existing MCP server or client

### ETDI Security Enhancements
- **OAuth 2.0 Integration**: Support for Auth0, Okta, Azure AD, and custom providers
- **Tool Verification**: Cryptographic verification of tool authenticity
- **Permission Management**: Fine-grained permission control with OAuth scopes
- **Version Control**: Automatic detection of tool changes requiring re-approval
- **Approval Management**: Encrypted storage of user tool approvals
- **🔌 Seamless Integration**: Add security to existing MCP tools with simple decorators

### Security Features
- **Tool Poisoning Prevention**: Cryptographic verification prevents malicious tool impersonation
- **Rug Pull Protection**: Version and permission change detection prevents unauthorized modifications
- **Multiple Security Levels**: Basic, Enhanced, and Strict security modes
- **Audit Logging**: Comprehensive security event logging
- **🛡️ Non-Breaking Security**: Security features don't break existing MCP workflows

## Installation

```bash
pip install mcp[etdi]
```

For development:
```bash
pip install mcp[etdi,dev]
```

## Quick Start

### ETDI Client

```python
import asyncio
from mcp.etdi import ETDIClient, OAuthConfig

async def main():
    # Configure OAuth provider
    oauth_config = OAuthConfig(
        provider="auth0",
        client_id="your-client-id",
        client_secret="your-client-secret",
        domain="your-domain.auth0.com",
        audience="https://your-api.example.com"
    )
    
    # Initialize ETDI client
    async with ETDIClient({
        "security_level": "enhanced",
        "oauth_config": oauth_config.to_dict()
    }) as client:
        
        # Discover and verify tools
        tools = await client.discover_tools()
        
        for tool in tools:
            if tool.verification_status.value == "verified":
                # Approve tool for usage
                await client.approve_tool(tool)
                
                # Invoke tool
                result = await client.invoke_tool(tool.id, {"param": "value"})
                print(f"Result: {result}")

asyncio.run(main())
```

### ETDI Secure Server

```python
import asyncio
from mcp.etdi import ETDISecureServer, OAuthConfig

async def main():
    # Configure OAuth
    oauth_configs = [
        OAuthConfig(
            provider="auth0",
            client_id="your-client-id",
            client_secret="your-client-secret",
            domain="your-domain.auth0.com"
        )
    ]
    
    # Create secure server
    server = ETDISecureServer(oauth_configs)
    
    # Register secure tool
    @server.secure_tool(permissions=["read:data", "write:data"])
    async def secure_calculator(operation: str, a: float, b: float) -> float:
        """A secure calculator with OAuth protection"""
        if operation == "add":
            return a + b
        elif operation == "multiply":
            return a * b
        else:
            raise ValueError(f"Unknown operation: {operation}")
    
    await server.initialize()
    print("Secure server running with OAuth protection")

asyncio.run(main())
```

## OAuth Provider Configuration

### Auth0

```python
from mcp.etdi import OAuthConfig

auth0_config = OAuthConfig(
    provider="auth0",
    client_id="your-auth0-client-id",
    client_secret="your-auth0-client-secret",
    domain="your-domain.auth0.com",
    audience="https://your-api.example.com",
    scopes=["read:tools", "execute:tools"]
)
```

### Okta

```python
okta_config = OAuthConfig(
    provider="okta",
    client_id="your-okta-client-id",
    client_secret="your-okta-client-secret",
    domain="your-domain.okta.com",
    scopes=["etdi.tools.read", "etdi.tools.execute"]
)
```

### Azure AD

```python
azure_config = OAuthConfig(
    provider="azure",
    client_id="your-azure-client-id",
    client_secret="your-azure-client-secret",
    domain="your-tenant-id",
    scopes=["https://graph.microsoft.com/.default"]
)
```

## 🔄 MCP Ecosystem Integration

ETDI is designed to work seamlessly with the entire MCP ecosystem, providing security enhancements without breaking existing workflows.

### **Connecting to Any MCP Server**

ETDI clients can connect to and discover tools from **any MCP server**, whether it uses ETDI security or not:

```python
from mcp.etdi.client.etdi_client import ETDIClient

# Connect to existing MCP servers
client = ETDIClient(config)

# Connect to a standard MCP server (no ETDI)
await client.connect_to_server(["python", "-m", "mcp_weather_server"], "weather")

# Connect to an ETDI-enabled server
await client.connect_to_server(["python", "-m", "secure_banking_server"], "banking")

# Connect to any MCP server via stdio
await client.connect_to_server(["node", "my-js-mcp-server.js"], "js-server")

# Discover tools from ALL connected servers
all_tools = await client.discover_tools()

# ETDI automatically handles security for ETDI tools,
# and provides basic compatibility for non-ETDI tools
for tool in all_tools:
    if tool.verification_status.value == "verified":
        print(f"✅ ETDI-secured: {tool.name}")
    else:
        print(f"🔓 Standard MCP: {tool.name}")
```

### **Upgrading Existing MCP Servers**

Transform any existing MCP server into an ETDI-secured server with minimal changes:

```python
# BEFORE: Standard MCP server with FastMCP
from mcp.server.fastmcp import FastMCP

app = FastMCP("My Banking Server")

@app.tool()
def transfer_money(from_account: str, to_account: str, amount: float) -> str:
    # Existing business logic unchanged
    return f"Transferred ${amount} from {from_account} to {to_account}"

@app.tool()
def get_balance(account_id: str) -> str:
    # Existing business logic unchanged
    return f"Account {account_id} balance: $1,234.56"

# AFTER: ETDI-secured server (same code + security decorators)
from mcp.server.fastmcp import FastMCP

app = FastMCP("My Banking Server")

@app.tool(etdi=True, etdi_permissions=['banking:write'], etdi_max_call_depth=2)
def transfer_money(from_account: str, to_account: str, amount: float) -> str:
    # Same business logic - now cryptographically secured!
    return f"Transferred ${amount} from {from_account} to {to_account}"

@app.tool(etdi=True, etdi_permissions=['banking:read'])
def get_balance(account_id: str) -> str:
    # Same business logic - now with permission control!
    return f"Account {account_id} balance: $1,234.56"
```

### **Mixed Environment Support**

ETDI supports mixed environments where some tools are secured and others are not:

```python
# Client configuration for mixed environments
config = ETDIClientConfig(
    security_level=SecurityLevel.ENHANCED,  # Strict for ETDI tools
    allow_non_etdi_tools=True,              # Allow standard MCP tools
    show_unverified_tools=True              # Show all available tools
)

client = ETDIClient(config)

# Discover tools from multiple server types
tools = await client.discover_tools()

for tool in tools:
    if tool.verification_status.value == "verified":
        # ETDI tool - full security verification
        await client.approve_tool(tool)
        result = await client.invoke_tool(tool.id, params)
    else:
        # Standard MCP tool - basic compatibility mode
        print(f"⚠️ Using unverified tool: {tool.name}")
        # Still works, but without ETDI security guarantees
```

### **Migration Strategies**

#### **1. Gradual Migration**
```python
# Start with basic security, upgrade incrementally
@app.tool(etdi=True)  # Basic ETDI security
def step1_tool(): pass

@app.tool(etdi=True, etdi_permissions=['data:read'])  # Add permissions
def step2_tool(): pass

@app.tool(etdi=True, etdi_permissions=['data:write'], etdi_max_call_depth=3)  # Full security
def step3_tool(): pass
```

#### **2. Parallel Deployment**
```python
# Run ETDI and non-ETDI versions side by side
@app.tool()  # Original version for backward compatibility
def legacy_calculator(a: int, b: int) -> int:
    return a + b

@app.tool(etdi=True, etdi_permissions=['math:calculate'])  # Secured version
def secure_calculator(a: int, b: int) -> int:
    return a + b  # Same logic, enhanced security
```

### **Ecosystem Compatibility Matrix**

| Component | ETDI Client | Standard MCP Client | ETDI Server | Standard MCP Server |
|-----------|-------------|-------------------|-------------|-------------------|
| **ETDI Client** | ✅ Full Security | ✅ Discovers Tools | ✅ Full Security | ✅ Basic Compatibility |
| **Standard MCP Client** | ✅ Basic Compatibility | ✅ Standard MCP | ✅ Basic Compatibility | ✅ Standard MCP |
| **ETDI Server** | ✅ Full Security | ✅ Basic Compatibility | N/A | N/A |
| **Standard MCP Server** | ✅ Basic Compatibility | ✅ Standard MCP | N/A | N/A |

### **Real-World Integration Examples**

#### **Enterprise Deployment**
```python
# Enterprise setup: Mix of legacy and secured systems
enterprise_client = ETDIClient({
    "security_level": "strict",           # Strict for financial tools
    "allow_non_etdi_tools": True,         # Allow legacy systems
    "oauth_config": enterprise_oauth      # Enterprise OAuth
})

# Connect to various systems
await enterprise_client.connect_to_server(["python", "-m", "legacy_crm"], "crm")
await enterprise_client.connect_to_server(["python", "-m", "secure_banking"], "banking")
await enterprise_client.connect_to_server(["node", "analytics-server.js"], "analytics")

# All tools available, security applied where possible
tools = await enterprise_client.discover_tools()
```

#### **Development Environment**
```python
# Development: Relaxed security for testing
dev_client = ETDIClient({
    "security_level": "basic",            # Relaxed for development
    "allow_non_etdi_tools": True,         # Allow all tools
    "show_unverified_tools": True         # Show everything
})

# Test against any MCP server
await dev_client.connect_to_server(["python", "-m", "test_server"], "test")
```

## Security Levels

### Basic
- Simple cryptographic verification
- No OAuth requirements
- Suitable for development and testing

### Enhanced (Recommended)
- OAuth 2.0 token verification
- Permission-based access control
- Tool change detection
- Suitable for production use

### Strict
- Full OAuth enforcement
- No unverified tools allowed
- Maximum security for sensitive environments

## Architecture

### Client-Side Components
- **ETDIClient**: Main client interface with security verification
- **ETDIVerifier**: OAuth token verification and change detection
- **ApprovalManager**: Encrypted storage of user approvals
- **ETDISecureClientSession**: Enhanced MCP client session

### Server-Side Components
- **ETDISecureServer**: OAuth-protected MCP server
- **OAuthSecurityMiddleware**: Security middleware for tool protection
- **TokenManager**: OAuth token lifecycle management

### OAuth Providers
- **Auth0Provider**: Auth0 integration
- **OktaProvider**: Okta integration  
- **AzureADProvider**: Azure AD integration
- **OAuthManager**: Multi-provider management

## Examples

See the `examples/etdi/` directory for comprehensive examples:

- `basic_usage.py`: Basic ETDI client usage
- `oauth_providers.py`: OAuth provider configurations
- `secure_server_example.py`: Secure server implementation

## Testing

Run the test suite:

```bash
pytest tests/etdi/
```

Run with coverage:

```bash
pytest tests/etdi/ --cov=src/mcp/etdi --cov-report=html
```

## Security Considerations

### Tool Verification
- Always verify tools before approval
- Monitor for version and permission changes
- Use appropriate security levels for your environment

### OAuth Configuration
- Store OAuth credentials securely
- Use appropriate scopes for your tools
- Implement proper token rotation

### Permission Management
- Follow principle of least privilege
- Regularly audit tool permissions
- Monitor approval and usage patterns

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Documentation

- [Core Documentation](docs/core/README.md)
- [Development Guide](docs/development/README.md)
- [Implementation Guide](docs/implementation/README.md)
- [API Reference](docs/development/api-reference.md)

## Support

- [GitHub Issues](https://github.com/modelcontextprotocol/python-sdk/issues)
- [Documentation](https://modelcontextprotocol.io/python)
- [Community Forum](https://community.modelcontextprotocol.io)
