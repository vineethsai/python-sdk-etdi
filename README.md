# Model Context Protocol Python SDK with ETDI Security

A Python implementation of the Model Context Protocol (MCP) with Enhanced Tool Definition Interface (ETDI) security extensions.

## Overview

This SDK provides a secure implementation of MCP with OAuth 2.0-based security enhancements to prevent Tool Poisoning and Rug Pull attacks. ETDI adds cryptographic verification, immutable versioned definitions, and explicit permission management to the MCP ecosystem.

## Features

### Core MCP Functionality
- **Client/Server Architecture**: Full MCP client and server implementations
- **Tool Management**: Register, discover, and invoke tools
- **Resource Access**: Secure access to external resources
- **Prompt Templates**: Reusable prompt templates for LLM interactions

### ETDI Security Enhancements
- **OAuth 2.0 Integration**: Support for Auth0, Okta, and Azure AD
- **Tool Verification**: Cryptographic verification of tool authenticity
- **Permission Management**: Fine-grained permission control with OAuth scopes
- **Version Control**: Automatic detection of tool changes requiring re-approval
- **Approval Management**: Encrypted storage of user tool approvals

### Security Features
- **Tool Poisoning Prevention**: Cryptographic verification prevents malicious tool impersonation
- **Rug Pull Protection**: Version and permission change detection prevents unauthorized modifications
- **Multiple Security Levels**: Basic, Enhanced, and Strict security modes
- **Audit Logging**: Comprehensive security event logging

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
