---
title: Authentication
weight: 1
---

# Authentication

ETDI provides comprehensive authentication mechanisms to verify user and system identities before granting access to AI tools.

## Supported Authentication Methods

### 1. OAuth 2.0 / OpenID Connect

The most common authentication method for modern applications:

```python
from mcp.etdi.auth import OAuthHandler

# Configure OAuth provider
oauth_handler = OAuthHandler(
    provider="auth0",
    domain="your-domain.auth0.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    scopes=["openid", "profile", "email", "tools:execute"]
)

server.add_auth_handler(oauth_handler)
```

### 2. SAML 2.0 (Enterprise SSO)

For enterprise environments with existing SAML infrastructure:

```python
from mcp.etdi.auth import SAMLHandler

saml_handler = SAMLHandler(
    entity_id="your-entity-id",
    sso_url="https://your-idp.com/sso",
    x509_cert="path/to/certificate.pem",
    attribute_mapping={
        "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "roles": "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    }
)

server.add_auth_handler(saml_handler)
```

### 3. Multi-Factor Authentication (MFA)

Enhanced security with multiple authentication factors:

```python
from mcp.etdi.auth import MFAHandler

mfa_handler = MFAHandler(
    primary_method="oauth",
    secondary_methods=["totp", "sms", "hardware_key"],
    require_mfa_for_sensitive_tools=True,
    mfa_timeout="10m"
)

server.add_auth_handler(mfa_handler)
```

### 4. API Key Authentication

For programmatic access and service-to-service communication:

```python
from mcp.etdi.auth import APIKeyHandler

api_key_handler = APIKeyHandler(
    key_storage="database",  # or "file", "vault"
    require_key_rotation=True,
    key_expiration="90d",
    rate_limiting=True
)

server.add_auth_handler(api_key_handler)
```

## Auth0 Integration Example

Complete Auth0 setup for ETDI:

```python
import os
from mcp.etdi import SecureServer
from mcp.etdi.auth import OAuthHandler

# Configure Auth0 authentication
auth0_handler = OAuthHandler(
    provider="auth0",
    domain=os.getenv("AUTH0_DOMAIN"),
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    callback_url="http://localhost:8000/auth/callback",
    scopes=["openid", "profile", "email", "tools:read", "tools:execute"]
)

# Create secure server
server = SecureServer(
    name="authenticated-server",
    require_authentication=True
)

server.add_auth_handler(auth0_handler)

# Protect tools with authentication
@server.tool("secure_data_access", require_auth=True)
async def secure_data_access(query: str) -> dict:
    """Access sensitive data with authentication required."""
    user = server.get_current_user()
    
    if not user.has_permission("data:read"):
        raise PermissionError("Insufficient permissions")
    
    return await fetch_secure_data(query, user.id)
```

## Custom Authentication Provider

Create custom authentication for specialized requirements:

```python
from mcp.etdi.auth import BaseAuthHandler
from typing import Optional

class CustomAuthHandler(BaseAuthHandler):
    """Custom authentication handler."""
    
    async def authenticate(self, credentials: dict) -> Optional[dict]:
        """Authenticate user with custom logic."""
        username = credentials.get("username")
        token = credentials.get("token")
        
        # Custom authentication logic
        if await self.validate_custom_token(username, token):
            return {
                "user_id": username,
                "permissions": await self.get_user_permissions(username),
                "session_expires": time.time() + 3600
            }
        
        return None
    
    async def validate_custom_token(self, username: str, token: str) -> bool:
        """Validate custom authentication token."""
        # Implementation specific logic
        return await external_auth_service.validate(username, token)
    
    async def get_user_permissions(self, username: str) -> list:
        """Get user permissions from custom system."""
        return await permission_service.get_permissions(username)

# Use custom handler
custom_handler = CustomAuthHandler()
server.add_auth_handler(custom_handler)
```

## Session Management

ETDI provides secure session management:

```python
from mcp.etdi.auth import SessionManager

session_manager = SessionManager(
    session_timeout="1h",
    rolling_session=True,
    secure_cookies=True,
    session_storage="redis",  # or "memory", "database"
    csrf_protection=True
)

server.set_session_manager(session_manager)

# Session events
@server.on_session_created
async def handle_session_created(session_id: str, user_id: str):
    logger.info(f"Session created for user {user_id}: {session_id}")

@server.on_session_expired
async def handle_session_expired(session_id: str, user_id: str):
    logger.info(f"Session expired for user {user_id}: {session_id}")
    await cleanup_user_resources(user_id)
```

## Environment Configuration

Set up authentication with environment variables:

```bash
# .env file
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret

# SAML configuration
SAML_ENTITY_ID=your-entity-id
SAML_SSO_URL=https://your-idp.com/sso
SAML_CERT_PATH=/path/to/certificate.pem

# Session configuration
SESSION_SECRET=your-session-secret
SESSION_TIMEOUT=3600
REDIS_URL=redis://localhost:6379
```

## Security Best Practices

1. **Use HTTPS everywhere** - Never transmit credentials over HTTP
2. **Implement proper session management** - Use secure, httpOnly cookies
3. **Enable CSRF protection** - Prevent cross-site request forgery
4. **Rotate secrets regularly** - Implement automatic secret rotation
5. **Monitor authentication events** - Log all authentication attempts
6. **Use strong session timeouts** - Balance security with usability

## Testing Authentication

Test your authentication setup:

```python
# test_authentication.py
import pytest
from mcp.etdi.test import AuthTestClient

async def test_oauth_authentication():
    """Test OAuth authentication flow."""
    client = AuthTestClient(server)
    
    # Test unauthenticated access (should fail)
    with pytest.raises(AuthenticationError):
        await client.call_tool("secure_tool", {})
    
    # Test authentication flow
    auth_result = await client.authenticate_oauth({
        "username": "test@example.com",
        "password": "test-password"
    })
    
    assert auth_result["authenticated"] is True
    assert auth_result["user_id"] == "test@example.com"
    
    # Test authenticated access (should succeed)
    result = await client.call_tool("secure_tool", {})
    assert result["status"] == "success"

async def test_session_expiry():
    """Test session expiration handling."""
    client = AuthTestClient(server)
    
    # Authenticate
    await client.authenticate_oauth(test_credentials)
    
    # Fast-forward time to expire session
    await client.advance_time(hours=2)
    
    # Tool call should fail due to expired session
    with pytest.raises(SessionExpiredError):
        await client.call_tool("secure_tool", {})
```

This comprehensive authentication system ensures that only authorized users can access your AI tools and provides the flexibility to integrate with existing enterprise authentication infrastructure. 