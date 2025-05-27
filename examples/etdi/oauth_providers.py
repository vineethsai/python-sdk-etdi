"""
Example demonstrating different OAuth provider configurations for ETDI
"""

import asyncio
import logging
from mcp.etdi import ETDIClient, OAuthConfig

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def demo_auth0_provider():
    """Demonstrate Auth0 OAuth provider"""
    print("\n🔐 Auth0 Provider Demo")
    print("=" * 50)
    
    oauth_config = OAuthConfig(
        provider="auth0",
        client_id="your-auth0-client-id",
        client_secret="your-auth0-client-secret", 
        domain="your-domain.auth0.com",
        audience="https://your-api.example.com",
        scopes=["read:tools", "execute:tools", "manage:tools"]
    )
    
    async with ETDIClient({
        "security_level": "enhanced",
        "oauth_config": oauth_config.to_dict()
    }) as client:
        stats = await client.get_stats()
        print(f"✅ Auth0 client initialized")
        print(f"📊 OAuth providers: {stats.get('oauth_providers', [])}")


async def demo_okta_provider():
    """Demonstrate Okta OAuth provider"""
    print("\n🔐 Okta Provider Demo")
    print("=" * 50)
    
    oauth_config = OAuthConfig(
        provider="okta",
        client_id="your-okta-client-id",
        client_secret="your-okta-client-secret",
        domain="your-domain.okta.com",
        scopes=["etdi.tools.read", "etdi.tools.execute"]
    )
    
    async with ETDIClient({
        "security_level": "enhanced", 
        "oauth_config": oauth_config.to_dict()
    }) as client:
        stats = await client.get_stats()
        print(f"✅ Okta client initialized")
        print(f"📊 OAuth providers: {stats.get('oauth_providers', [])}")


async def demo_azure_ad_provider():
    """Demonstrate Azure AD OAuth provider"""
    print("\n🔐 Azure AD Provider Demo")
    print("=" * 50)
    
    oauth_config = OAuthConfig(
        provider="azure",
        client_id="your-azure-client-id",
        client_secret="your-azure-client-secret",
        domain="your-tenant-id",  # Can be tenant ID or domain
        scopes=["https://graph.microsoft.com/.default", "api://your-app-id/etdi.tools"]
    )
    
    async with ETDIClient({
        "security_level": "enhanced",
        "oauth_config": oauth_config.to_dict()
    }) as client:
        stats = await client.get_stats()
        print(f"✅ Azure AD client initialized")
        print(f"📊 OAuth providers: {stats.get('oauth_providers', [])}")


async def demo_security_levels():
    """Demonstrate different security levels"""
    print("\n🔒 Security Levels Demo")
    print("=" * 50)
    
    oauth_config = OAuthConfig(
        provider="auth0",
        client_id="demo-client-id",
        client_secret="demo-client-secret",
        domain="demo.auth0.com"
    )
    
    # Basic security level
    print("\n📊 Basic Security Level:")
    async with ETDIClient({
        "security_level": "basic",
        "allow_non_etdi_tools": True,
        "show_unverified_tools": True
    }) as client:
        stats = await client.get_stats()
        print(f"  Security level: {stats.get('config', {}).get('security_level')}")
        print(f"  Allow non-ETDI tools: {stats.get('config', {}).get('allow_non_etdi_tools')}")
    
    # Enhanced security level
    print("\n🔒 Enhanced Security Level:")
    async with ETDIClient({
        "security_level": "enhanced",
        "oauth_config": oauth_config.to_dict(),
        "allow_non_etdi_tools": False,
        "show_unverified_tools": False
    }) as client:
        stats = await client.get_stats()
        print(f"  Security level: {stats.get('config', {}).get('security_level')}")
        print(f"  OAuth providers: {stats.get('oauth_providers', [])}")
        print(f"  Allow non-ETDI tools: {stats.get('config', {}).get('allow_non_etdi_tools')}")
    
    # Strict security level
    print("\n🛡️ Strict Security Level:")
    async with ETDIClient({
        "security_level": "strict",
        "oauth_config": oauth_config.to_dict(),
        "allow_non_etdi_tools": False,
        "show_unverified_tools": False,
        "verification_cache_ttl": 60  # Shorter cache for strict mode
    }) as client:
        stats = await client.get_stats()
        print(f"  Security level: {stats.get('config', {}).get('security_level')}")
        print(f"  Cache TTL: {stats.get('config', {}).get('verification_cache_ttl')}s")


async def demo_oauth_token_operations():
    """Demonstrate OAuth token operations"""
    print("\n🎫 OAuth Token Operations Demo")
    print("=" * 50)
    
    from mcp.etdi.oauth import OAuthManager, Auth0Provider
    from mcp.etdi.types import ETDIToolDefinition, Permission
    
    # Create OAuth configuration
    oauth_config = OAuthConfig(
        provider="auth0",
        client_id="demo-client-id",
        client_secret="demo-client-secret",
        domain="demo.auth0.com",
        audience="https://demo-api.example.com"
    )
    
    # Create OAuth manager
    oauth_manager = OAuthManager()
    auth0_provider = Auth0Provider(oauth_config)
    oauth_manager.register_provider("auth0", auth0_provider)
    
    print(f"✅ OAuth manager created with providers: {oauth_manager.list_providers()}")
    
    # Create example tool definition
    tool = ETDIToolDefinition(
        id="demo-tool",
        name="Demo Tool",
        version="1.0.0",
        description="A demonstration tool",
        provider={"id": "demo-provider", "name": "Demo Provider"},
        schema={"type": "object"},
        permissions=[
            Permission(
                name="read_data",
                description="Read data from the system",
                scope="read:data",
                required=True
            ),
            Permission(
                name="write_data", 
                description="Write data to the system",
                scope="write:data",
                required=False
            )
        ]
    )
    
    print(f"📋 Created demo tool: {tool.name}")
    print(f"🔑 Tool permissions: {[p.name for p in tool.permissions]}")
    print(f"🎯 Required scopes: {tool.get_permission_scopes()}")
    
    # Note: Actual token operations would require valid OAuth credentials
    print("\n⚠️ Note: Actual token operations require valid OAuth provider credentials")


async def main():
    """Run all OAuth provider demos"""
    print("🚀 ETDI OAuth Providers Demo")
    print("=" * 60)
    
    try:
        # Demo different providers (will fail without real credentials)
        await demo_auth0_provider()
        await demo_okta_provider() 
        await demo_azure_ad_provider()
        
        # Demo security levels
        await demo_security_levels()
        
        # Demo token operations
        await demo_oauth_token_operations()
        
        print("\n✅ All demos completed successfully!")
        print("\n💡 To use with real OAuth providers:")
        print("   1. Replace demo credentials with real ones")
        print("   2. Configure OAuth provider applications")
        print("   3. Set appropriate scopes and audiences")
        print("   4. Test with actual MCP servers")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        print("This is expected when running without real OAuth credentials")


if __name__ == "__main__":
    asyncio.run(main())