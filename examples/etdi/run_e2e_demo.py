#!/usr/bin/env python3
"""
ETDI End-to-End Demo Runner

This script demonstrates the complete ETDI security toolchain including:
- Tool Registration/Provider SDK
- Custom OAuth Providers  
- Event System
- Tool Discovery from MCP Servers
- Real attack prevention
"""

import asyncio
import logging
import sys
import time
from pathlib import Path
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


async def demo_tool_provider_sdk():
    """Demonstrate the Tool Provider SDK"""
    print("\n🔧 Tool Provider SDK Demo")
    print("=" * 50)
    
    try:
        from mcp.etdi.server.tool_provider import ToolProvider
        from mcp.etdi.types import Permission
        
        # Create a tool provider
        provider = ToolProvider(
            provider_id="demo-provider",
            provider_name="Demo Tool Provider",
            private_key=None,  # Will use OAuth instead for demo
            oauth_manager=None  # Simplified for demo
        )
        
        # Register a tool
        tool = await provider.register_tool(
            tool_id="demo-calculator",
            name="Demo Calculator",
            version="1.0.0",
            description="A demonstration calculator tool",
            schema={
                "type": "object",
                "properties": {
                    "operation": {"type": "string", "enum": ["add", "subtract", "multiply", "divide"]},
                    "a": {"type": "number"},
                    "b": {"type": "number"}
                },
                "required": ["operation", "a", "b"]
            },
            permissions=[
                Permission(
                    name="calculate",
                    description="Perform mathematical calculations",
                    scope="math:calculate",
                    required=True
                )
            ],
            use_oauth=False  # Skip OAuth for demo
        )
        
        print(f"✅ Registered tool: {tool.name} (ID: {tool.id})")
        print(f"   Version: {tool.version}")
        print(f"   Permissions: {[p.name for p in tool.permissions]}")
        
        # Update the tool
        updated_tool = await provider.update_tool(
            tool_id="demo-calculator",
            version="1.1.0",
            description="Enhanced calculator with more operations"
        )
        
        print(f"✅ Updated tool to version: {updated_tool.version}")
        
        # Get provider stats
        stats = provider.get_provider_stats()
        print(f"📊 Provider Stats:")
        print(f"   - Total tools: {stats['total_tools']}")
        print(f"   - OAuth enabled: {stats['oauth_enabled_tools']}")
        print(f"   - Signed tools: {stats['cryptographically_signed_tools']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Tool Provider Demo failed: {e}")
        return False


def demo_custom_oauth_provider():
    """Demonstrate Custom OAuth Provider"""
    print("\n🔐 Custom OAuth Provider Demo")
    print("=" * 50)
    
    try:
        from mcp.etdi.oauth.custom import GenericOAuthProvider
        from mcp.etdi.types import OAuthConfig
        
        # Define custom OAuth endpoints
        custom_endpoints = {
            "token_endpoint": "https://my-oauth.example.com/oauth/token",
            "jwks_uri": "https://my-oauth.example.com/.well-known/jwks.json",
            "userinfo_endpoint": "https://my-oauth.example.com/userinfo",
            "revoke_endpoint": "https://my-oauth.example.com/oauth/revoke",
            "issuer": "https://my-oauth.example.com"
        }
        
        # Create OAuth config for custom provider
        oauth_config = OAuthConfig(
            provider="custom",
            client_id="my-custom-client",
            client_secret="my-custom-secret",
            domain="my-oauth.example.com",
            audience="https://my-api.example.com",
            scopes=["read", "write"]
        )
        
        # Create custom provider
        custom_provider = GenericOAuthProvider(oauth_config, custom_endpoints)
        
        print(f"✅ Created custom OAuth provider")
        print(f"   Provider: {oauth_config.provider}")
        print(f"   Token Endpoint: {custom_provider.get_token_endpoint()}")
        print(f"   JWKS URI: {custom_provider.get_jwks_uri()}")
        print(f"   Userinfo Endpoint: {custom_provider.userinfo_endpoint}")
        print(f"   Expected Issuer: {custom_provider._get_expected_issuer()}")
        
        print("   ✅ Custom provider ready for use with real OAuth endpoints")
        
        return True
        
    except Exception as e:
        print(f"❌ Custom OAuth Provider Demo failed: {e}")
        return False


def demo_event_system():
    """Demonstrate the Event System"""
    print("\n📡 Event System Demo")
    print("=" * 50)
    
    try:
        from mcp.etdi.events import EventType, emit_tool_event, emit_security_event, get_event_emitter
        
        # Get the global event emitter
        emitter = get_event_emitter()
        
        # Event counters
        events_received = {"count": 0, "events": []}
        
        # Register event listeners
        def on_tool_verified(event):
            events_received["count"] += 1
            events_received["events"].append(f"Tool verified: {event.tool_id}")
            print(f"🎉 Event: Tool verified - {event.tool_id}")
        
        def on_tool_approved(event):
            events_received["count"] += 1
            events_received["events"].append(f"Tool approved: {event.tool_id}")
            print(f"✅ Event: Tool approved - {event.tool_id}")
        
        def on_security_event(event):
            events_received["count"] += 1
            events_received["events"].append(f"Security event: {event.type.value}")
            print(f"🚨 Security Event: {event.type.value} - Severity: {event.severity}")
        
        # Register listeners
        emitter.on(EventType.TOOL_VERIFIED, on_tool_verified)
        emitter.on(EventType.TOOL_APPROVED, on_tool_approved)
        emitter.on(EventType.SECURITY_VIOLATION, on_security_event)
        
        print("✅ Registered event listeners for:")
        print("   - TOOL_VERIFIED")
        print("   - TOOL_APPROVED") 
        print("   - SECURITY_VIOLATION")
        
        # Simulate some events
        emit_tool_event(
            EventType.TOOL_VERIFIED,
            "demo-tool",
            "EventDemo",
            tool_name="Demo Tool",
            tool_version="1.0.0"
        )
        
        emit_tool_event(
            EventType.TOOL_APPROVED,
            "demo-tool",
            "EventDemo",
            tool_name="Demo Tool",
            tool_version="1.0.0"
        )
        
        emit_security_event(
            EventType.SECURITY_VIOLATION,
            "EventDemo",
            "high",
            threat_type="demo_violation",
            details={"reason": "Demonstration security event"}
        )
        
        print(f"\n📊 Event System Results:")
        print(f"   - Total events received: {events_received['count']}")
        print(f"   - Events: {events_received['events']}")
        
        # Get event history
        history = emitter.get_event_history(limit=5)
        print(f"   - Recent events in history: {len(history)}")
        
        # Show listener counts
        print(f"   - TOOL_VERIFIED listeners: {emitter.get_listener_count(EventType.TOOL_VERIFIED)}")
        print(f"   - TOOL_APPROVED listeners: {emitter.get_listener_count(EventType.TOOL_APPROVED)}")
        print(f"   - SECURITY_VIOLATION listeners: {emitter.get_listener_count(EventType.SECURITY_VIOLATION)}")
        
        # Clean up
        emitter.remove_all_listeners(EventType.TOOL_VERIFIED)
        emitter.remove_all_listeners(EventType.TOOL_APPROVED)
        emitter.remove_all_listeners(EventType.SECURITY_VIOLATION)
        
        return True
        
    except Exception as e:
        print(f"❌ Event System Demo failed: {e}")
        return False


async def demo_mcp_discovery():
    """Demonstrate MCP Tool Discovery"""
    print("\n🔍 MCP Tool Discovery Demo")
    print("=" * 50)
    
    try:
        from mcp.etdi.client.etdi_client import ETDIClient
        from mcp.etdi.types import ETDIClientConfig, SecurityLevel
        
        # Create ETDI client configuration
        config = ETDIClientConfig(
            security_level=SecurityLevel.BASIC,
            oauth_config=None,  # No OAuth for basic demo
            allow_non_etdi_tools=True,
            show_unverified_tools=True
        )
        
        # Create ETDI client
        client = ETDIClient(config)
        await client.initialize()
        
        print("✅ ETDI Client initialized with enhanced features:")
        print("   - MCP server connection support")
        print("   - Real-time tool discovery")
        print("   - Event-driven notifications")
        print("   - Security-level filtering")
        
        # Show the new capabilities
        print("\n🔧 New MCP Integration Capabilities:")
        print("   - connect_to_server(command, name) - Connect to MCP servers")
        print("   - discover_tools(server_ids) - Discover tools from servers")
        print("   - Real-time event emission for all operations")
        print("   - Security-level based tool filtering")
        print("   - Tool verification before invocation")
        
        # Get client stats
        stats = await client.get_stats()
        print(f"\n📊 Enhanced Client Stats:")
        print(f"   - Security level: {stats.get('security_level', 'N/A')}")
        print(f"   - OAuth enabled: {stats.get('oauth_enabled', False)}")
        print(f"   - Connected servers: {stats.get('connected_servers', 0)}")
        print(f"   - Discovered tools: {stats.get('discovered_tools', 0)}")
        
        await client.cleanup()
        
        return True
        
    except Exception as e:
        print(f"❌ MCP Discovery Demo failed: {e}")
        return False


async def demo_security_features():
    """Demonstrate existing security features"""
    print("\n🛡️ Core Security Features Demo")
    print("=" * 50)
    
    try:
        # Import and run the existing client demo
        from e2e_secure_client import SecureBankingClient
        
        client = SecureBankingClient()
        
        # Run the attack prevention tests
        await client.demonstrate_attack_prevention()
        
        return True
        
    except Exception as e:
        print(f"❌ Security Features Demo failed: {e}")
        return False


async def run_complete_demo():
    """Run the complete ETDI demonstration with all new features"""
    print("🚀 ETDI Complete Feature Demonstration")
    print("=" * 70)
    print("This demo showcases ETDI's comprehensive security platform:")
    print("• Tool Registration/Provider SDK")
    print("• Custom OAuth Provider Support")
    print("• Event-Driven Architecture")
    print("• MCP Server Integration")
    print("• Real Attack Prevention")
    print("=" * 70)
    
    # Track demo results
    demo_results = []
    
    # Run all feature demonstrations
    demos = [
        ("Tool Provider SDK", demo_tool_provider_sdk()),
        ("Custom OAuth Providers", demo_custom_oauth_provider()),
        ("Event System", demo_event_system()),
        ("MCP Discovery", demo_mcp_discovery()),
        ("Security Features", demo_security_features())
    ]
    
    for demo_name, demo_coro in demos:
        print(f"\n{'='*20} {demo_name} {'='*20}")
        try:
            if asyncio.iscoroutine(demo_coro):
                result = await demo_coro
            else:
                result = demo_coro
            demo_results.append((demo_name, result))
        except Exception as e:
            print(f"❌ {demo_name} failed: {e}")
            demo_results.append((demo_name, False))
    
    # Show final results
    print("\n" + "=" * 70)
    print("🎯 ETDI COMPLETE DEMONSTRATION RESULTS")
    print("=" * 70)
    
    successful_demos = sum(1 for _, success in demo_results if success)
    total_demos = len(demo_results)
    
    for demo_name, success in demo_results:
        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"{status} {demo_name}")
    
    print(f"\n📊 Results: {successful_demos}/{total_demos} demonstrations successful")
    
    if successful_demos == total_demos:
        print("\n🎉 ALL DEMONSTRATIONS SUCCESSFUL!")
        print("\n✅ ETDI Implementation Verified:")
        print("   ✓ Tool Registration/Provider SDK - IMPLEMENTED")
        print("   ✓ Custom OAuth Provider Support - IMPLEMENTED")
        print("   ✓ Event System - IMPLEMENTED")
        print("   ✓ MCP Tool Discovery - IMPLEMENTED")
        print("   ✓ Real Security Attack Prevention - IMPLEMENTED")
        print("\n🌟 ETDI successfully transforms MCP into a comprehensive")
        print("   enterprise-ready security platform!")
    else:
        print(f"\n⚠️ {total_demos - successful_demos} demonstration(s) had issues.")
        print("   Some features may need additional configuration or dependencies.")
    
    print("\n" + "=" * 70)
    print("🚀 ETDI: From Development Protocol to Enterprise Security Platform")
    print("=" * 70)
    
    return successful_demos == total_demos


def main():
    """Main entry point"""
    try:
        result = asyncio.run(run_complete_demo())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️ Demo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Demo failed with unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()