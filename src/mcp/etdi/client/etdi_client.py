"""
Main ETDI client for secure tool discovery and invocation
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

from ..types import (
    ETDIToolDefinition, 
    ETDIClientConfig, 
    OAuthConfig,
    SecurityLevel,
    VerificationStatus,
    Permission
)
from ..exceptions import ETDIError, ConfigurationError, ToolNotFoundError
from ..oauth import OAuthManager, Auth0Provider, OktaProvider, AzureADProvider
from .verifier import ETDIVerifier
from .approval_manager import ApprovalManager

logger = logging.getLogger(__name__)


class ETDIClient:
    """
    Main ETDI client for secure tool operations
    """
    
    def __init__(self, config: Union[ETDIClientConfig, Dict[str, Any]]):
        """
        Initialize ETDI client
        
        Args:
            config: ETDI client configuration
        """
        if isinstance(config, dict):
            self.config = ETDIClientConfig(**config)
        else:
            self.config = config
        
        # Initialize components
        self.oauth_manager = OAuthManager()
        self.verifier: Optional[ETDIVerifier] = None
        self.approval_manager: Optional[ApprovalManager] = None
        self._initialized = False
        
        # Event callbacks
        self._event_callbacks: Dict[str, List[callable]] = {}
    
    async def initialize(self) -> None:
        """Initialize the ETDI client"""
        if self._initialized:
            return
        
        try:
            # Initialize OAuth providers
            await self._setup_oauth_providers()
            
            # Initialize verifier
            self.verifier = ETDIVerifier(
                self.oauth_manager,
                cache_ttl=self.config.verification_cache_ttl
            )
            
            # Initialize approval manager
            storage_config = self.config.storage_config or {}
            self.approval_manager = ApprovalManager(
                storage_path=storage_config.get("path"),
                encryption_key=storage_config.get("encryption_key")
            )
            
            # Initialize OAuth manager
            await self.oauth_manager.initialize_all()
            
            self._initialized = True
            logger.info("ETDI client initialized successfully")
            
        except Exception as e:
            raise ETDIError(f"Failed to initialize ETDI client: {e}")
    
    async def cleanup(self) -> None:
        """Cleanup resources"""
        if self.oauth_manager:
            await self.oauth_manager.cleanup_all()
        self._initialized = False
    
    async def __aenter__(self):
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()
    
    async def discover_tools(self, servers: Optional[List[Any]] = None) -> List[ETDIToolDefinition]:
        """
        Discover available tools from MCP servers
        
        Args:
            servers: List of MCP servers to query (if None, uses configured servers)
            
        Returns:
            List of discovered and verified tools
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # This would integrate with actual MCP client discovery
            # For now, return empty list as placeholder
            discovered_tools = []
            
            # TODO: Integrate with actual MCP client to discover tools
            # discovered_tools = await self._discover_from_mcp_servers(servers)
            
            # Verify discovered tools
            verified_tools = []
            for tool in discovered_tools:
                if self._should_include_tool(tool):
                    verification_result = await self.verifier.verify_tool(tool)
                    if verification_result.valid or self.config.show_unverified_tools:
                        verified_tools.append(tool)
            
            self._emit_event("tools_discovered", {"count": len(verified_tools)})
            return verified_tools
            
        except Exception as e:
            logger.error(f"Error discovering tools: {e}")
            raise ETDIError(f"Tool discovery failed: {e}")
    
    async def verify_tool(self, tool: ETDIToolDefinition) -> bool:
        """
        Verify a tool's security credentials
        
        Args:
            tool: Tool to verify
            
        Returns:
            True if tool is verified
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            result = await self.verifier.verify_tool(tool)
            
            if result.valid:
                self._emit_event("tool_verified", {"tool": tool})
            else:
                self._emit_event("tool_verification_failed", {
                    "tool": tool, 
                    "error": result.error
                })
            
            return result.valid
            
        except Exception as e:
            logger.error(f"Error verifying tool {tool.id}: {e}")
            return False
    
    async def approve_tool(self, tool: ETDIToolDefinition, permissions: Optional[List[Permission]] = None) -> None:
        """
        Approve a tool for usage
        
        Args:
            tool: Tool to approve
            permissions: Specific permissions to approve (defaults to all tool permissions)
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Verify tool before approval
            if not await self.verify_tool(tool):
                raise ETDIError(f"Cannot approve unverified tool: {tool.id}")
            
            # Create approval record
            await self.approval_manager.approve_tool_with_etdi(tool, permissions)
            
            self._emit_event("tool_approved", {"tool": tool, "permissions": permissions})
            logger.info(f"Tool {tool.id} approved successfully")
            
        except Exception as e:
            logger.error(f"Error approving tool {tool.id}: {e}")
            raise ETDIError(f"Tool approval failed: {e}")
    
    async def is_tool_approved(self, tool_id: str) -> bool:
        """
        Check if a tool is approved
        
        Args:
            tool_id: Tool identifier
            
        Returns:
            True if tool is approved
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            return await self.approval_manager.is_tool_approved(tool_id)
        except Exception as e:
            logger.error(f"Error checking approval for tool {tool_id}: {e}")
            return False
    
    async def invoke_tool(self, tool_id: str, params: Any) -> Any:
        """
        Invoke a tool with parameters
        
        Args:
            tool_id: Tool identifier
            params: Tool parameters
            
        Returns:
            Tool execution result
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # TODO: Get tool definition from discovered tools
            # For now, raise error as placeholder
            raise ToolNotFoundError(f"Tool {tool_id} not found", tool_id=tool_id)
            
            # This would be the actual implementation:
            # tool = await self._get_tool_definition(tool_id)
            # 
            # # Check if tool can be invoked
            # approval = await self.approval_manager.get_approval(tool_id)
            # check_result = await self.verifier.check_tool_before_invocation(tool, approval.to_dict() if approval else None)
            # 
            # if not check_result.can_proceed:
            #     if check_result.requires_reapproval:
            #         raise ETDIError(f"Tool {tool_id} requires re-approval: {check_result.reason}")
            #     else:
            #         raise ETDIError(f"Tool {tool_id} cannot be invoked: {check_result.reason}")
            # 
            # # Invoke tool through MCP
            # result = await self._invoke_mcp_tool(tool_id, params)
            # 
            # self._emit_event("tool_invoked", {"tool_id": tool_id, "params": params})
            # return result
            
        except Exception as e:
            logger.error(f"Error invoking tool {tool_id}: {e}")
            if isinstance(e, ETDIError):
                raise
            raise ETDIError(f"Tool invocation failed: {e}")
    
    async def check_version_change(self, tool_id: str) -> bool:
        """
        Check if a tool's version has changed since approval
        
        Args:
            tool_id: Tool identifier
            
        Returns:
            True if version has changed
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # TODO: Get current tool definition
            # For now, return False as placeholder
            return False
            
            # This would be the actual implementation:
            # tool = await self._get_tool_definition(tool_id)
            # changes = await self.approval_manager.check_for_changes(tool)
            # return changes.get("changes_detected", False)
            
        except Exception as e:
            logger.error(f"Error checking version change for tool {tool_id}: {e}")
            return False
    
    async def request_reapproval(self, tool_id: str) -> None:
        """
        Request re-approval for a tool
        
        Args:
            tool_id: Tool identifier
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Remove existing approval to force re-approval
            await self.approval_manager.remove_approval(tool_id)
            
            self._emit_event("reapproval_requested", {"tool_id": tool_id})
            logger.info(f"Re-approval requested for tool {tool_id}")
            
        except Exception as e:
            logger.error(f"Error requesting re-approval for tool {tool_id}: {e}")
            raise ETDIError(f"Re-approval request failed: {e}")
    
    async def check_permission(self, tool_id: str, permission: str) -> bool:
        """
        Check if a tool has a specific permission
        
        Args:
            tool_id: Tool identifier
            permission: Permission to check
            
        Returns:
            True if tool has the permission
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            approval = await self.approval_manager.get_approval(tool_id)
            if not approval:
                return False
            
            return any(p.scope == permission for p in approval.permissions)
            
        except Exception as e:
            logger.error(f"Error checking permission {permission} for tool {tool_id}: {e}")
            return False
    
    def on(self, event: str, callback: callable) -> None:
        """
        Register event callback
        
        Args:
            event: Event name
            callback: Callback function
        """
        if event not in self._event_callbacks:
            self._event_callbacks[event] = []
        self._event_callbacks[event].append(callback)
    
    def off(self, event: str, callback: callable) -> None:
        """
        Remove event callback
        
        Args:
            event: Event name
            callback: Callback function to remove
        """
        if event in self._event_callbacks:
            try:
                self._event_callbacks[event].remove(callback)
            except ValueError:
                pass
    
    def _emit_event(self, event: str, data: Dict[str, Any]) -> None:
        """Emit event to registered callbacks"""
        if event in self._event_callbacks:
            for callback in self._event_callbacks[event]:
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"Error in event callback for {event}: {e}")
    
    async def _setup_oauth_providers(self) -> None:
        """Setup OAuth providers from configuration"""
        if not self.config.oauth_config:
            if self.config.security_level in [SecurityLevel.ENHANCED, SecurityLevel.STRICT]:
                raise ConfigurationError("OAuth configuration required for enhanced/strict security levels")
            return
        
        oauth_config = OAuthConfig.from_dict(self.config.oauth_config)
        
        # Create provider based on type
        if oauth_config.provider.lower() == "auth0":
            provider = Auth0Provider(oauth_config)
        elif oauth_config.provider.lower() == "okta":
            provider = OktaProvider(oauth_config)
        elif oauth_config.provider.lower() in ["azure", "azuread", "azure_ad"]:
            provider = AzureADProvider(oauth_config)
        else:
            raise ConfigurationError(f"Unsupported OAuth provider: {oauth_config.provider}")
        
        self.oauth_manager.register_provider(oauth_config.provider, provider)
    
    def _should_include_tool(self, tool: ETDIToolDefinition) -> bool:
        """Check if tool should be included based on security settings"""
        if tool.verification_status == VerificationStatus.VERIFIED:
            return True
        
        if self.config.security_level == SecurityLevel.STRICT:
            return False
        
        if not self.config.allow_non_etdi_tools and not tool.security:
            return False
        
        return True
    
    async def get_stats(self) -> Dict[str, Any]:
        """
        Get ETDI client statistics
        
        Returns:
            Dictionary with client statistics
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            verification_stats = await self.verifier.get_verification_stats()
            storage_stats = await self.approval_manager.get_storage_stats()
            
            return {
                "initialized": self._initialized,
                "security_level": self.config.security_level.value,
                "oauth_providers": self.oauth_manager.list_providers(),
                "verification": verification_stats,
                "storage": storage_stats,
                "config": {
                    "allow_non_etdi_tools": self.config.allow_non_etdi_tools,
                    "show_unverified_tools": self.config.show_unverified_tools,
                    "verification_cache_ttl": self.config.verification_cache_ttl
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {"error": str(e)}