"""
ETDI-enhanced MCP client session with security verification
"""

import logging
from typing import Any, Dict, List, Optional
from mcp.client.session import ClientSession
from mcp.types import Tool, CallToolRequest, CallToolResult

from ..types import ETDIToolDefinition, VerificationStatus
from ..exceptions import ETDIError, PermissionError
from .verifier import ETDIVerifier
from .approval_manager import ApprovalManager

logger = logging.getLogger(__name__)


class ETDISecureClientSession(ClientSession):
    """
    Enhanced MCP client session with ETDI security verification
    """
    
    def __init__(
        self,
        verifier: ETDIVerifier,
        approval_manager: ApprovalManager,
        **kwargs
    ):
        """
        Initialize secure client session
        
        Args:
            verifier: ETDI tool verifier
            approval_manager: Tool approval manager
            **kwargs: Additional arguments for base ClientSession
        """
        super().__init__(**kwargs)
        self.verifier = verifier
        self.approval_manager = approval_manager
        self._etdi_tools: Dict[str, ETDIToolDefinition] = {}
    
    async def list_tools(self) -> List[ETDIToolDefinition]:
        """
        List tools with ETDI security verification
        
        Returns:
            List of verified ETDI tool definitions
        """
        try:
            # Get standard MCP tools
            standard_tools = await super().list_tools()
            
            # Convert to ETDI tools and verify
            etdi_tools = []
            for tool in standard_tools.tools:
                etdi_tool = self._convert_to_etdi_tool(tool)
                
                # Verify the tool
                verification_result = await self.verifier.verify_tool(etdi_tool)
                if verification_result.valid:
                    etdi_tool.verification_status = VerificationStatus.VERIFIED
                else:
                    etdi_tool.verification_status = VerificationStatus.TOKEN_INVALID
                
                etdi_tools.append(etdi_tool)
                self._etdi_tools[etdi_tool.id] = etdi_tool
            
            logger.info(f"Listed {len(etdi_tools)} tools, {sum(1 for t in etdi_tools if t.verification_status == VerificationStatus.VERIFIED)} verified")
            return etdi_tools
            
        except Exception as e:
            logger.error(f"Error listing tools: {e}")
            raise ETDIError(f"Tool listing failed: {e}")
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """
        Call a tool with ETDI security checks
        
        Args:
            name: Tool name
            arguments: Tool arguments
            
        Returns:
            Tool execution result
            
        Raises:
            ETDIError: If security checks fail
            PermissionError: If tool lacks required permissions
        """
        try:
            # Get tool definition
            etdi_tool = self._etdi_tools.get(name)
            if not etdi_tool:
                # Try to refresh tool list
                await self.list_tools()
                etdi_tool = self._etdi_tools.get(name)
                
                if not etdi_tool:
                    raise ETDIError(f"Tool not found: {name}")
            
            # Check if tool is approved
            approval = await self.approval_manager.get_approval(etdi_tool.id)
            
            # Perform pre-invocation security check
            check_result = await self.verifier.check_tool_before_invocation(
                etdi_tool,
                approval.to_dict() if approval else None
            )
            
            if not check_result.can_proceed:
                if check_result.requires_reapproval:
                    raise PermissionError(
                        f"Tool {name} requires re-approval: {check_result.reason}",
                        tool_id=name
                    )
                else:
                    raise ETDIError(f"Tool {name} cannot be invoked: {check_result.reason}")
            
            # Call the tool using standard MCP
            request = CallToolRequest(name=name, arguments=arguments)
            result = await super().call_tool(request)
            
            logger.info(f"Successfully called tool {name}")
            return result
            
        except Exception as e:
            logger.error(f"Error calling tool {name}: {e}")
            if isinstance(e, (ETDIError, PermissionError)):
                raise
            raise ETDIError(f"Tool invocation failed: {e}")
    
    def _convert_to_etdi_tool(self, tool: Tool) -> ETDIToolDefinition:
        """
        Convert standard MCP tool to ETDI tool definition
        
        Args:
            tool: Standard MCP tool
            
        Returns:
            ETDI tool definition
        """
        # Extract ETDI security information if present
        security_info = None
        if hasattr(tool, 'security') and tool.security:
            from ..types import SecurityInfo, OAuthInfo
            oauth_data = getattr(tool.security, 'oauth', None)
            if oauth_data:
                security_info = SecurityInfo(
                    oauth=OAuthInfo(
                        token=getattr(oauth_data, 'token', ''),
                        provider=getattr(oauth_data, 'provider', '')
                    )
                )
        
        # Extract permissions if present
        permissions = []
        if hasattr(tool, 'permissions') and tool.permissions:
            from ..types import Permission
            for perm in tool.permissions:
                permissions.append(Permission(
                    name=getattr(perm, 'name', ''),
                    description=getattr(perm, 'description', ''),
                    scope=getattr(perm, 'scope', ''),
                    required=getattr(perm, 'required', True)
                ))
        
        # Extract provider information
        provider_info = {"id": "unknown", "name": "Unknown Provider"}
        if hasattr(tool, 'provider') and tool.provider:
            provider_info = {
                "id": getattr(tool.provider, 'id', 'unknown'),
                "name": getattr(tool.provider, 'name', 'Unknown Provider')
            }
        
        return ETDIToolDefinition(
            id=tool.name,  # MCP uses name as identifier
            name=tool.name,
            version=getattr(tool, 'version', '1.0.0'),
            description=tool.description or '',
            provider=provider_info,
            schema=tool.inputSchema or {},
            permissions=permissions,
            security=security_info,
            verification_status=VerificationStatus.UNVERIFIED
        )
    
    async def approve_tool(self, tool_name: str) -> None:
        """
        Approve a tool for usage
        
        Args:
            tool_name: Name of tool to approve
        """
        etdi_tool = self._etdi_tools.get(tool_name)
        if not etdi_tool:
            raise ETDIError(f"Tool not found: {tool_name}")
        
        await self.approval_manager.approve_tool_with_etdi(etdi_tool)
        logger.info(f"Approved tool: {tool_name}")
    
    async def get_tool_security_status(self, tool_name: str) -> Dict[str, Any]:
        """
        Get security status for a tool
        
        Args:
            tool_name: Name of tool
            
        Returns:
            Security status information
        """
        etdi_tool = self._etdi_tools.get(tool_name)
        if not etdi_tool:
            return {"error": "Tool not found"}
        
        approval = await self.approval_manager.get_approval(etdi_tool.id)
        changes = await self.approval_manager.check_for_changes(etdi_tool)
        
        return {
            "tool_id": etdi_tool.id,
            "verification_status": etdi_tool.verification_status.value,
            "has_oauth": etdi_tool.security and etdi_tool.security.oauth is not None,
            "is_approved": approval is not None,
            "approval_date": approval.approval_date.isoformat() if approval else None,
            "changes_detected": changes.get("changes_detected", False),
            "changes": changes.get("changes", [])
        }