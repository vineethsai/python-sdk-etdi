---
title: API Reference
---

# API Reference

Complete API documentation for the ETDI Security Framework.

## Core Classes

{{< hextra/cards >}}
  {{< hextra/card link="secure-server" title="SecureServer" icon="server" >}}
    Main server class with security middleware.
  {{< /hextra/card >}}
  
  {{< hextra/card link="etdi-client" title="ETDIClient" icon="computer-desktop" >}}
    Enhanced client with verification capabilities.
  {{< /hextra/card >}}
  
  {{< hextra/card link="security-types" title="Security Types" icon="shield" >}}
    Security policies, levels, and configuration types.
  {{< /hextra/card >}}
{{< /hextra/cards >}}

## Quick Reference

### SecureServer

```python
from mcp.etdi import SecureServer

server = SecureServer(
    name: str,
    security_level: SecurityLevel = SecurityLevel.MEDIUM,
    enable_tool_verification: bool = True,
    enable_behavior_monitoring: bool = True,
    auth_handler: Optional[BaseAuthHandler] = None
)
```

### ETDIClient

```python
from mcp.etdi.client import ETDIClient

client = ETDIClient(
    server_url: str,
    verification_level: VerificationLevel = VerificationLevel.HIGH,
    enable_approval_management: bool = True
)
```

### Security Configuration

```python
from mcp.etdi.types import SecurityPolicy, SecurityLevel

policy = SecurityPolicy(
    security_level=SecurityLevel.HIGH,
    require_tool_signatures=True,
    enable_behavior_monitoring=True,
    audit_all_calls=True
)
```

For complete API documentation, see the individual class reference pages. 