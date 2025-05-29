---
title: "ETDI Security Framework"
layout: hextra-home
---

{{< hextra/hero-badge link="/docs/getting-started" >}}
  <div class="w-2 h-2 rounded-full bg-current"></div>
  <span>Get Started</span>
  {{< icon name="arrow-circle-right" attributes="height=14" >}}
{{< /hextra/hero-badge >}}

<div class="mt-6 mb-6">
{{< hextra/hero-headline >}}
  Enterprise-Grade Security&nbsp;<br class="sm:block hidden" />for AI Tool Interactions
{{< /hextra/hero-headline >}}
</div>

<div class="mb-12">
{{< hextra/hero-subtitle >}}
  Prevent tool poisoning, rug poisoning, and unauthorized access with cryptographic verification, behavioral monitoring, and comprehensive audit trails.
{{< /hextra/hero-subtitle >}}
</div>

<div class="mb-6">
{{< hextra/hero-button text="Get Started" link="/docs/getting-started" >}}
</div>

<div class="mt-6">
{{< hextra/cards >}}
  {{< hextra/card link="/docs/attack-prevention/tool-poisoning" title="Tool Poisoning Prevention" icon="shield-check" >}}
    Cryptographic verification and identity spoofing protection against malicious tools.
  {{< /hextra/card >}}
  
  {{< hextra/card link="/docs/attack-prevention/rug-poisoning" title="Rug Poisoning Protection" icon="eye" >}}
    Behavior change detection and reapproval workflows for modified tools.
  {{< /hextra/card >}}
  
  {{< hextra/card link="/docs/security-features/authentication" title="Enterprise Authentication" icon="key" >}}
    OAuth 2.0, SAML, and enterprise SSO integration with role-based access control.
  {{< /hextra/card >}}
{{< /hextra/cards >}}
</div>

## Key Security Features

- **🛡️ Tool Poisoning Prevention**: Cryptographic signatures and behavioral verification
- **👁️ Rug Poisoning Protection**: Change detection and reapproval workflows  
- **🔐 Call Chain Validation**: Stack constraints and caller/callee authorization
- **🔑 Enterprise Authentication**: OAuth 2.0, SAML, and SSO integration
- **📊 Comprehensive Auditing**: Security events, compliance reporting, and forensics
- **⚡ Real-time Monitoring**: Live threat detection and automated response

## Quick Start

```python
from mcp.etdi import SecureServer, ToolProvider
from mcp.etdi.auth import OAuthHandler

# Create secure server with ETDI protection
server = SecureServer(
    security_level="high",
    enable_tool_verification=True,
    enable_behavior_monitoring=True
)

# Add OAuth authentication
auth = OAuthHandler(
    provider="auth0",
    domain="your-domain.auth0.com",
    client_id="your-client-id"
)
server.add_auth_handler(auth)

# Register verified tools
@server.tool("secure_file_read")
async def secure_file_read(path: str) -> str:
    # Tool implementation with ETDI security
    return await verified_file_read(path)
```

## Documentation Structure

{{< hextra/cards >}}
  {{< hextra/card link="/docs/getting-started" title="Getting Started" icon="play" >}}
    Installation, setup, and your first secure server.
  {{< /hextra/card >}}
  
  {{< hextra/card link="/docs/attack-prevention" title="Attack Prevention" icon="shield" >}}
    Comprehensive protection against AI security threats.
  {{< /hextra/card >}}
  
  {{< hextra/card link="/docs/security-features" title="Security Features" icon="lock" >}}
    Authentication, authorization, and behavioral verification.
  {{< /hextra/card >}}
  
  {{< hextra/card link="/examples" title="Examples & Demos" icon="code" >}}
    Real-world examples and interactive demonstrations.
  {{< /hextra/card >}}
{{< /hextra/cards >}} 