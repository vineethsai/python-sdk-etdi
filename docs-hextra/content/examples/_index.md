---
title: Examples & Demos
---

# Examples & Demos

Comprehensive examples and interactive demonstrations of ETDI security features.

## Quick Navigation

{{< hextra/cards >}}
  {{< hextra/card link="attack-simulations" title="Attack Simulations" icon="bug" >}}
    Realistic attack scenarios and prevention demos.
  {{< /hextra/card >}}
  
  {{< hextra/card link="enterprise-security" title="Enterprise Security" icon="building-office" >}}
    Enterprise-grade security implementations.
  {{< /hextra/card >}}
  
  {{< hextra/card link="real-world-scenarios" title="Real-World Scenarios" icon="globe" >}}
    Production-ready examples and use cases.
  {{< /hextra/card >}}
{{< /hextra/cards >}}

## Getting Started Examples

### Basic Secure Server

```python
from mcp.etdi import SecureServer

server = SecureServer(name="basic-secure-server")

@server.tool("hello_world")
async def hello_world(name: str) -> str:
    return f"Hello, {name}! This is a secure tool."

await server.start()
```

### Tool Poisoning Prevention Demo

```python
# Run the comprehensive demo
python examples/etdi/tool_poisoning_demo/run_e2e_demo.py

# Expected output:
# ✓ Legitimate tools: ALLOWED (6/6)
# ✓ Malicious tools: BLOCKED (8/8) 
# ✓ Security score: 100/100
```

### Enterprise Authentication

```python
from mcp.etdi import SecureServer
from mcp.etdi.auth import OAuthHandler

# Configure enterprise authentication
oauth = OAuthHandler(
    provider="auth0",
    domain=os.getenv("AUTH0_DOMAIN"),
    client_id=os.getenv("AUTH0_CLIENT_ID")
)

server = SecureServer(auth_handler=oauth)
```

## Interactive Demos

1. **Tool Poisoning Demo** - See real-time attack prevention
2. **Rug Poisoning Simulation** - Watch behavior change detection  
3. **Call Chain Validation** - Observe access control in action
4. **Enterprise Integration** - Full production setup 