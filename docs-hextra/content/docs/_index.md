---
title: Documentation
type: docs
sidebar:
  open: true
---

# ETDI Security Framework Documentation

Welcome to the Enhanced Tool Definition Interface (ETDI) documentation. ETDI provides enterprise-grade security for AI tool interactions, protecting against tool poisoning, rug poisoning, and unauthorized access.

## Quick Navigation

{{< hextra/cards >}}
  {{< hextra/card link="getting-started" title="Getting Started" icon="play" >}}
    Installation, setup, and basic concepts.
  {{< /hextra/card >}}
  
  {{< hextra/card link="attack-prevention" title="Attack Prevention" icon="shield" >}}
    Protection against security threats.
  {{< /hextra/card >}}
  
  {{< hextra/card link="security-features" title="Security Features" icon="lock" >}}
    Authentication and authorization systems.
  {{< /hextra/card >}}
{{< /hextra/cards >}}

## Architecture Overview

ETDI implements a multi-layered security architecture:

1. **Cryptographic Verification**: Tool signatures and identity verification
2. **Behavioral Monitoring**: Real-time behavior analysis and anomaly detection  
3. **Access Control**: Role-based permissions and call chain validation
4. **Audit Trail**: Comprehensive logging and compliance reporting

## Core Components

- **Secure Server**: Enhanced MCP server with security middleware
- **ETDI Client**: Verification and approval management
- **Token Manager**: Cryptographic token handling and validation
- **Inspector**: Security analysis and threat detection
- **OAuth Integration**: Enterprise authentication providers 