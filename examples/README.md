# Python MCP SDK Examples

This folder provides comprehensive examples of using the Python MCP (Model Context Protocol) SDK, with a special focus on **ETDI (Enhanced Tool Definition Interface)** security features.

## 🎯 Quick Start with ETDI Tool Poisoning Prevention

**ETDI** prevents tool poisoning attacks in MCP environments by providing cryptographic verification and security analysis. Experience real AI security in action!

### 🚀 Try ETDI with Claude Desktop (Recommended)

```bash
# 1. Navigate to the ETDI demo
cd examples/etdi/tool_poisoning_demo

# 2. Set up your environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Configure Auth0 (see detailed steps below)
cp ../.env.example ../.env
# Edit ../.env with your Auth0 credentials

# 4. Set up Claude Desktop integration
python claude_desktop_integration.py

# 5. Restart Claude Desktop and try the tool poisoning demo!
```



## 📁 Available Examples

### 🔒 ETDI Security Examples (`examples/etdi/`)

**Primary Demo: Tool Poisoning Prevention**
- **Location**: `examples/etdi/tool_poisoning_demo/`
- **Purpose**: Demonstrates real-world tool poisoning attacks and ETDI prevention
- **Highlights**: Claude Desktop integration, OAuth authentication, real MCP servers

**Core ETDI Examples**:
- `basic_usage.py` - Simple ETDI client/server setup
- `e2e_secure_server.py` - End-to-end secure server with full ETDI
- `oauth_providers.py` - Auth0 and OAuth integration examples
- `demo_etdi.py` - Interactive ETDI demonstration

### 🌐 Standard MCP Examples
For basic MCP usage without ETDI security, refer to the [official servers repository](https://github.com/modelcontextprotocol/servers).

## 🔧 Detailed Setup Instructions

### Prerequisites

1. **Python 3.11+** with pip and venv
2. **Claude Desktop** (for AI assistant integration)
3. **Auth0 Account** (free tier sufficient)
4. **Git** (for cloning and version control)

### Step 1: Environment Setup

```bash
# Clone the repository (if not already done)
git clone <repository-url>
cd python-sdk-etdi

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .
pip install fastapi uvicorn python-jose[cryptography] httpx typer
```

### Step 2: Auth0 Configuration

1. **Create Auth0 Account**:
   - Go to [auth0.com](https://auth0.com)
   - Sign up for a free account
   - Create a new tenant

2. **Create Application**:
   - In Auth0 Dashboard → Applications → Create Application
   - Choose "Machine to Machine Applications"
   - Name: "ETDI Tool Provider"
   - Authorize for your API

3. **Get Credentials**:
   - Note your **Domain** (e.g., `your-tenant.auth0.com`)
   - Note your **Client ID** (32-character string)
   - Note your **Client Secret** (if needed)

4. **Configure Environment**:
   ```bash
   # Copy example environment file
   cp examples/etdi/.env.example examples/etdi/.env
   
   # Edit the .env file with your credentials
   nano examples/etdi/.env
   ```
   
   Update these values:
   ```env
   ETDI_AUTH0_DOMAIN=your-tenant.auth0.com
   ETDI_CLIENT_ID=your-client-id-here
   ETDI_DEMO_MODE=true
   ETDI_VERBOSE=true
   ```

### Step 3: Choose Your Demo Experience

#### Option A: Claude Desktop Integration (Recommended)

```bash
cd examples/etdi/tool_poisoning_demo

# Set up Claude Desktop integration
python claude_desktop_integration.py

# Restart Claude Desktop completely
# Look for 'etdi-legitimate' and 'etdi-malicious' servers
# Try asking Claude to scan documents for PII
```

#### Option B: Real Server Demo

```bash
cd examples/etdi/tool_poisoning_demo

# Run the comprehensive demo
python run_real_server_demo.py

# See real-time tool poisoning prevention
# Watch ETDI block malicious tools automatically
```

#### Option C: Basic ETDI Examples

```bash
cd examples/etdi

# Try basic ETDI usage
python basic_usage.py

# Explore OAuth integration
python oauth_providers.py

# Run interactive demo
python demo_etdi.py
```

### Step 4: Understanding the Results

#### ✅ ETDI-Protected Tools (Legitimate)
```
🔒 ETDI SECURITY VERIFICATION
✅ ETDI Protection: ENABLED (+50 points)
✅ OAuth Authentication: ENABLED (+30 points)
✅ Auth0 Domain: VERIFIED (+10 points)
✅ Client ID: VERIFIED (+10 points)
📊 TOTAL SCORE: 100/100 points
🛡️ TRUST LEVEL: TRUSTED
✅ RECOMMENDATION: ALLOW EXECUTION
```

#### ❌ Malicious Tools (Demonstration)
```
🚨 SECURITY WARNING
❌ ETDI Protection: DISABLED (0 points)
❌ OAuth Authentication: DISABLED (0 points)
❌ Auth0 Domain: MISSING (0 points)
❌ Client ID: MISSING (0 points)
📊 TOTAL SCORE: 0/100 points
🛡️ TRUST LEVEL: UNTRUSTED
🛑 RECOMMENDATION: BLOCK EXECUTION
```

## 🛠️ Troubleshooting

### Common Issues

**"spawn python ENOENT" in Claude Desktop**:
```bash
# Fix Python path issue
cd examples/etdi/tool_poisoning_demo
python fix_claude_config.py
```

**Auth0 Authentication Errors**:
```bash
# Verify your .env file
cat examples/etdi/.env

# Test Auth0 connection
python examples/etdi/oauth_providers.py
```

**Import Errors**:
```bash
# Ensure you're in the virtual environment
source .venv/bin/activate

# Reinstall dependencies
pip install -e .
pip install fastapi uvicorn python-jose[cryptography] httpx
```

**Tools Not Appearing in Claude Desktop**:
1. Completely quit and restart Claude Desktop
2. Check Claude Desktop logs for errors
3. Verify configuration: `~/Library/Application Support/Claude/claude_desktop_config.json`

## 🎓 Learning Path

### 1. **Start Here**: Basic Understanding
```bash
# Learn ETDI concepts
cd examples/etdi
python basic_usage.py
```

### 2. **Experience Real Attacks**: Tool Poisoning Demo
```bash
# See real security threats
cd examples/etdi/tool_poisoning_demo
python run_real_server_demo.py
```

### 3. **Production Integration**: Claude Desktop
```bash
# Use with real AI assistant
python claude_desktop_integration.py
# Then restart Claude Desktop
```

### 4. **Advanced Topics**: Custom Implementation
```bash
# Build your own secure tools
python examples/etdi/e2e_secure_server.py
python examples/etdi/oauth_providers.py
```

## 🔗 Next Steps

After exploring these examples:

1. **Implement ETDI in Your Tools**: Add security to your MCP servers
2. **Set Up OAuth**: Integrate with Auth0 or other providers  
3. **Deploy Securely**: Use ETDI in production environments
4. **Contribute**: Help improve ETDI security standards

## 📚 Additional Resources

- **Detailed Documentation**: See `examples/etdi/tool_poisoning_demo/README.md`
- **Claude Desktop Guide**: See `CLAUDE_DESKTOP_INTEGRATION.md`
- **Security Analysis**: See `examples/etdi/verify_implementation.py`
- **OAuth Setup**: See `examples/etdi/oauth_providers.py`

## 🤝 Contributing

Help improve MCP security:

1. **Test New Scenarios**: Try different attack vectors
2. **Enhance Documentation**: Add more examples and explanations  
3. **Report Issues**: Help us fix problems and improve security
4. **Share Knowledge**: Teach others about tool poisoning prevention

---

**🛡️ Remember**: ETDI makes MCP tool ecosystems secure by design. Experience real AI security with these comprehensive examples!
