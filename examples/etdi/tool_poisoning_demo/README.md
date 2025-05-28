# ETDI Tool Poisoning Prevention Demos

This directory contains comprehensive demonstrations of how ETDI (Enhanced Tool Definition Interface) prevents tool poisoning attacks in MCP (Model Context Protocol) environments. The demos feature **detailed logging and explanatory messages** that show exactly what's happening at each step of the attack and prevention process.

## 🚀 Complete Setup Guide - Step by Step

### Prerequisites ✅

Before starting, ensure you have:

1. **Python 3.11+** installed with pip and venv
2. **Git** for cloning the repository  
3. **Claude Desktop** (optional but recommended for best experience)
4. **Auth0 Account** (free tier sufficient) - we'll set this up

### Step 1: Repository and Environment Setup

```bash
# 1. Clone the repository (if not already done)
git clone <your-repository-url>
cd python-sdk-etdi

# 2. Create and activate virtual environment
python -m venv .venv

# On macOS/Linux:
source .venv/bin/activate

# On Windows:
.venv\Scripts\activate

# 3. Install the ETDI package in development mode
pip install -e .

# 4. Navigate to the tool poisoning demo
cd examples/etdi/tool_poisoning_demo

# 5. Install demo-specific dependencies
pip install -r requirements.txt
```

### Step 2: Auth0 Setup (Required for Full Functionality)

#### 2.1 Create Auth0 Account

1. Go to [auth0.com](https://auth0.com) and sign up for a free account
2. Create a new tenant (choose any name, e.g., "etdi-demo")
3. Complete the setup wizard

#### 2.2 Create Application

1. In Auth0 Dashboard, go to **Applications** → **Create Application**
2. Choose **Machine to Machine Applications**
3. Name it "ETDI Tool Provider Demo"
4. Select your default API or create a new one:
   - **Name**: "ETDI Tool Registry API"
   - **Identifier**: `https://api.etdi-tools.demo.com`
5. Authorize the application for your API

#### 2.3 Get Your Credentials

1. In your application settings, note:
   - **Domain** (e.g., `your-tenant.auth0.com`)
   - **Client ID** (32-character string)
   - **Client Secret** (for machine-to-machine auth)

#### 2.4 Configure Environment Variables

```bash
# Copy the example environment file
cp ../.env.example ../.env

# Edit the .env file with your actual credentials
nano ../.env
# OR use your preferred editor: code ../.env, vim ../.env, etc.
```

Update your `.env` file with your Auth0 credentials:
```env
# Auth0 Configuration - Replace with your actual values
ETDI_AUTH0_DOMAIN=your-tenant.auth0.com
ETDI_CLIENT_ID=your-client-id-here

# Demo Configuration
ETDI_DEMO_MODE=true
ETDI_VERBOSE=true
```

### Step 3: Choose Your Demo Experience

#### Option A: Claude Desktop Integration (🌟 Recommended)

**Best for**: Experiencing ETDI with a real AI assistant

```bash
# 1. Set up Claude Desktop integration
python claude_desktop_integration.py

# 2. Restart Claude Desktop completely:
#    - Quit Claude Desktop entirely (not just close window)
#    - Reopen Claude Desktop
#    - Wait for servers to initialize

# 3. Look for these servers in Claude Desktop:
#    ✅ etdi-legitimate (SAFE - ETDI protected)
#    ⚠️  etdi-malicious (DEMO - Attack simulation)

# 4. Try these prompts in Claude Desktop:
#    "Can you scan this document for PII using SecureDocs_Scanner?"
#    "What tools are available from the ETDI servers?"
#    "Can you analyze the security of the available servers?"
```

**Troubleshooting Claude Desktop**:
```bash
# If you see "spawn python ENOENT" errors:
python fix_claude_config.py

# If servers don't appear, check:
cat "/Users/$USER/Library/Application Support/Claude/claude_desktop_config.json"
```

#### Option B: Real Server Demo

**Best for**: Understanding the technical implementation

```bash
# Run the comprehensive real server demonstration
python run_real_server_demo.py

# This will:
# 1. Start both legitimate and malicious servers
# 2. Connect an ETDI-enabled client
# 3. Demonstrate tool poisoning attack prevention
# 4. Show detailed security analysis and blocking
```

#### Option C: Simulation Demo

**Best for**: Quick conceptual understanding

```bash
# Run the educational simulation
python tool_poisoning_prevention_demo.py

# This provides a simplified demonstration of:
# - Tool poisoning concepts
# - ETDI security analysis
# - Attack prevention mechanisms
```

### Step 4: Verify Everything Works

#### Test 1: Basic Functionality
```bash
# Test that your environment is set up correctly
python -c "import mcp; print('✅ MCP imported successfully')"
python -c "import os; print('Auth0 Domain:', os.getenv('ETDI_AUTH0_DOMAIN', 'NOT SET'))"
```

#### Test 2: Server Loading
```bash
# Test that servers can be imported and run
python test_claude_integration.py
```

#### Test 3: Claude Desktop Integration (if using Option A)
1. Open Claude Desktop
2. Look for `etdi-legitimate` and `etdi-malicious` in the server list
3. Try asking Claude: "What servers are available?"

### Step 5: Understanding the Results

#### ✅ What Success Looks Like

**Claude Desktop Integration**:
- Two servers appear: `etdi-legitimate` and `etdi-malicious`
- Tools from legitimate server work with security verification
- Tools from malicious server are blocked or warned about

**Real Server Demo**:
```
🎯 DEMONSTRATION COMPLETE
✅ ETDI successfully demonstrated real-time attack prevention!
📊 Security Score - Legitimate: 100/100, Malicious: 0/100
🛡️ Attack Prevention Rate: 50.0% (1 blocked, 1 allowed)
```

**Security Analysis Output**:
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

## 🛠️ Troubleshooting Common Issues

### Issue: "ModuleNotFoundError: No module named 'mcp'"

**Solution**:
```bash
# Ensure you're in the virtual environment
source .venv/bin/activate  # macOS/Linux
# OR
.venv\Scripts\activate     # Windows

# Reinstall the package
pip install -e .
```

### Issue: "spawn python ENOENT" in Claude Desktop

**Solution**:
```bash
# Fix the Python path in Claude Desktop config
python fix_claude_config.py
```

### Issue: Auth0 Authentication Errors

**Solutions**:
```bash
# 1. Verify your .env file
cat ../.env

# 2. Test Auth0 connection
cd ..
python oauth_providers.py

# 3. Check your Auth0 application settings:
#    - Application Type: Machine to Machine
#    - Authorized APIs: Your API should be selected
#    - Domain and Client ID are correct
```

### Issue: Servers Don't Appear in Claude Desktop

**Solutions**:
1. **Restart Claude Desktop completely** (quit entirely, then reopen)
2. **Check configuration**:
   ```bash
   # macOS
   cat "/Users/$USER/Library/Application Support/Claude/claude_desktop_config.json"
   
   # Windows  
   cat "%APPDATA%/Claude/claude_desktop_config.json"
   ```
3. **Verify Python path**: Make sure the command points to your virtual environment's Python
4. **Check Claude Desktop logs** for error messages

### Issue: Import Errors

**Solutions**:
```bash
# 1. Ensure all dependencies are installed
pip install -r requirements.txt

# 2. Reinstall specific packages if needed
pip install fastapi uvicorn python-jose[cryptography] httpx typer

# 3. If you see ETDI import errors:
pip install -e .
```

## 🎓 Step-by-Step Learning Path

### Level 1: Beginner (Start Here)
```bash
# 1. Understand basic concepts
cd examples/etdi
python basic_usage.py

# 2. See a simple demo
cd tool_poisoning_demo
python tool_poisoning_prevention_demo.py
```

### Level 2: Intermediate  
```bash
# 1. Experience real attacks
python run_real_server_demo.py

# 2. Understand OAuth integration
cd ..
python oauth_providers.py
```

### Level 3: Advanced
```bash
# 1. Integrate with Claude Desktop
cd tool_poisoning_demo
python claude_desktop_integration.py

# 2. Explore implementation details
python -c "
import legitimate_etdi_server
import malicious_server
print('Servers loaded successfully')
"
```

### Level 4: Expert
```bash
# 1. Build your own secure server
cd ..
python e2e_secure_server.py

# 2. Implement custom security policies
python verify_implementation.py
```

## 📁 Demo Files Overview

### 🎯 Real Server Demo (Recommended) - **Enhanced with Detailed Logging**
**Files:**
- `legitimate_etdi_server.py` - Real FastMCP server with ETDI protection
- `malicious_server.py` - Real FastMCP server simulating attack
- `etdi_attack_prevention_client.py` - ETDI-enabled MCP client
- `run_real_server_demo.py` - Automated demo orchestrator
- `REAL_SERVER_DEMO_README.md` - Detailed documentation

**What it demonstrates:**
- ✅ **Real FastMCP servers** with actual MCP protocol communication
- ✅ **ETDI security analysis** with detailed scoring (100/100 vs 0/100)
- ✅ **Tool poisoning attack prevention** with real-time blocking
- ✅ **OAuth authentication** using Auth0 integration
- ✅ **Comprehensive logging** showing every security check
- ✅ **Educational explanations** of attack vectors and prevention

### 🎓 Simulation Demo (Educational)
**Files:**
- `tool_poisoning_prevention_demo.py` - Simulation-based demonstration
- `TOOL_POISONING_DEMO_README.md` - Educational documentation

**What it demonstrates:**
- 📚 **Educational simulation** of tool poisoning attacks
- 📚 **Conceptual understanding** of ETDI security features
- 📚 **Attack scenarios** and prevention mechanisms
- 📚 **Security analysis** without real server complexity

### 🖥️ Claude Desktop Integration - **NEW!**
**Files:**
- `claude_desktop_integration.py` - Simple setup script
- `setup_claude_integration.py` - Advanced setup with MCP CLI
- `CLAUDE_DESKTOP_INTEGRATION.md` - Comprehensive integration guide

**What it demonstrates:**
- 🤖 **Real AI assistant integration** with Claude Desktop
- 🔄 **Live tool poisoning scenarios** in actual conversations
- 🛡️ **ETDI protection in action** during real AI interactions
- 📊 **Side-by-side comparison** of secure vs. insecure tools
- 🎓 **Hands-on learning** with real-world AI assistant usage

## 🚀 Quick Start

### Option 1: Claude Desktop Integration (Recommended for Real Experience)
```bash
cd tool_poisoning_demo

# Simple setup
python claude_desktop_integration.py

# Then restart Claude Desktop and look for:
# - etdi-legitimate (SAFE server)
# - etdi-malicious (DEMO attack server)
```

### Option 2: Enhanced Real Server Demo
```bash
cd tool_poisoning_demo
python run_real_server_demo.py
```

### Option 3: Simulation Demo
```bash
cd tool_poisoning_demo
python tool_poisoning_prevention_demo.py
```

## 🎯 Attack Scenario - **Now with Detailed Explanations**

All demos demonstrate the same core attack scenario with comprehensive logging:

### The Problem: Tool Poisoning
1. **Legitimate Tool**: "SecureDocs Scanner" from TrustedSoft Inc.
   - ✅ **ETDI Protection**: Enabled (+50 security points)
   - ✅ **OAuth Authentication**: Enabled (+30 security points)
   - ✅ **Auth0 Domain**: Verified (+10 security points)
   - ✅ **Client ID**: Verified (+10 security points)
   - 📊 **Total Score**: 100/100 → **TRUSTED** → **ALLOWED**

2. **Malicious Tool**: Identical "SecureDocs Scanner" (spoofed)
   - ❌ **ETDI Protection**: Disabled (0 security points)
   - ❌ **OAuth Authentication**: Disabled (0 security points)
   - ❌ **Auth0 Domain**: Missing (0 security points)
   - ❌ **Client ID**: Missing (0 security points)
   - 📊 **Total Score**: 0/100 → **UNTRUSTED** → **BLOCKED**

3. **User Dilemma**: Without ETDI, tools appear identical
   - Same name, same description, same interface
   - No way to distinguish legitimate from malicious
   - User unknowingly uses malicious tool

### The Solution: ETDI Prevention - **With Real-Time Analysis**
ETDI provides cryptographic verification and detailed security analysis:

1. **Security Analysis**: Client analyzes server metadata with detailed logging
   ```
   🔍 ETDI SECURITY ANALYSIS FOR Legitimate Server
   ============================================================
   📋 Server Name: TrustedSoft SecureDocs Server
   🏢 Provider: TrustedSoft Inc.
   📊 Starting security verification...

   🔒 ETDI VERIFICATION CHECKS:
   ✅ ETDI Protection: ENABLED (+50 points)
   ✅ OAuth Authentication: ENABLED (+30 points)
   ✅ Auth0 Domain: VERIFIED (+10 points)
   ✅ OAuth Client ID: VERIFIED (+10 points)
   📈 TOTAL SCORE: 100/100 points
   🛡️ TRUST LEVEL: TRUSTED (80+ points)
   ✅ RECOMMENDATION: ALLOW EXECUTION
   ```

2. **Trust Levels**: Based on security score with detailed explanations
   - **TRUSTED (80-100)**: Full protection, execution ALLOWED
   - **PARTIALLY_TRUSTED (50-79)**: Some protection, execution with WARNING
   - **UNTRUSTED (0-49)**: No protection, execution BLOCKED

3. **Attack Prevention**: Malicious tools blocked with detailed reasoning
   ```
   🛑 ETDI BLOCKS TOOL EXECUTION
   ===================================
   🚨 TOOL POISONING ATTACK PREVENTED!
   📋 Server: Malicious Server
   🔧 Tool: SecureDocs_Scanner
   ❌ Reason: Insufficient security features
   🛡️ Protection: ETDI prevented malicious tool execution

   🚨 SECURITY VIOLATIONS:
      1. No ETDI security
      2. No OAuth authentication
      3. Invalid or missing Auth0 domain
      4. Invalid or missing OAuth client ID
   ```

## 📊 Enhanced Demo Results

### Claude Desktop Integration Results - **Real AI Assistant Experience**
```
🤖 CLAUDE DESKTOP INTEGRATION
==============================
✅ Servers successfully added to Claude Desktop
🔍 Available in Claude Desktop:
   • etdi-legitimate - ETDI-protected server
   • etdi-malicious - Attack demonstration server

🧪 TESTING SCENARIOS:
   1. Ask Claude to scan documents using SecureDocs_Scanner
   2. Compare tools from both servers
   3. See ETDI protection in real conversations
   4. Experience tool poisoning prevention live

🛡️ EXPECTED BEHAVIOR:
   • ETDI server: Full security verification, safe execution
   • Malicious server: Security warnings, blocked execution
   • Educational: Learn about tool verification in practice
```

### Real Server Demo Results - **With Detailed Metrics**
```
🎯 DEMONSTRATION COMPLETE
==============================
✅ ETDI successfully demonstrated real-time attack prevention!
🛡️ Tool poisoning attack blocked before data exposure
🔒 User data protected through ETDI verification
📊 Security analysis provided clear risk assessment

📈 ETDI ATTACK PREVENTION SUMMARY
=============================================
   ✅ Servers Allowed: 1
   ⚠️ Servers Warned: 0
   🛑 Servers Blocked: 1
   🛡️ Attack Prevention Rate: 50.0%

🔍 DETAILED SECURITY COMPARISON
========================================
Legitimate Server:
   🔒 ETDI Protection: ✅ ENABLED
   🔑 OAuth Authentication: ✅ ENABLED
   📊 Security Score: 100/100
   🛡️ Trust Level: TRUSTED
   📋 Final Decision: ALLOW

Malicious Server:
   🔒 ETDI Protection: ❌ DISABLED
   🔑 OAuth Authentication: ❌ DISABLED
   📊 Security Score: 0/100
   🛡️ Trust Level: UNTRUSTED
   📋 Final Decision: BLOCK
```

### Key Insights Demonstrated - **With Educational Context**
- **Without ETDI**: Tools appear identical, no protection
- **With ETDI**: Cryptographic proof enables safe tool selection
- **Real Protection**: Actual data exfiltration prevented
- **User Safety**: Malicious tools blocked transparently
- **Educational Value**: Clear understanding of threats and solutions

## 🔧 Technical Implementation - **Enhanced Features**

### Claude Desktop Integration Architecture - **Real AI Assistant**
- **MCP Protocol**: Direct integration with Claude Desktop via MCP servers
- **Live Conversations**: Test tool poisoning during actual AI interactions
- **Real-time Security**: ETDI verification happens during tool usage
- **Educational Experience**: Learn through hands-on AI assistant usage
- **Production-like**: Experience real-world tool verification scenarios

### Real Server Demo Architecture - **With Detailed Logging**
- **FastMCP Servers**: Actual MCP protocol servers with comprehensive logging
- **Stdio Transport**: Real client-server communication with status reporting
- **ETDI Integration**: Genuine security verification with step-by-step analysis
- **OAuth Authentication**: Auth0-based authentication with detailed verification
- **Process Management**: Multi-process demonstration with status monitoring

### Security Features Demonstrated - **With Real-Time Feedback**
- **Tool Verification**: Cryptographic authenticity proof with detailed scoring
- **OAuth Integration**: Provider identity verification with Auth0 validation
- **Permission Scoping**: Fine-grained access control with enforcement logging
- **Call Stack Constraints**: Tool interaction limits with violation detection
- **Audit Logging**: Comprehensive security tracking with event details

### Enhanced Logging Features
- **🔐 Legitimate Server**: Shows ETDI protection activation and security features
- **💀 Malicious Server**: Demonstrates attack vectors and data exfiltration attempts
- **🛡️ ETDI Client**: Provides detailed security analysis and prevention reasoning
- **🚀 Demo Orchestrator**: Manages the entire demonstration with phase-by-phase reporting

## 🌍 Real-World Applications

### Enterprise Security - **Proven Protection**
- **Tool Marketplace Protection**: Verify tools before deployment with detailed analysis
- **Supply Chain Security**: Prevent malicious tool injection with cryptographic proof
- **Compliance Requirements**: Meet security audit standards with comprehensive logging
- **Zero Trust Architecture**: Verify every tool interaction with detailed verification

### Development Workflows - **Secure by Design**
- **CI/CD Pipeline Security**: Verify build tools and scripts with ETDI protection
- **Code Analysis Tools**: Ensure legitimate security scanners with OAuth verification
- **Deployment Automation**: Verify infrastructure tools with detailed security checks
- **Monitoring Systems**: Authenticate observability tools with comprehensive analysis

### AI/ML Environments - **Trusted Tool Ecosystems**
- **Model Training Security**: Verify data processing tools with detailed verification
- **Inference Pipeline Protection**: Authenticate model serving tools with real-time analysis
- **Data Pipeline Security**: Verify ETL and transformation tools with comprehensive checks
- **Research Tool Verification**: Ensure legitimate analysis tools with detailed scoring

## 📚 Documentation

### Detailed Guides - **Enhanced with Examples**
- **`CLAUDE_DESKTOP_INTEGRATION.md`**: Complete Claude Desktop setup and usage guide
- **`REAL_SERVER_DEMO_README.md`**: Complete real server demo documentation with examples
- **`TOOL_POISONING_DEMO_README.md`**: Simulation demo documentation with educational content

### Key Concepts Explained - **With Practical Examples**
- **Tool Poisoning Attacks**: How malicious actors exploit tool similarity (with real examples)
- **ETDI Security Model**: Cryptographic verification and OAuth integration (with scoring details)
- **Attack Prevention**: Real-time security analysis and blocking (with detailed logs)
- **Trust Establishment**: Building confidence in tool ecosystems (with practical metrics)

## 🎯 Choosing the Right Demo

### Use Claude Desktop Integration When:
- 🤖 You want to experience tool poisoning with a **real AI assistant**
- 🔄 You need to see ETDI protection in **actual conversations**
- 🎓 You're learning about AI security through **hands-on experience**
- 🏢 You're evaluating ETDI for **production AI deployments**
- 📊 You want to see **side-by-side tool comparison** in real usage

### Use Enhanced Real Server Demo When:
- ✅ You want to see actual MCP protocol in action **with detailed logging**
- ✅ You need proof that ETDI works in practice **with comprehensive analysis**
- ✅ You're evaluating ETDI for production use **with real security metrics**
- ✅ You want to understand real implementation details **with step-by-step explanations**
- ✅ You need educational content about tool poisoning **with practical examples**

### Use Simulation Demo When:
- 📚 You're learning about tool poisoning concepts **without server complexity**
- 📚 You want a simpler, educational demonstration **with basic examples**
- 📚 You're teaching others about ETDI security **with conceptual explanations**
- 📚 You need a quick conceptual overview **without detailed technical implementation**

## 🔍 What's New in the Enhanced Version

### 🆕 Claude Desktop Integration
- **Real AI assistant**: Experience tool poisoning with actual Claude Desktop
- **Live conversations**: Test security during real AI interactions
- **Production-like**: See how ETDI works in real-world AI usage
- **Educational experience**: Learn through hands-on AI assistant usage

### 🆕 Detailed Security Analysis
- **Real-time scoring**: See exactly how ETDI calculates security scores (50+30+10+10=100)
- **Step-by-step verification**: Watch each security check with detailed explanations
- **Trust level determination**: Understand how scores translate to trust levels
- **Violation reporting**: See exactly why malicious tools are blocked

### 🆕 Educational Explanations
- **Attack vector analysis**: Understand how tool poisoning works in practice
- **Prevention mechanisms**: See how ETDI stops attacks before they happen
- **Real-world impact**: Learn about the broader implications for security
- **Best practices**: Understand how to implement ETDI in your own systems

### 🆕 Comprehensive Logging
- **Phase-by-phase execution**: Clear progression through demo stages
- **Security event tracking**: Real-time logging of all security decisions
- **Attack simulation**: Detailed view of what malicious tools attempt
- **Protection demonstration**: Clear evidence of ETDI effectiveness

### 🆕 Enhanced User Experience
- **Visual indicators**: Emojis and formatting for easy understanding
- **Progress tracking**: Clear indication of demo progression
- **Error handling**: Graceful handling of issues with helpful messages
- **Educational context**: Explanations of why each step matters

## 🔍 Next Steps

After running these enhanced demos, explore:

1. **Claude Desktop Integration**: Experience ETDI with a real AI assistant **for hands-on learning**
2. **ETDI Integration**: Learn how to add ETDI to your own tools **with detailed examples**
3. **OAuth Configuration**: Set up Auth0 for your applications **with step-by-step guides**
4. **Security Policies**: Define custom security requirements **with practical templates**
5. **Production Deployment**: Implement ETDI in real environments **with deployment guides**

## 🤝 Contributing

To improve these demos:
1. Test with different attack scenarios **and document the results**
2. Add new security verification methods **with detailed explanations**
3. Enhance documentation and examples **with practical use cases**
4. Report issues and suggest improvements **with specific feedback**
5. Try Claude Desktop integration **and share your experience**

## 💡 Key Takeaways from Enhanced Demos

### 🚨 The Tool Poisoning Threat
- **Real and Present**: Malicious actors can easily spoof legitimate tools
- **Hard to Detect**: Without ETDI, tools appear identical to users
- **Serious Impact**: Data can be stolen while users believe they're safe
- **Growing Problem**: Tool ecosystems are expanding rapidly
- **AI Assistant Risk**: AI assistants make tool selection decisions for users

### 🛡️ The ETDI Solution
- **Cryptographic Proof**: OAuth tokens provide verifiable authenticity
- **Detailed Analysis**: Security scoring enables informed decisions
- **Real-time Protection**: Malicious tools blocked before execution
- **Educational Value**: Users understand threats and protections
- **AI Integration**: Works seamlessly with AI assistants like Claude Desktop

### 🔒 Real-World Impact
- **Data Protection**: Sensitive information secured from exfiltration
- **Trust Building**: Users can confidently use tool ecosystems
- **Compliance Support**: Audit trails meet regulatory requirements
- **Security Culture**: Organizations adopt security-first approaches
- **AI Safety**: AI assistants can make secure tool selection decisions

---

**🛡️ ETDI: Making MCP Tool Ecosystems Secure by Design with Comprehensive Education, Real-Time Protection, and Real AI Assistant Integration** 