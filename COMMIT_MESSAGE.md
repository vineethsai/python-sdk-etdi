feat: Add comprehensive ETDI tool poisoning prevention demo with Claude Desktop integration

## Major Features Added

### 🔒 Security & Secret Management
- Remove all hardcoded Auth0 credentials from codebase
- Replace with secure environment variables using os.getenv()
- Add .env.example template for easy setup
- Implement automatic secret redaction tooling

### 🤖 Claude Desktop Integration  
- Add full MCP server integration with Claude Desktop
- Demonstrate real-time tool poisoning prevention in AI assistant
- Support side-by-side comparison of secure vs malicious tools
- Include automatic Python path detection and configuration

### 🛡️ ETDI Tool Poisoning Prevention Demo
- Create comprehensive tool poisoning attack demonstration
- Implement legitimate ETDI-protected server with OAuth authentication
- Add malicious server simulation for educational purposes
- Provide real-time security analysis and threat blocking

### 📚 Documentation & Setup
- Complete rewrite of examples/README.md with step-by-step instructions
- Add comprehensive tool poisoning demo documentation
- Include Auth0 setup guide and troubleshooting sections
- Create progressive learning path from beginner to expert

### 🛠️ Infrastructure & Tooling
- Add requirements.txt with all necessary dependencies  
- Create setup verification and testing scripts
- Implement automatic environment configuration
- Add comprehensive error handling and user guidance

## Files Modified
- examples/README.md: Complete rewrite with ETDI focus
- examples/etdi/oauth_providers.py: Secret redaction + env vars
- examples/etdi/run_e2e_demo.py: Secret redaction + env vars  
- src/mcp/etdi/server/tool_provider.py: Enhanced functionality

## Files Added
- examples/etdi/.env.example: Environment variable template
- examples/etdi/tool_poisoning_demo/: Complete demo directory
- examples/etdi/tool_poisoning_demo/requirements.txt: Dependencies
- examples/etdi/tool_poisoning_demo/README.md: Setup documentation
- examples/etdi/legitimate_etdi_server.py: ETDI-protected server
- examples/etdi/tool_poisoning_demo/malicious_server.py: Attack simulation
- examples/etdi/tool_poisoning_demo/etdi_attack_prevention_client.py: ETDI client
- examples/etdi/tool_poisoning_demo/run_real_server_demo.py: Demo orchestrator

## Breaking Changes
None - all changes are additive and backward compatible

## Security Impact
- ✅ Eliminates hardcoded secrets from repository
- ✅ Implements secure environment variable patterns
- ✅ Demonstrates real security threat prevention
- ✅ Provides educational security tooling

## User Impact  
- 🚀 Easy one-command setup for new users
- 🎓 Multiple learning paths from basic to advanced
- 🤖 Real AI assistant integration experience  
- 📖 Comprehensive documentation and troubleshooting 