# Caido Workflows & Automation Guide

## Purpose
Based on Episode 138 insights - leverage Caido's advanced workflow capabilities for maximum efficiency and automation.

## Essential Caido Plugins

### Even Better Plugin
**Features**:
- Common Filters (recent: 5min, 1hr, 6hr, 12hr, 24hr)
- Convert Workflow command palette entries
- Auto-updating filters every minute

**Setup**:
```bash
# Install from Caido store
# Search "even better" and install
```

**Usage**:
- Press `Ctrl+K` for command palette
- Type workflow name for quick encoding
- Example: `base64 encode` for selected text

### Notes Plugin
**Features**:
- Windows+Shift+N for quick notes
- Attach current context automatically
- Graphical request representation
- Click-to-navigate from notes to requests

**Workflow**:
1. Find interesting request in Replay
2. Press `Win+Shift+N`
3. Write note with context attached
4. Click embedded request to jump back

### Shift Agents
**Purpose**: Build custom micro-agents for automated testing

**Example: Domain Restriction Bypass Agent**
```javascript
// System prompt template
You are a domain restriction bypass specialist. 
Check the following methods:
1. Regex validation bypass
2. Ends-with validation bypass  
3. Invalid URL parsing
4. Unicode normalization
5. @ symbol at front of URL

Test each method systematically and report findings.
```

**Usage**:
1. Open Replay tab with target request
2. Open AI window (h icon)
3. Load system prompt
4. Delegate tab to AI
5. Review findings when complete

### Drop Plugin
**Purpose**: End-to-end encrypted collaboration

**Setup**:
```bash
# Get collaborator's PGP public key
# Add to Drop plugin
# Share requests, workflows, scopes instantly
```

## Workflow Automation

### Auto Session Refresher
**Purpose**: Never deal with expired sessions again

**Setup**:
```javascript
// Passive workflow for session extraction
// 1. Create passive workflow
// 2. Target: specific host
// 3. Extract session cookies
// 4. Store in environment variable
// 5. Use placeholder in Replay requests
```

**Benefits**:
- Sessions auto-refresh
- No manual token updates
- Always-live authentication

### RPC ID Translation (Case Study)
**Problem**: App uses opaque 6-digit RPC IDs instead of readable endpoints

**Solution**: Workflow + Match/Replace system

**Step 1: Extract Mapping**
```javascript
// Passive workflow to extract RPC->path mapping
const extractRPCMapping = () => {
  // Regex to find RPC ID patterns in JS
  const rpcPattern = /rpc_id:\s*["']([A-Z0-9]{6})["'][\s\S]{0,500}["']([^"']+)["']/g;
  
  // Store in environment variables
  // Format: RPC_ABC123 -> "/api/users/list"
};
```

**Step 2: Match and Replace**
```javascript
// Match RPC requests and add human-readable parameter
// Match: requests with RPC ID
// Replace: Add ?human_readable_path parameter
// Using convert workflow for dynamic replacement
```

**Result**: 
- Clear request understanding
- 20k bounty from previously hidden IDOR
- 15 minutes setup, massive ROI

## Advanced HTTPQL Usage

### Time-Based Filtering
```httpql
# Recent requests (last 5 minutes)
created > "5 minutes ago"

# Custom time ranges
created > "2025-01-01" AND created < "2025-01-02"

# Combined filters
created > "1 hour ago" AND status_code == 500
```

### Request Pattern Matching
```httpql
# Find specific endpoints
path =~ "/api/v[0-9]+/users"

# Error responses
status_code >= 400 AND status_code < 500

# Authentication failures
status_code == 401 OR status_code == 403
```

## Top-Level Navigation Highlighting

**Purpose**: Never lose context in HTTP history

**Setup**:
1. Go to Passive Workflows
2. Enable "Top Level Navigation Highlighter"
3. Uses SEC-FETCH headers for detection
4. Highlights main navigations in history

**Impact**: Life-changing for orientation in complex apps

## Convert Workflows

### Essential Encoding Workflows
```javascript
// Base64 encode/decode
function base64Encode(input) {
  return btoa(input);
}

// URL encode
function urlEncode(input) {
  return encodeURIComponent(input);
}

// JSON encode
function jsonEncode(input) {
  return JSON.stringify(input);
}
```

### Custom Workflows
```javascript
// Extract JWT payload
function extractJWTPayload(token) {
  const parts = token.split('.');
  return JSON.parse(atob(parts[1]));
}

// Generate test data
function generateTestData() {
  return {
    timestamp: Date.now(),
    random_id: Math.random().toString(36).substr(2, 9)
  };
}
```

## AI Integration Strategies

### Micro-Agent Development
**Start Simple**:
1. Single-purpose agents
2. Clear system prompts
3. Defined testing methodology
4. Success criteria

**Example Prompts**:
- "Test for IDOR in user management endpoints"
- "Analyze CORS configuration for misconfigurations"
- "Check for subdomain takeover vulnerabilities"

### Cost Management
- Use OpenRouter for model selection
- Gemini: Good balance of cost/performance
- GPT-4o: Higher performance, higher cost
- Monitor usage with built-in tracking

## Collaboration Workflows

### Sharing Request Collections
```bash
# Using Drop plugin
1. Select requests in HTTP history
2. Click Drop button
3. Choose collaborator
4. Instant encrypted transfer
```

### Team Testing Sessions
```bash
# Real-time collaboration
1. Share scope configuration
2. Sync environment variables
3. Exchange match/replace rules
4. Coordinate testing approaches
```

## Performance Optimization

### Workflow Efficiency
```javascript
// Batch operations
const batchProcess = (requests) => {
  return requests.map(processRequest);
};

// Caching results
const cache = new Map();
const cachedOperation = (input) => {
  if (cache.has(input)) return cache.get(input);
  const result = expensiveOperation(input);
  cache.set(input, result);
  return result;
};
```

### Memory Management
- Clear unused environment variables
- Archive old workflows
- Optimize regex patterns
- Monitor workflow execution time

## Troubleshooting

### Common Issues
- **Workflows not triggering**: Check passive vs active settings
- **Environment variables not updating**: Verify workflow permissions
- **AI agents not responding**: Check API keys and model availability
- **Drop transfers failing**: Verify PGP key configuration

### Debugging Techniques
```javascript
// Add logging to workflows
console.log('Processing request:', request.url);
console.log('Environment variables:', env.getAll());

// Test workflows manually
const testResult = workflow.test(input);
console.log('Test result:', testResult);
```

## Migration from Burp

### Feature Mapping
| Burp Feature | Caido Equivalent |
|--------------|------------------|
| Intruder | Workflows + AI agents |
| Repeater | Replay (enhanced) |
| Proxy history | HTTP history (with navigation highlighting) |
| Match/Replace | Match/Replace (with workflow replacement) |
| Extensions | Plugins (growing ecosystem) |

### Transition Strategy
1. **Week 1**: Use both tools side-by-side
2. **Week 2**: Migrate primary workflows to Caido
3. **Week 3**: Advanced features and automation
4. **Week 4**: Full migration with custom workflows

## Quick Reference Commands

### Essential Shortcuts
- `Ctrl+K`: Command palette
- `Win+Shift+N`: Quick note
- `Ctrl+Shift+F`: HTTPQL search
- `Ctrl+Shift+W`: New workflow

### HTTPQL Examples
```httpql
# Find all authentication failures
status_code == 401 OR status_code == 403

# Recent error responses
created > "1 hour ago" AND status_code >= 400

# Specific domain analysis
host == "api.example.com" AND method == "POST"
```

## Community Resources

### Getting Help
- Caido Discord: Active community support
- GitHub Discussions: Feature requests and bug reports
- CTBBP Discord: Workflow sharing and collaboration

### Sharing Workflows
- Export workflows for team use
- Contribute to community workflow library
- Document custom agents and prompts

---

*Based on Episode 138 (Caido Tools and Workflows) with real-world case studies and automation strategies*
