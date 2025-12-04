# DevTools Gadgets & Conditional Breakpoints Cheatsheet

## Purpose
Based on Episode 143 insights - leverage client-side gadgets and conditional breakpoints for advanced testing.

## Conditional Breakpoints Mastery

### Basic Conditional Breakpoints
```javascript
// Run code without breaking
(your_code_here), false

// Example: Force feature flags to true
(window.featureFlags = {all: true}), false

// Example: Override user permissions
(window.userPermissions = ['admin', 'superuser']), false
```

### Feature Flag Testing
```javascript
// Find feature flag parsing function and set breakpoint
// Condition: return true for all flags
Object.keys(window.featureFlags).forEach(key => window.featureFlags[key] = true), false

// Force specific feature on
window.featureFlags.newDashboard = true, false

// Log all feature flag checks
console.log('Feature flag checked:', arguments[0]), false
```

### Authentication Bypass
```javascript
// Skip authentication checks
(window.isAuthenticated = true), false

// Override user role
(window.currentUser = {role: 'admin', permissions: ['all']}), false

// Force token validation to pass
(window.validateToken = () => true), false
```

## Client-Side Gadgets Collection

### Path Traversal Gadgets
```javascript
// Extract path parameters from URLs
const paths = window.location.pathname.split('/');
const pathParams = paths.filter(p => p.includes('id') || p.includes('uuid'));

// Find all relative links that might be vulnerable
document.querySelectorAll('a[href^="../"], a[href^="./"]').forEach(a => console.log(a.href));
```

### Open Redirect Detection
```javascript
// Find redirect parameters
const urlParams = new URLSearchParams(window.location.search);
const redirectParams = ['redirect', 'return', 'next', 'url', 'callback'];
redirectParams.forEach(param => {
  if (urlParams.get(param)) console.log(`${param}: ${urlParams.get(param)}`);
});

// Monitor for dynamic redirects
const originalOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url) {
  if (url.includes('redirect') || url.includes('return')) {
    console.log('Redirect detected:', method, url);
  }
  return originalOpen.apply(this, arguments);
};
```

### XSS Injection Points
```javascript
// Find all places where user input is reflected
const inputs = document.querySelectorAll('input[type=text], textarea');
inputs.forEach(input => {
  input.addEventListener('input', e => {
    if (document.body.innerHTML.includes(e.target.value)) {
      console.log('Potential XSS reflection:', e.target);
    }
  });
});

// Monitor DOM changes for reflections
const observer = new MutationObserver(mutations => {
  mutations.forEach(mutation => {
    if (mutation.type === 'childList') {
      mutation.addedNodes.forEach(node => {
        if (node.innerHTML && node.innerHTML.includes(window.location.search)) {
          console.log('Search parameter reflected in DOM:', node);
        }
      });
    }
  });
});
observer.observe(document.body, {childList: true, subtree: true});
```

## Secondary Context Exploitation (Episode 143)

### Cross-Context Attack Patterns
```javascript
// Identify if access controls are frontend vs backend
// Set breakpoint before API calls and check if validation happens client-side

// Monitor organization/account ID usage
const originalFetch = window.fetch;
window.fetch = function(url, options) {
  if (url.includes('/api/') && options?.body) {
    const body = JSON.parse(options.body);
    if (body.orgId || body.accountId || body.tenantId) {
      console.log('Org/Account ID in request:', body);
    }
  }
  return originalFetch.apply(this, arguments);
};
```

### Same-Organization RBAC Testing
```javascript
// Override organization context to test same-org attacks
// Set breakpoint where org ID is extracted from URL/token
(window.currentOrg = 'target-org-id'), false

// Test if you can access other resources in same org
const testOrgAccess = (targetResourceId) => {
  // Override the resource ID while keeping your org ID
  window.resourceId = targetResourceId;
};
```

## WebSocket Monitoring

### WebSocket Message Interception
```javascript
// Hook WebSocket to monitor messages
const OriginalWebSocket = window.WebSocket;
window.WebSocket = function(url, protocols) {
  const ws = new OriginalWebSocket(url, protocols);
  
  ws.addEventListener('message', function(event) {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'authorization' || data.type === 'permissions') {
        console.log('Auth message:', data);
      }
    } catch (e) {
      // Handle non-JSON messages
    }
  });
  
  return ws;
};
```

### WebSocket Authentication Testing
```javascript
// Intercept WebSocket handshake
const originalSend = OriginalWebSocket.prototype.send;
OriginalWebSocket.prototype.send = function(data) {
  if (data.includes('auth') || data.includes('token')) {
    console.log('WebSocket auth data:', data);
  }
  return originalSend.apply(this, arguments);
};
```

## JavaScript Monitoring Setup

### High-Signal Pattern Detection
```javascript
// Monitor for new endpoint declarations
const endpointPatterns = [
  /\/api\/v[0-9]+\//,
  /\/graphql/,
  /\/ws\//,
  /\.json$/,
  /\/(users|clients|organizations|accounts)\//
];

// Scan for new routes in JavaScript
const scanForEndpoints = () => {
  const scripts = document.querySelectorAll('script');
  scripts.forEach(script => {
    if (script.src) return; // Skip external scripts
    
    const content = script.textContent;
    endpointPatterns.forEach(pattern => {
      const matches = content.match(pattern);
      if (matches) console.log('Potential endpoints:', matches);
    });
  });
};
```

### Permission and Role Monitoring
```javascript
// Track permission/role definitions
const permissionKeywords = [
  'is_admin', 'is_staff', 'is_internal', 'permissions', 'roles', 
  'entitlements', 'scopes', 'can_read', 'can_write', 'can_delete'
];

const monitorPermissions = () => {
  permissionKeywords.forEach(keyword => {
    if (window[keyword] !== undefined) {
      console.log(`Permission found: ${keyword}:`, window[keyword]);
    }
  });
  
  // Monitor localStorage/sessionStorage for permissions
  ['localStorage', 'sessionStorage'].forEach(storage => {
    Object.keys(window[storage]).forEach(key => {
      if (permissionKeywords.some(k => key.includes(k))) {
        console.log(`Storage permission: ${key}:`, window[storage][key]);
      }
    });
  });
};
```

## Advanced DevTools Techniques

### Network Request Modification
```javascript
// Intercept and modify network requests
const interceptRequests = () => {
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    this._method = method;
    this._url = url;
    return originalOpen.apply(this, arguments);
  };
  
  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(data) {
    if (this._url.includes('admin') && data) {
      const modifiedData = data.replace('"role":"user"', '"role":"admin"');
      console.log('Modified request data:', modifiedData);
      return originalSend.call(this, modifiedData);
    }
    return originalSend.apply(this, arguments);
  };
};
```

### DOM Mutation for Business Logic
```javascript
// Track UI changes that indicate business logic
const trackBusinessLogic = () => {
  const observer = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
      // Look for permission-based UI changes
      if (mutation.target.classList?.contains('admin-only') || 
          mutation.target.classList?.contains('staff-only')) {
        console.log('Permission-based UI change:', mutation.target);
      }
      
      // Track feature rollouts
      if (mutation.target.dataset?.feature) {
        console.log('Feature flag UI element:', mutation.target.dataset.feature);
      }
    });
  });
  
  observer.observe(document.body, {
    attributes: true,
    childList: true,
    subtree: true
  });
};
```

## Quick Reference Commands

### Essential Breakpoint Conditions
```javascript
// Force all boolean checks to true
(arguments[0] = true), false

// Log function arguments
console.log('Args:', arguments), false

// Modify return value
(return 'modified_value'), false

// Skip rate limiting
(window.lastRequest = 0), false
```

### One-Liner Gadgets
```javascript
// Extract all API endpoints from page
[...document.querySelectorAll('script')].map(s => s.textContent).join('').match(/\/api\/[^"\s]+/g)

// Find all form actions
[...document.querySelectorAll('form')].map(f => f.action)

// Extract all CSRF tokens
document.querySelector('[name*="csrf"]')?.value

// Get current user info
window.user || window.currentUser || window.auth?.user
```

## Troubleshooting

### Common Issues
- **Breakpoints not triggering**: Check if code is minified/obfuscated
- **Conditional breakpoints failing**: Ensure syntax is valid JavaScript
- **DevTools resetting**: Use "Preserve log" and "Disable cache"
- **Breakpoints disappearing**: Save as snippet for reuse

### Getting Help
- Use Chrome DevTools documentation
- Check CTBBP Discord for community gadgets
- Reference MDN for JavaScript APIs
- Test gadgets in console before using in breakpoints

---
*Based on Episode 143 (Client-Side Gadgets) and advanced DevTools techniques*
