# Hypothesis Testing Log

## Purpose
Structured manual testing for IDOR/BOLA vulnerabilities based on Episode 145 methodology.

## Target Information
- **Program**: 
- **Target**: 
- **Date**: 
- **Tester**: 
- **Test Account**: 

## Test Session
- **Start Time**: 
- **End Time**: 
- **Duration**: 

## Hypothesis Template

### Hypothesis #[Number]
**Date**: [YYYY-MM-DD]
**Endpoint**: [METHOD] [path]
**Test Type**: [IDOR/BOLA/Authorization Bypass]

#### Hypothesis Statement
*I believe that by [action] on parameter [parameter_name], I can [expected outcome] because [reasoning].*

#### Test Setup
- **Base Request**: 
```http
[Paste clean request here]
```
- **Modified Request**: 
```http
[Paste modified request here]
```
- **Parameters Tested**:
  - [param1]: [original_value] → [test_value]
  - [param2]: [original_value] → [test_value]

#### Test Execution
- **Step 1**: [Action taken]
- **Step 2**: [Action taken]
- **Step 3**: [Action taken]

#### Results
- **Status Code**: [xxx]
- **Response Body**: [Key findings from response]
- **Response Time**: [ms]
- **Headers**: [Interesting headers]

#### Analysis
**Success Criteria Met**: [Yes/No]
**Why it worked/failed**: [Technical explanation]
**Impact Assessment**: [Critical/High/Medium/Low]
**Next Steps**: [What to test next based on this result]

## IDOR/BOLA Specific Tests

### Same-Tenant Tests
- [ ] Test user-to-user access within same tenant
- [ ] Test client-to-client access within same organization
- [ ] Test privilege escalation within same account

### Cross-Tenant Tests
- [ ] Test access to other tenant's resources
- [ ] Test tenant ID manipulation
- [ ] Test organization boundary bypass

### Parameter Manipulation
- [ ] user_id parameter
- [ ] client_id parameter
- [ ] organization_id parameter
- [ ] tenant_id parameter
- [ ] account_id parameter

### Authorization Bypass
- [ ] Remove authentication headers
- [ ] Use lower-privilege tokens
- [ ] Test expired tokens
- [ ] Test malformed tokens

## Error Oracle Documentation
Based on Episode 145 - Track these for future exploitation:

### Discovered Error Oracles
- **Endpoint**: [URL]
- **Trigger**: [What causes the error]
- **Information Disclosed**: 
  - [Internal hostnames]
  - [Authentication headers]
  - [Database information]
  - [Service details]
- **Potential Use**: [How this could be exploited later]

## High Signal Areas
Track these for quick reference:

### Sensitive Endpoints
- [ ] User management
- [ ] Client configuration
- [ ] Organization settings
- [ ] Authorization checks

### Interesting Parameters
- [ ] ID parameters that accept UUIDs
- [ ] Tenant identifiers
- [ ] Permission flags
- [ ] Feature toggles

## Gadgets and Attack Chains
Document reusable components:

### Client-Side Gadgets
- [ ] Path traversal in parameters
- [ ] Open redirect functionality
- [ ] XSS injection points
- [ ] CSRF token bypass

### API Gadgets
- [ ] Authentication bypass
- [ ] Privilege escalation
- [ ] Data exposure
- [ ] Business logic flaws

## Attack Chain Development
Combine multiple findings:

### Chain #[Number]
**Goal**: [What you're trying to achieve]
**Components**:
1. [Gadget 1]
2. [Gadget 2]
3. [Gadget 3]

**Execution Steps**:
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Status**: [Planning/In Progress/Successful/Failed]

## Collaboration Notes
For sharing with team members:

### Key Findings
- **Most Critical**: [Finding]
- **Easiest to Reproduce**: [Finding]
- **Best for Demonstration**: [Finding]

### Unfinished Tests
- [ ] Test that needs more investigation
- [ ] Promising endpoint that needs deeper analysis
- [ ] Attack chain that needs additional gadgets

## Daily Summary
**Tests Run**: [Number]
**Successful**: [Number]
**Failed**: [Number]
**Interesting Findings**: [Number]
**Time Spent**: [Hours]

## Lessons Learned
- [Technique that worked well]
- [Common patterns discovered]
- [Tools that were most useful]
- [Approaches to avoid]

## Next Session Plan
- [Priority 1 test]
- [Priority 2 test]
- [Research needed]
- [Tools to prepare]

---
*Template based on Episode 145 (Gr3pme's Note Taking Methodology) and Episode 147 (Workflow Tips)*
