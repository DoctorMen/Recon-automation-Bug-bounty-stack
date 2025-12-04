# Bug Bounty Prioritization Framework

## Purpose
Based on Episode 144 insights - avoid rabbit holes, focus on high-impact targets, and optimize decision-making for maximum ROI.

## The "Ghost of Justin" Priority Matrix

### Event/Live Hacking Prioritization
**Core Principle**: Focus on bonus targets and high-impact findings during timed events

#### Priority Levels
1. **CRITICAL** - Bonus targets with multipliers
2. **HIGH** - Program's known acceptance patterns  
3. **MEDIUM** - Interesting but secondary findings
4. **LOW** - Rabbit holes and complex research

#### Decision Framework
```
Is this a bonus target? → YES → CRITICAL PRIORITY
Is this what the program values? → YES → HIGH PRIORITY  
Is this interesting but time-consuming? → MAYBE → SAVE FOR LATER
Is this a deep research rabbit hole? → NO → POSTPONE
```

## Daily Hunting Prioritization

### Morning Setup (15 minutes)
- [ ] Review program bonuses and incentives
- [ ] Check recent program updates/new features
- [ ] Identify 1-2 primary targets for the session
- [ ] Set clear success criteria

### Session Decision Tree
```
Start with primary target → Found promising lead? → YES → Deep dive
                                      → NO → Switch to secondary target
                                      → Stuck → Move to next target
```

### Time Boxing Rules
- **30 minutes** on single endpoint without results → MOVE ON
- **1 hour** on research without clear path → DOCUMENT AND SWITCH
- **2 hours** maximum on complex chains → SAVE FOR LATER

## Program-Specific Prioritization

### Research Before Hunting
- [ ] Read program scope carefully
- [ ] Study recent accepted reports
- [ ] Identify program's preferred vulnerability types
- [ ] Note any special bonuses or incentives

### Target Selection Matrix
| Factor | Weight | Scoring |
|--------|--------|---------|
| Program maturity | 20% | High/Med/Low |
| Bonus availability | 25% | Yes/No |
| Your expertise | 20% | High/Med/Low |
| Recent changes | 15% | Yes/No |
| Competition level | 10% | High/Med/Low |
| Tool compatibility | 10% | High/Med/Low |

## AI-Assisted Prioritization (Episode 144)

### When to Use AI Tools
- **GOOD**: Rapid prototyping, initial reconnaissance
- **BAD**: Complex logic bugs, business logic flaws
- **BEST**: Pattern recognition across large datasets

### Model Selection Guide
- **GPT-4/o1**: Complex reasoning and business logic
- **Claude Code**: IDOR and access control patterns  
- **04-mini**: Path traversal and simple injections
- **Specialized**: Use specific models for specific vuln classes

### AI Workflow Integration
1. **Phase 1**: AI for broad reconnaissance
2. **Phase 2**: Manual validation of AI findings
3. **Phase 3**: Human creativity for complex chains
4. **Phase 4**: AI assistance for report writing

## Avoiding Analysis Paralysis

### Red Flags for Rabbit Holes
- Spending >30 minutes on single endpoint
- Research without clear testing path
- Complex setup without immediate payoff
- "Interesting but not exploitable" findings

### Recovery Strategies
1. **The 5-Minute Rule**: Can you test this in 5 minutes?
2. **The MVP Test**: What's the minimum viable proof?
3. **The Switch Prompt**: "Would Justin tell me to move on?"
4. **The Bonus Check**: Does this align with program priorities?

## Weekly Review Process

### Sunday Planning (30 minutes)
- [ ] Review last week's findings and ROI
- [ ] Identify successful patterns
- [ ] Plan next week's focus areas
- [ ] Update program priority matrix

### Daily Standup (5 minutes)
- [ ] What's the primary target today?
- [ ] What are the success criteria?
- [ ] What's the time limit for rabbit holes?
- [ ] When will I review and pivot?

## Collaboration Prioritization

### When to Collaborate
- **IMMEDIATE**: Critical findings needing quick validation
- **PLANNED**: Complex research projects
- **OPPORTUNIC**: When you hit a wall and need fresh eyes

### Effective Collaboration Habits
- Share notes before asking for help
- Clearly state what you've tried
- Define the specific problem you need help with
- Set time limits for collaboration sessions

## Mental Models for Quick Decisions

### The "Is This a Bug?" Filter
1. Can I demonstrate impact?
2. Is this in scope?
3. Can I reproduce this reliably?
4. Is this worth the reporting time?

### The "Should I Continue?" Test
1. Have I found anything in 30 minutes?
2. Do I have a clear path forward?
3. Is this aligned with program priorities?
4. Would a time-boxed session help?

## Tool-Based Prioritization

### Automated Triage Setup
- [ ] Configure Burp to highlight status codes
- [ ] Set up automated parameter extraction
- [ ] Use scripts to identify high-signal patterns
- [ ] Implement quick filtering for interesting responses

### Efficiency Metrics
Track these weekly:
- **Bugs per hour**: Overall efficiency
- **Critical bugs per session**: High-impact focus
- **Time to first finding**: Session startup efficiency
- **Rabbit hole time**: Wasted effort tracking

---
*Based on Episode 144 insights from Busfactor and Monke, with the "Ghost of Justin" prioritization methodology*
