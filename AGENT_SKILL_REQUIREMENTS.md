# Agent Skill Requirements

This document defines the formal skill requirements, competencies, and qualifications for each agent role in the Bug Bounty Automation Stack.

---

## 📋 Role Overview

| Agent | Level | Primary Domain | Experience Required |
|-------|-------|----------------|---------------------|
| Strategist | Senior/Staff | Product & Strategy | 5+ years |
| Executor | Mid-Senior | Engineering & DevOps | 3+ years |
| Composer 1 | Mid-Senior | Platform Engineering | 3+ years |
| Composer 2 | Mid-Senior | Performance Engineering | 3+ years |
| Composer 3 | Mid | Content & Analytics | 2+ years |
| Composer 4 | Senior | Security Operations | 4+ years |
| Divergent Thinker | Staff/Principal | Offensive Security | 6+ years |

---

## 🎯 Strategist

**Role:** Plans overall workflow, decides task sequencing, verifies logic, and optimizes bug bounty automation direction.

**Team Alignment:** Product Management, Business Strategy

### Required Skills

**Technical Skills:**
- [ ] Bug bounty program management
- [ ] Security assessment methodology design
- [ ] Risk prioritization frameworks
- [ ] Automation workflow design
- [ ] Python scripting (intermediate)
- [ ] API security fundamentals

**Business Skills:**
- [ ] Strategic planning and roadmapping
- [ ] ROI analysis and optimization
- [ ] Stakeholder communication
- [ ] Resource allocation
- [ ] Vendor/program evaluation

**Leadership Skills:**
- [ ] Cross-functional coordination
- [ ] Decision-making under uncertainty
- [ ] Conflict resolution
- [ ] Mentorship capability

### Certifications (Preferred)
- OSCP or equivalent offensive certification
- PMP or Agile certification
- CISSP or CISM (for enterprise contexts)

### Performance Metrics
- Vulnerability discovery rate improvement
- False positive reduction percentage
- Time-to-submission optimization
- Team coordination effectiveness

---

## ⚡ Executor

**Role:** Executes scripts, validates syntax, performs git commits, runs local tests, and handles recon.sh deployments.

**Team Alignment:** Full-Stack Engineering, DevOps

### Required Skills

**Technical Skills:**
- [ ] Python (advanced)
- [ ] Bash scripting (advanced)
- [ ] Git version control (expert)
- [ ] Linux system administration
- [ ] Docker containerization
- [ ] CI/CD pipeline management
- [ ] Security tool proficiency (Nuclei, httpx, subfinder)

**DevOps Skills:**
- [ ] Infrastructure as Code
- [ ] Monitoring and alerting
- [ ] Log management
- [ ] Deployment automation
- [ ] Environment management

**Security Skills:**
- [ ] Scope validation implementation
- [ ] Authorization system management
- [ ] Secrets management
- [ ] Audit logging

### Certifications (Preferred)
- AWS/GCP/Azure certifications
- Kubernetes certifications (CKA/CKAD)
- Linux certifications (RHCE/LFCS)

### Performance Metrics
- Deployment success rate
- Script reliability percentage
- Mean time to recovery (MTTR)
- Automation coverage

---

## 🔧 Composer 1 — Automation Engineer

**Role:** Maintains, updates, and hardens recon.sh, auto_runner.sh, and post_scan scripts.

**Team Alignment:** Platform Engineering, Release Engineering

### Required Skills

**Technical Skills:**
- [ ] Shell scripting (expert)
- [ ] Python automation (advanced)
- [ ] Security tool integration
- [ ] Error handling and resilience
- [ ] Idempotent script design
- [ ] Cross-platform compatibility

**Engineering Practices:**
- [ ] Code review methodology
- [ ] Testing automation
- [ ] Documentation standards
- [ ] Version control best practices
- [ ] Dependency management

**Security Skills:**
- [ ] Input validation
- [ ] Secure coding practices
- [ ] Scope enforcement implementation

### Certifications (Preferred)
- Security+ or equivalent
- Python certifications
- DevOps certifications

### Performance Metrics
- Script uptime and reliability
- Bug fix turnaround time
- Code coverage percentage
- Documentation completeness

---

## 🚀 Composer 2 — Parallelization & Optimization

**Role:** Implements concurrent recon runs, optimizes threading logic, and resource allocation for maximum throughput.

**Team Alignment:** Performance Engineering, Data Engineering

### Required Skills

**Technical Skills:**
- [ ] Concurrent programming (advanced)
- [ ] Python asyncio and threading
- [ ] Performance profiling
- [ ] Memory optimization
- [ ] Network optimization
- [ ] Database optimization

**Performance Engineering:**
- [ ] Load testing
- [ ] Bottleneck identification
- [ ] Capacity planning
- [ ] Scalability design
- [ ] Resource monitoring

**Security Skills:**
- [ ] Rate limiting implementation
- [ ] Resource exhaustion prevention
- [ ] Distributed system security

### Certifications (Preferred)
- Performance engineering certifications
- Cloud architecture certifications
- Data engineering certifications

### Performance Metrics
- Throughput improvement percentage
- Resource utilization efficiency
- Latency reduction metrics
- Scalability benchmarks

---

## 📝 Composer 3 — Documentation & Reporting

**Role:** Auto-updates README.md, CHANGELOG.md, and summary.md. Generates post-run analytics and visual summaries.

**Team Alignment:** Content Design, Analytics

### Required Skills

**Technical Skills:**
- [ ] Markdown and documentation tools
- [ ] Python report generation
- [ ] Data visualization
- [ ] Template engines
- [ ] HTML/CSS (intermediate)
- [ ] JSON/YAML processing

**Content Skills:**
- [ ] Technical writing
- [ ] Executive summary creation
- [ ] Diagram and visualization creation
- [ ] Compliance documentation
- [ ] User-facing documentation

**Analytics Skills:**
- [ ] Data aggregation
- [ ] Metrics calculation
- [ ] Trend analysis
- [ ] Dashboard creation

### Certifications (Preferred)
- Technical writing certifications
- Data analytics certifications
- Visualization tool certifications

### Performance Metrics
- Documentation accuracy
- Report generation time
- User feedback scores
- Compliance audit pass rate

---

## 🔒 Composer 4 — CI/CD & Security Ops

**Role:** Creates GitHub workflows, Docker integration, and environment hardening (YAML + GitHub Actions).

**Team Alignment:** DevOps, Product Security

### Required Skills

**Technical Skills:**
- [ ] GitHub Actions (expert)
- [ ] Docker and containerization (advanced)
- [ ] YAML configuration
- [ ] Secret management
- [ ] Environment hardening
- [ ] Security scanning integration

**Security Operations:**
- [ ] Vulnerability scanning
- [ ] Compliance automation
- [ ] Security monitoring
- [ ] Incident response procedures
- [ ] Access control implementation

**DevSecOps:**
- [ ] Shift-left security
- [ ] SAST/DAST integration
- [ ] Container security
- [ ] Supply chain security

### Certifications (Required)
- Security+ or SSCP minimum
- AWS/GCP Security Specialty (preferred)
- Container security certifications

### Performance Metrics
- Pipeline security score
- Vulnerability remediation time
- Compliance automation coverage
- Security incident response time

---

## 🧠 Divergent Thinker

**Role:** Generates creative exploration paths using 7 thinking modes to discover novel vulnerabilities and alternative attack approaches.

**Team Alignment:** Offensive Security, Bug Bounty

### Required Skills

**Technical Skills:**
- [ ] Penetration testing (expert)
- [ ] Web application security (expert)
- [ ] API security testing
- [ ] Mobile security testing
- [ ] Cloud security assessment
- [ ] Smart contract auditing (preferred)

**Offensive Skills:**
- [ ] Vulnerability chaining
- [ ] Custom exploit development
- [ ] Bypass techniques
- [ ] Creative attack vectors
- [ ] Business logic flaw discovery

**Thinking Modes:**
- [ ] Lateral thinking
- [ ] Parallel processing
- [ ] Associative reasoning
- [ ] Generative ideation
- [ ] Combinatorial analysis
- [ ] Perspective shifting
- [ ] Constraint-free exploration

### Certifications (Required)
- OSCP or OSWE
- OSCE or OSEP (preferred)
- Bug bounty track record (Hall of Fame entries)

### Performance Metrics
- Novel vulnerability discovery rate
- Bounty earnings/value
- Unique finding percentage
- Accepted submission rate

---

## 📊 Skill Assessment Matrix

### Technical Proficiency Levels

| Level | Definition | Experience |
|-------|------------|------------|
| Basic | Fundamental understanding | 0-1 years |
| Intermediate | Independent work capability | 1-3 years |
| Advanced | Complex problem solving | 3-5 years |
| Expert | System design and leadership | 5+ years |

### Competency Framework

```
Level 1 (Entry):     Can execute tasks with guidance
Level 2 (Junior):    Can execute tasks independently
Level 3 (Mid):       Can design solutions and mentor
Level 4 (Senior):    Can architect systems and lead teams
Level 5 (Staff):     Can define strategy and influence org
Level 6 (Principal): Can drive industry-level innovation
```

---

## 🎓 Training & Development Path

### Onboarding (All Roles)
1. Repository structure overview
2. Safety system training
3. Legal authorization system
4. Scope enforcement procedures
5. Audit logging requirements

### Role-Specific Training

**Strategist Path:**
- Business analysis fundamentals → Security program management → Strategic leadership

**Executor Path:**
- DevOps fundamentals → Security automation → Platform engineering

**Composer Path:**
- Specialized domain training → Integration skills → System optimization

**Divergent Thinker Path:**
- Web security → Advanced exploitation → Creative methodology → Innovation leadership

---

## 📋 Hiring Checklist

For each role, verify:

- [ ] Technical skill requirements met
- [ ] Domain experience validated
- [ ] Security clearance (if applicable)
- [ ] Background check completed
- [ ] Certification verification
- [ ] Reference checks completed
- [ ] Cultural fit assessment
- [ ] Trial project completion

---

*Last Updated: 2025*
*Document Owner: HR & Talent Acquisition*
