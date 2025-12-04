<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->

# Team Organization Taxonomy

This document provides a comprehensive taxonomy of teams and departments, including common aliases and alternative names used across organizations. This taxonomy helps standardize team identification for bug bounty programs, security assessments, and cross-functional collaboration.

---

## Product & Strategy

### Product Management
- **Aliases**: Product / PM / Product Strategy / Product Leadership

### Business Strategy
- **Aliases**: Strategy / Corporate Strategy / BizOps / Business Operations

### Corporate Development
- **Aliases**: Corp Dev / M&A / Strategic Partnerships

---

## Engineering

### Frontend Engineering
- **Aliases**: Front-End / Web Engineering / UI Engineering / Client Engineering / Web UI

### Mobile Engineering
- **Aliases**: Mobile Apps / iOS Team / Android Team / Native Apps / Mobile Client

### Backend Engineering
- **Aliases**: Back-End / Services Engineering / API Engineering / Service Platform / Core Services

### Full-Stack Engineering
- **Aliases**: Full Stack / Feature Teams / Feature Squads / Product Squads / Cross-Functional Squads / Pods

---

## Platform & Infrastructure

### Platform Engineering
- **Aliases**: Core Platform / Developer Platform / Internal Platform / Platform Services

### DevOps
- **Aliases**: SRE / Site Reliability Engineering / Production Engineering / Reliability Engineering / Infra Ops

### Developer Experience
- **Aliases**: Developer Productivity / DX / Dev Productivity / Developer Tools / Dev Tools

### Release Engineering
- **Aliases**: Build & Release / Build Engineering / Release Management / Release Ops

---

## Data & Analytics

### Data Engineering
- **Aliases**: Data Platform / Data Infra / Data Infrastructure

### Analytics
- **Aliases**: Product Analytics / Data Analytics / BI / Business Intelligence / Insights / Decision Science

### Data Science
- **Aliases**: Applied Data Science / Quant / Decision Science (sometimes overlaps with Analytics)

### ML Engineering
- **Aliases**: Machine Learning Engineering / Applied ML / AI Engineering / AI Platform / ML Platform

### Experimentation Platform
- **Aliases**: Experimentation & Personalization / A/B Testing Platform / Growth Platform / Growth Engineering

---

## Security

### Product Security
- **Aliases**: Application Security / AppSec / Product & Platform Security / Software Security

### Offensive Security
- **Aliases**: Red Team / Red Teaming / Penetration Testing / Pentest / Adversary Simulation

### Bug Bounty
- **Aliases**: Vulnerability Management / Product Security Response / PSIRT / VRM (Vuln & Risk Management)

### Cloud Security
- **Aliases**: Infrastructure Security / Cloud & Platform Security / Cloud & Infra Sec

### Identity & Access Management
- **Aliases**: IAM / Identity Platform / AuthN/AuthZ / Access Management

### Security Operations Center
- **Aliases**: SOC / Security Operations / Detection & Response / Blue Team

### Governance, Risk & Compliance
- **Aliases**: GRC / Security Governance / Risk & Compliance / Trust & Security

### Privacy Engineering
- **Aliases**: Data Privacy / Privacy & Data Protection / Privacy & Compliance

---

## Quality & Performance

### Quality Assurance
- **Aliases**: QA / Test Engineering / Software Testing / SDET / Quality Engineering

### Performance Engineering
- **Aliases**: Performance & Load Testing / Scalability Engineering / Performance & Reliability

---

## Design & Research

### UX Design
- **Aliases**: Product Design / Experience Design / Interaction Design / UI/UX

### UX Research
- **Aliases**: User Research / Design Research / Customer Research

### Content Design
- **Aliases**: UX Writing / Content Strategy / Product Content

---

## Customer & Support

### Customer Support
- **Aliases**: Customer Service / Support / Customer Experience (CX)

### Support Engineering
- **Aliases**: Support Tools / Support Tooling / Internal Tools for Support / Agent Tools

### Solutions Engineering
- **Aliases**: Sales Engineering / Field Engineering / Customer Engineering / Solutions Architecture

---

## Business Operations

### Legal
- **Aliases**: Legal Counsel / Product Counsel / Commercial Legal / Privacy & Product Legal

### Marketing
- **Aliases**: Growth / Growth Marketing / Demand Generation / Demand Gen / Product Marketing / Performance Marketing

### Revenue Operations
- **Aliases**: RevOps / Sales Operations / GTM Operations / Commercial Operations

---

## Usage in Bug Bounty Context

This taxonomy helps identify:

1. **Scope Ownership**: Determine which team owns specific attack surfaces
2. **Escalation Paths**: Route vulnerabilities to the correct security team
3. **Cross-Team Coordination**: Identify stakeholders for multi-component vulnerabilities
4. **Program Contacts**: Match bug bounty program contacts to team functions

### Security Team Mapping for Bug Bounty

| Vulnerability Type | Primary Team | Secondary Team |
|-------------------|--------------|----------------|
| Web Application | Product Security | Frontend Engineering |
| API Security | Product Security | Backend Engineering |
| Mobile App | Product Security | Mobile Engineering |
| Cloud/Infra | Cloud Security | Platform Engineering |
| Authentication | IAM | Product Security |
| Data Exposure | Privacy Engineering | Data Engineering |
| Red Team Findings | Offensive Security | SOC |
| Compliance Issues | GRC | Privacy Engineering |

---

## Integration with Agent System

These team taxonomies map to the agent system defined in `agents.json`:

- **Strategist Agent** → Aligns with Product Management, Business Strategy
- **Executor Agent** → Aligns with Full-Stack Engineering, DevOps
- **Composer 1 (Automation)** → Aligns with Platform Engineering, Release Engineering
- **Composer 2 (Optimization)** → Aligns with Performance Engineering, Data Engineering
- **Composer 3 (Documentation)** → Aligns with Content Design, UX Writing
- **Composer 4 (CI/CD & Security)** → Aligns with DevOps, Product Security
- **Divergent Thinker** → Aligns with Offensive Security, Red Team

---

*Last updated: 2025*
