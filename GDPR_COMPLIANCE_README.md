# 🇪🇺 GDPR COMPLIANCE SYSTEM
## European Cybersecurity & Data Protection Compliance

**Copyright © 2025 DoctorMen. All Rights Reserved.**

---

## ⚠️ CRITICAL: EU/EEA OPERATIONS

**If you operate in the European Union or European Economic Area, you MUST use this GDPR-compliant system.**

**Standard US authorization system is NOT sufficient for European operations.**

---

## 🎯 WHAT THIS SYSTEM PROVIDES

### **Full GDPR Compliance (EU 2016/679)**
- ✅ Article 6: Lawful basis for processing
- ✅ Article 7: Conditions for consent
- ✅ Articles 13-14: Information to data subjects
- ✅ Articles 15-22: Data subject rights (access, erasure, portability, etc.)
- ✅ Article 25: Data protection by design and default
- ✅ Article 30: Records of processing activities
- ✅ Article 32: Security of processing
- ✅ Articles 33-34: Data breach notification (72-hour rule)
- ✅ Article 35: Data Protection Impact Assessment (DPIA)
- ✅ Articles 44-50: International data transfers

### **NIS2 Directive Compliance (EU 2022/2555)**
- ✅ Security measures for critical entities
- ✅ Incident reporting requirements
- ✅ CSIRT (Computer Security Incident Response Team) integration
- ✅ Supply chain security

### **Additional EU Regulations**
- ✅ Cybersecurity Act (EU 2019/881)
- ✅ ePrivacy Directive (2002/58/EC)
- ✅ DORA (Digital Operational Resilience Act - EU 2022/2554)

---

## 📁 SYSTEM COMPONENTS

### **1. LEGAL_AUTHORIZATION_SYSTEM_GDPR.py**
**Enhanced authorization system with GDPR compliance**

**New Features vs US System:**
- Lawful basis validation (6 legal bases)
- Explicit consent recording
- Data Protection Officer (DPO) requirements
- Data categories declaration
- Retention period enforcement (max 7 years)
- Cross-border transfer safeguards
- Data subject rights acknowledgment
- DPIA integration
- NIS2 compliance for critical entities
- Consent log (demonstrable consent)

**Usage:**
```python
from LEGAL_AUTHORIZATION_SYSTEM_GDPR import GDPRLegalAuthorizationShield

shield = GDPRLegalAuthorizationShield()
authorized, reason, auth_data = shield.check_authorization('example.com')

if authorized:
    # Proceed with scanning
    pass
else:
    # Blocked - GDPR requirements not met
    print(reason)
```

---

### **2. CREATE_GDPR_AUTHORIZATION.py**
**Authorization template creator for EU operations**

**Usage:**
```bash
python3 CREATE_GDPR_AUTHORIZATION.py \
  --target example.com \
  --client "Client Corp" \
  --country "France"
```

**Creates:** `./authorizations/example_com_gdpr_authorization.json`

**Required Fields (29 GDPR-specific):**
- Basic: client, target, scope, dates
- GDPR Article 6: lawful_basis, consent_date
- GDPR Article 13: data_controller, DPO contact
- GDPR Article 30: data_categories, processing purpose
- GDPR Article 5: retention_period, deletion_date
- GDPR Arts 15-22: data_subject_rights
- GDPR Arts 44-50: cross_border_transfer
- GDPR Article 35: DPIA reference
- GDPR Article 32: security_measures
- NIS2: critical_entity, incident_response, CSIRT

---

### **3. CREATE_DPIA_TEMPLATE.py**
**Data Protection Impact Assessment creator**

**Required by GDPR Article 35 for:**
- Security testing (systematic monitoring)
- Large scale processing of personal data
- High-risk processing operations

**Usage:**
```bash
python3 CREATE_DPIA_TEMPLATE.py \
  --target example.com \
  --client "Client Corp"
```

**Creates:** `./authorizations/dpia_assessments/DPIA-[target]-[date].json`

**DPIA Sections (Per Article 35(7)):**
1. Description of processing operations
2. Necessity and proportionality assessment
3. Risk assessment (confidentiality, integrity, availability)
4. Risk mitigation measures
5. Technical and organizational measures
6. DPO consultation
7. Data subject consultation (if appropriate)
8. Supervisory authority consultation (if high risk)
9. Approval and review schedule

---

### **4. VERIFY_GDPR_COMPLIANCE.py**
**Pre-scan GDPR compliance checker**

**Usage:**
```bash
# Verify authorization + DPIA
python3 VERIFY_GDPR_COMPLIANCE.py \
  ./authorizations/example_com_gdpr_authorization.json

# Verify DPIA only
python3 VERIFY_GDPR_COMPLIANCE.py \
  --dpia-only ./authorizations/dpia_assessments/DPIA-example-20251104.json
```

**Checks:**
- ✅ All required GDPR fields present
- ✅ Lawful basis valid
- ✅ Consent not expired (< 2 years)
- ✅ Time window valid
- ✅ DPO contact complete
- ✅ Data categories declared
- ✅ Retention period reasonable
- ✅ Cross-border safeguards (if applicable)
- ✅ DPIA completed (if required)
- ✅ Signature present

---

## 🚀 COMPLETE WORKFLOW

### **Step 1: Get Client Authorization**

**Required Documents:**
1. **Written authorization** (email or contract)
2. **Privacy notice** to data subjects
3. **DPO contact** (if client has DPO)
4. **Cross-border transfer agreement** (if data leaves EU/EEA)

**Best Practices:**
- Use signed contract (not just email)
- Include data processing agreement (DPA)
- Specify lawful basis clearly
- Get explicit consent if relying on consent basis

---

### **Step 2: Create Authorization File**

```bash
# Create template
python3 CREATE_GDPR_AUTHORIZATION.py \
  --target clientsite.com \
  --client "Client Corp" \
  --country "France"

# File created: ./authorizations/clientsite_com_gdpr_authorization.json
```

---

### **Step 3: Create DPIA**

```bash
# Create DPIA template
python3 CREATE_DPIA_TEMPLATE.py \
  --target clientsite.com \
  --client "Client Corp"

# File created: ./authorizations/dpia_assessments/DPIA-clientsite_com-20251104.json
```

---

### **Step 4: Complete DPIA**

```bash
# Edit DPIA
nano ./authorizations/dpia_assessments/DPIA-clientsite_com-20251104.json

# Required steps:
# 1. Review all risk assessments
# 2. Document mitigation measures
# 3. Consult DPO (if you have one)
# 4. Get approval from management
# 5. Set "dpia_complete": true
# 6. Set "processing_may_proceed": true
```

---

### **Step 5: Edit Authorization File**

```bash
# Edit authorization
nano ./authorizations/clientsite_com_gdpr_authorization.json

# Required edits:
# 1. Set gdpr_lawful_basis (consent, contract, etc.)
# 2. Add data_controller information
# 3. Add gdpr_dpo_contact (name, email, phone)
# 4. Review gdpr_data_categories
# 5. Set gdpr_retention_period (days)
# 6. Configure cross_border_transfer settings
# 7. Set gdpr_dpia_reference (DPIA ID)
# 8. Set gdpr_dpia_completed: true
# 9. Add signature_date after client signs
# 10. Calculate and add signature_hash
```

---

### **Step 6: Verify Compliance**

```bash
# Verify everything is correct
python3 VERIFY_GDPR_COMPLIANCE.py \
  ./authorizations/clientsite_com_gdpr_authorization.json

# Output:
# ✅ Authorization file: VALID
# ✅ DPIA: VALID
# ✅ All GDPR requirements: MET
```

---

### **Step 7: Run Authorized Scan**

```bash
# Using SENTINEL Agent (with GDPR mode)
python3 SENTINEL_AGENT.py clientsite.com --tier basic --gdpr

# Using main pipeline
echo "clientsite.com" >> targets.txt
python3 run_pipeline.py --gdpr

# Manual script with wrapper
./LEGAL_SHIELD_WRAPPER_GDPR.sh clientsite.com ./your_script.sh
```

---

## 📋 AUTHORIZATION FILE EXAMPLE

```json
{
  "client_name": "Example Corp SAS",
  "target": "example.fr",
  "scope": ["example.fr", "*.example.fr", "api.example.fr"],
  "start_date": "2025-11-04T00:00:00",
  "end_date": "2025-12-04T23:59:59",
  
  "authorized_by": "Marie Dupont",
  "authorized_by_email": "marie.dupont@example.fr",
  "authorized_by_title": "RSSI (Chief Information Security Officer)",
  "contact_emergency": "+33-1-23-45-67-89",
  
  "gdpr_lawful_basis": "contract",
  "gdpr_consent_date": "2025-11-01T10:00:00",
  "gdpr_consent_method": "written_agreement",
  "gdpr_consent_withdrawal_method": "email",
  
  "gdpr_data_controller": {
    "name": "Example Corp SAS",
    "address": "123 Rue de la Paix, 75001 Paris, France",
    "country": "France",
    "email": "dpo@example.fr",
    "phone": "+33-1-23-45-67-89"
  },
  
  "gdpr_dpo_contact": {
    "name": "Jean Martin",
    "email": "dpo@example.fr",
    "phone": "+33-1-23-45-67-90"
  },
  
  "gdpr_data_categories": [
    "system_logs",
    "network_traffic_metadata",
    "vulnerability_scan_results"
  ],
  
  "gdpr_retention_period": 365,
  "gdpr_deletion_date": "2026-12-04T00:00:00",
  
  "gdpr_subject_rights_acknowledged": true,
  
  "gdpr_cross_border_transfer": {
    "transfers_data_outside_eea": false,
    "destination_countries": [],
    "adequacy_decision": false,
    "safeguards": ""
  },
  
  "requires_dpia": true,
  "gdpr_dpia_reference": "DPIA-example_fr-20251104",
  "gdpr_dpia_completed": true,
  
  "nis2_critical_entity": false,
  "eu_member_state": "France",
  
  "signature_date": "2025-11-01T14:30:00",
  "signature_method": "electronic_signature",
  "signature_hash": "a3f5c9d2e4b8f1a6c3d7e9f2b4a8c5d1e7f9b3a6c8d2e5f1b7a9c4d6e8f3b5a7"
}
```

---

## ⚖️ LAWFUL BASIS OPTIONS

**GDPR Article 6 provides 6 legal bases:**

### **1. Consent (gdpr_lawful_basis: "consent")**
- ✅ Use when: Client explicitly agrees to testing
- ⚠️  Requirements: Must be freely given, specific, informed, unambiguous
- ⚠️  Must provide: Easy withdrawal mechanism
- **Example:** "We consent to security testing of our systems"

### **2. Contract (gdpr_lawful_basis: "contract")**
- ✅ Use when: Testing is part of service contract
- ✅ Most common for security assessments
- **Example:** "Security assessment as per SOW dated [date]"

### **3. Legal Obligation (gdpr_lawful_basis: "legal_obligation")**
- ✅ Use when: Testing required by law/regulation
- **Example:** PCI-DSS compliance testing, NIS2 requirements

### **4. Vital Interests (gdpr_lawful_basis: "vital_interests")**
- ⚠️  Rarely applicable
- Use when: Testing necessary to protect life/safety

### **5. Public Task (gdpr_lawful_basis: "public_task")**
- ⚠️  Only for public authorities
- Use when: Testing for public interest

### **6. Legitimate Interests (gdpr_lawful_basis: "legitimate_interests")**
- ✅ Use when: Testing necessary for security purposes
- ⚠️  Requires: Balancing test (interests vs data subject rights)
- **Example:** "Necessary to ensure security of our services"

**⚠️  WARNING:** Incorrect lawful basis = GDPR violation. Consult legal counsel if unsure.

---

## 🔍 DATA PROTECTION IMPACT ASSESSMENT (DPIA)

### **When DPIA is Required (Article 35):**

**ALWAYS Required:**
- ✅ Security testing of large-scale systems
- ✅ Systematic monitoring of systems
- ✅ Processing of special category data (health, biometric, etc.)

**Usually Required:**
- ✅ Automated vulnerability scanning at scale
- ✅ Penetration testing of production systems
- ✅ Testing that accesses personal data

**NOT Required:**
- ❌ Testing in isolated dev environment (no personal data)
- ❌ Small-scale, low-risk testing
- ❌ Testing already covered by previous DPIA

**Tip:** When in doubt, complete a DPIA. It's better to over-comply than under-comply.

---

## 🌍 CROSS-BORDER DATA TRANSFERS

### **If Data Leaves EU/EEA:**

**Options for Compliance:**

**1. Adequacy Decision (Article 45)**
- EU has deemed country provides adequate protection
- **Countries with adequacy:** UK, Switzerland, Japan, Canada (commercial), Israel, etc.
- **Check current list:** https://ec.europa.eu/info/law/law-topic/data-protection/international-dimension-data-protection/adequacy-decisions

**2. Standard Contractual Clauses (SCCs)**
- EU-approved contract templates
- **Download:** https://commission.europa.eu/publications/standard-contractual-clauses-controllers-and-processors-eueea_en
- Set: `"safeguards": "standard_contractual_clauses"`

**3. Binding Corporate Rules (BCRs)**
- For multinational companies
- Requires DPA approval

**4. US Data Privacy Framework (DPF)**
- Replaces Privacy Shield
- For US companies certified under DPF
- Set: `"us_data_privacy_framework": true`
- **Check certification:** https://www.dataprivacyframework.gov/

**⚠️  CRITICAL:** Unauthorized transfer to third countries = GDPR violation (fines up to €20M or 4% global revenue)

---

## 📞 DATA PROTECTION AUTHORITIES (DPAs)

### **EU Member State DPAs:**

**France - CNIL**
- Website: https://www.cnil.fr/
- Email: [Via website contact form]
- Incident reporting: Within 72 hours

**Germany - BfDI (Federal) + State DPAs**
- Federal: https://www.bfdi.bund.de/
- Bavaria: https://www.datenschutz-bayern.de/
- [Each state has own DPA]

**Netherlands - Autoriteit Persoonsgegevens**
- Website: https://autoriteitpersoonsgegevens.nl/
- Email: info@autoriteitpersoonsgegevens.nl

**Spain - AEPD**
- Website: https://www.aepd.es/
- Email: informacion@aepd.es

**Italy - Garante**
- Website: https://www.garanteprivacy.it/
- Email: garante@gpdp.it

**Ireland - DPC (for many tech companies)**
- Website: https://www.dataprotection.ie/
- Email: info@dataprotection.ie

**Full List:**
https://edpb.europa.eu/about-edpb/about-edpb/members_en

---

## 🚨 DATA BREACH NOTIFICATION

### **72-Hour Rule (Article 33):**

**If personal data breach occurs during testing:**

**1. Notify Supervisory Authority (< 72 hours)**
```
What: Breach notification to DPA
When: Within 72 hours of becoming aware
How: Via DPA's official notification form
Contains:
  - Nature of breach
  - Data categories affected
  - Number of data subjects
  - Likely consequences
  - Mitigation measures taken
  - DPO contact
```

**2. Notify Data Subjects (if high risk)**
```
What: Direct notification to affected individuals
When: Without undue delay
How: Email, letter, or public communication
Language: Clear and plain language
```

**3. Document Breach**
```
What: Internal breach register
Contains: Facts, effects, remedial action
Retention: 7 years minimum
```

**⚠️  Failure to notify within 72 hours = Additional fines**

---

## 💰 GDPR PENALTIES

### **Violation Tiers:**

**Tier 1 (Up to €10M or 2% global revenue):**
- Inadequate security measures (Article 32)
- Failure to notify DPA (Article 33)
- Inadequate DPIA (Article 35)

**Tier 2 (Up to €20M or 4% global revenue):**
- No lawful basis (Article 6)
- Violating data subject rights (Articles 15-22)
- Unauthorized data transfers (Articles 44-50)

**Recent Examples:**
- Amazon (2021): €746M (Luxembourg) - targeted advertising
- WhatsApp (2021): €225M (Ireland) - lack of transparency
- Google (2019): €50M (France) - insufficient consent
- British Airways (2020): €22M (UK) - data breach

**For Security Assessments:**
- Scanning without authorization: €10M+ fine
- Unauthorized data transfer: €20M+ fine
- Failure to complete DPIA: €10M+ fine
- Inadequate security: €10M+ fine

---

## ✅ COMPLIANCE CHECKLIST

### **Before Every Scan:**

**Authorization:**
- [ ] GDPR authorization file created
- [ ] Lawful basis clearly identified
- [ ] Client signature obtained
- [ ] Scope clearly defined
- [ ] Time window appropriate
- [ ] DPO contact obtained (if applicable)

**DPIA:**
- [ ] DPIA required determination made
- [ ] If required: DPIA completed
- [ ] Risks assessed
- [ ] Mitigation measures documented
- [ ] DPO consulted (if you have DPO)
- [ ] DPIA approved

**Data Protection:**
- [ ] Data categories identified
- [ ] Retention period set (≤ 7 years)
- [ ] Security measures in place
- [ ] Data subject rights mechanism ready
- [ ] Breach notification plan ready

**Cross-Border:**
- [ ] Data transfer locations identified
- [ ] If outside EU/EEA: Safeguards in place
- [ ] SCCs signed (if applicable)
- [ ] Adequacy decision verified (if applicable)

**Verification:**
- [ ] Ran VERIFY_GDPR_COMPLIANCE.py
- [ ] All checks passed
- [ ] Authorization and DPIA linked

---

## 🛡️ NIS2 DIRECTIVE (For Critical Entities)

### **Applies to:**

**Essential Entities:**
- Energy (electricity, oil, gas)
- Transport (air, rail, water, road)
- Banking and financial markets
- Health sector
- Drinking water
- Wastewater
- Digital infrastructure
- Public administration

**Important Entities:**
- Postal services
- Waste management
- Chemical production
- Food production
- Manufacturing (medical devices, electronics, etc.)
- Digital providers
- Research organizations

### **Additional Requirements:**

**If client is NIS2 critical entity:**
- [ ] Set `"nis2_critical_entity": true`
- [ ] Identify sector
- [ ] Reference incident response plan
- [ ] Provide CSIRT contact
- [ ] Ensure 24-hour incident reporting capability
- [ ] Enhanced security measures documented

---

## 📚 RESOURCES

### **Official GDPR Resources:**
- **GDPR Full Text:** https://gdpr.eu/
- **EU Commission:** https://ec.europa.eu/info/law/law-topic/data-protection
- **EDPB Guidelines:** https://edpb.europa.eu/our-work-tools/our-documents/guidelines_en

### **DPIA Resources:**
- **WP29 DPIA Guidelines:** https://ec.europa.eu/newsroom/article29/items/611236
- **ICO DPIA Tools:** https://ico.org.uk/for-organisations/guide-to-data-protection/
- **CNIL PIA Tools:** https://www.cnil.fr/en/PIA-privacy-impact-assessment

### **Training:**
- **IAPP (International Association of Privacy Professionals):** https://iapp.org/
- **CIPP/E Certification** (Certified Information Privacy Professional - Europe)

### **Legal Counsel:**
- **European Law Firms with GDPR Expertise**
- **Data Protection Officers (DPOs)**
- **Privacy consultants**

---

## ⚠️ DISCLAIMER

**This system provides technical compliance tools. You are responsible for:**

1. **Legal Compliance:** Ensuring your operations comply with GDPR and member state laws
2. **Legal Counsel:** Consulting with qualified legal professionals
3. **DPA Guidance:** Following your supervisory authority's guidance
4. **Continuous Compliance:** Maintaining compliance as laws evolve
5. **Member State Laws:** Complying with national laws in each EU country

**This is NOT legal advice. Consult a qualified attorney for legal guidance.**

---

## 🎯 SUMMARY

**What This System Provides:**
- ✅ GDPR-compliant authorization templates
- ✅ DPIA templates and workflows
- ✅ Automated compliance checking
- ✅ Audit logging (consent log + authorization log)
- ✅ Cross-border transfer management
- ✅ NIS2 compliance for critical entities
- ✅ Data subject rights framework
- ✅ 72-hour breach notification support

**What You Need To Do:**
1. Use GDPR system for all EU/EEA operations
2. Complete DPIA for high-risk processing
3. Obtain proper authorization with lawful basis
4. Consult DPO (if required)
5. Register with supervisory authority (if required)
6. Maintain documentation (7 years minimum)
7. Be prepared for 72-hour breach notification
8. Review and update annually

---

**Your security testing operations are now GDPR compliant. You can operate legally and professionally throughout the European Union and EEA.** 🇪🇺✅🛡️

**Copyright © 2025 DoctorMen. All Rights Reserved.**
