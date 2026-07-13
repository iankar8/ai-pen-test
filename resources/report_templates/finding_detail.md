# Finding Detail Template

---

## {{FINDING_ID}}: {{VULNERABILITY_TITLE}}

**Severity**: {{SEVERITY_BADGE}}  
**CVSS Score**: {{CVSS_SCORE}} ({{CVSS_VECTOR}})  
**CWE**: {{CWE_ID}} - {{CWE_NAME}}  
**OWASP**: {{OWASP_CATEGORY}}

**Location**: `{{FILE_PATH}}:{{LINE_NUMBER}}`  
**Confidence**: {{CONFIDENCE_LEVEL}}

---

### Description

{{VULNERABILITY_DESCRIPTION}}

### Vulnerable Code

```{{LANGUAGE}}
{{CODE_SNIPPET}}
```

### Proof of Concept

{{POC_DESCRIPTION}}

**Attack Scenario**:
```{{POC_LANGUAGE}}
{{POC_CODE}}
```

**Expected Result**: {{POC_EXPECTED_RESULT}}

---

### Impact Analysis

#### Technical Impact

{{TECHNICAL_IMPACT}}

**Attack Vectors**:
- {{ATTACK_VECTOR_1}}
- {{ATTACK_VECTOR_2}}
- {{ATTACK_VECTOR_3}}

**Exploitability**: {{EXPLOITABILITY_RATING}}

#### Business Impact

{{BUSINESS_IMPACT}}

**Potential Consequences**:
- **Confidentiality**: {{CONFIDENTIALITY_IMPACT}}
- **Integrity**: {{INTEGRITY_IMPACT}}
- **Availability**: {{AVAILABILITY_IMPACT}}

**Financial Risk**: {{FINANCIAL_RISK_ESTIMATE}}

**Compliance Impact**: {{COMPLIANCE_IMPACT}}

---

### Real-World Attack Scenario

{{ATTACK_SCENARIO_NARRATIVE}}

**Timeline**:
1. Day 0: {{SCENARIO_STEP_1}}
2. Day 1: {{SCENARIO_STEP_2}}
3. Day 3: {{SCENARIO_STEP_3}}
4. Week 2: {{SCENARIO_STEP_4}}

---

### Remediation

#### Immediate Mitigation (Deploy within {{IMMEDIATE_TIMELINE}})

**Quick Fix**:
```{{LANGUAGE}}
{{IMMEDIATE_FIX_CODE}}
```

**Deployment Steps**:
1. {{IMMEDIATE_STEP_1}}
2. {{IMMEDIATE_STEP_2}}
3. {{IMMEDIATE_STEP_3}}

#### Long-term Solution

**Secure Implementation**:
```{{LANGUAGE}}
{{SECURE_CODE_EXAMPLE}}
```

**Architecture Changes**:
1. {{ARCHITECTURE_CHANGE_1}}
2. {{ARCHITECTURE_CHANGE_2}}
3. {{ARCHITECTURE_CHANGE_3}}

**Additional Controls**:
- {{CONTROL_1}}
- {{CONTROL_2}}
- {{CONTROL_3}}

---

### Testing & Verification

#### Manual Testing

**Step 1**: {{TEST_STEP_1}}
```bash
{{TEST_COMMAND_1}}
```

**Step 2**: {{TEST_STEP_2}}
```bash
{{TEST_COMMAND_2}}
```

**Step 3**: Verify the fix
```bash
{{TEST_COMMAND_3}}
```

**Expected Outcome**: {{TEST_EXPECTED_OUTCOME}}

#### Automated Testing

**Unit Test Example**:
```{{LANGUAGE}}
{{UNIT_TEST_CODE}}
```

**Integration Test Example**:
```{{LANGUAGE}}
{{INTEGRATION_TEST_CODE}}
```

---

### References

- [OWASP - {{OWASP_REFERENCE_TITLE}}]({{OWASP_REFERENCE_URL}})
- [CWE-{{CWE_ID}}: {{CWE_NAME}}]({{CWE_REFERENCE_URL}})
- {{ADDITIONAL_REFERENCE_1}}
- {{ADDITIONAL_REFERENCE_2}}

### Related Findings

{{#if RELATED_FINDINGS}}
This finding is related to:
- {{RELATED_FINDING_1}}
- {{RELATED_FINDING_2}}
{{/if}}

---

**Remediation Priority**: {{PRIORITY_RANK}}/{{TOTAL_FINDINGS}}  
**Estimated Fix Time**: {{FIX_TIME_ESTIMATE}} hours  
**Assignee**: {{ASSIGNEE}}  
**Due Date**: {{DUE_DATE}}

