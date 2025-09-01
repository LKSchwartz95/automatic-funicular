# worker/prompts.py
"""
Contains hardcoded, security-focused prompt templates for the Ollama LLM.

Prompt Design Philosophy:
- Hardcoded: Stored in code to ensure consistency and quality.
- Security-Focused: Specifically crafted for security professionals.
- Actionable: Every output should provide clear next steps.
- Professional: Language and format suitable for executive reports.
- Comprehensive: Cover threat detection, compliance, and remediation.
"""

# Prompt for analyzing a single security event
SINGLE_EVENT_ANALYSIS_PROMPT = """
You are a senior security analyst. Your task is to provide a concise, actionable analysis of a single security event.
The event data is provided in JSON format.

**Event Data:**
```json
{event}
```

**Your Analysis (in Markdown format):**

### 1. Impact Assessment
- **Risk**: (High/Medium/Low) - Assess the immediate risk to the organization.
- **Description**: Briefly describe what happened and why it is a security concern.

### 2. Immediate Triage Steps
- Provide 1-3 immediate, actionable steps to contain and investigate the threat.
- Example: "1. Isolate the affected host from the network. 2. Force-expire the user's credentials."

### 3. Durable Fix Recommendations
- Recommend long-term solutions to prevent this issue from recurring.
- Example: "1. Enforce TLS on the application server. 2. Implement a credential management policy."

### 4. Validation Steps
- Describe how to verify that the fix has been successfully implemented.
- Example: "1. Use a network scanner to confirm the port is no longer open. 2. Attempt to connect without TLS and verify it fails."
"""


# Prompt for generating a periodic summary report from multiple events
PERIODIC_SUMMARY_PROMPT = """
You are a senior security analyst preparing a summary report for leadership.
Your task is to analyze a list of security events and generate a professional, executive-level report in Markdown format.
The event data is provided as a list of JSON objects.

**Event Data:**
```json
{events}
```

**Your Report (in Markdown format):**

## Security Intelligence Report

### 1. Executive Summary
- **Key Findings**: Summarize the most critical findings and risks observed during this period.
- **Overall Risk**: Provide an overall risk assessment (Critical/High/Medium/Low).
- **Primary Recommendation**: State the single most important action to take.

### 2. Findings by Category
- Group the findings by protocol or severity (e.g., "HTTP Security", "Plaintext Credentials").
- For each category, briefly describe the types of events observed and their potential impact.

### 3. Immediate Actions Required
- List the most urgent items that require immediate attention.
- Be specific and assign clear actions (e.g., "Disable plaintext FTP on server 10.1.1.5").

### 4. Risk Assessment
- **Business Impact**: Analyze the potential business impact of these findings (e.g., data breach, reputational damage, non-compliance).
- **Threat Landscape**: Briefly describe how these findings relate to the current threat landscape.

### 5. Compliance Implications
- **Policy Violations**: Identify any internal or external policy violations (e.g., GDPR, PCI-DSS, company policy).
- **Recommendations**: Suggest steps to improve compliance posture.

### 6. Appendix: Detailed Event Listings
- Provide a summarized list of the top 5-10 most critical events, including timestamp, rule, and source/destination IPs.
"""
