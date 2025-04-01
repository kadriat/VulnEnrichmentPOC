# Risk-Based Vulnerability Prioritization Algorithm

## Overview

This document outlines the risk-based scoring algorithm used to prioritize vulnerabilities based on multiple security-related factors. The goal of this system is to help organizations focus on the most critical vulnerabilities first, enabling efficient remediation efforts.

## Scoring Components

The risk score is calculated based on the following factors:

### 1. **Asset Criticality (Max: 60 Points)**

- **Non-linear Scaling**:
- Asset Criticality is a numeric score, and its contribution to the risk score is scaled non-linearly for better distinction.
- Formula:

$$ \text{Asset Criticality Contribution} = \min((\text{Asset Criticality} ^ {1.5}) \times 5, 60) $$

Where:

- Asset Criticality is a numeric value, with higher values indicating more critical assets.
- The score is capped at **60 points** to avoid excessive weight from critical assets.

**Rationale:** Critical assets require higher prioritization since an exploit on these systems could have a significant business impact. The non-linear scaling ensures more variance between assets with differing criticality.

### 2. **CVSS Score Contribution (Max: 35 Points)**

- Calculated using a logarithmic scale for more varied contributions:

$$\text{CVSS Contribution} = \left( \frac{\log(CVSS + 1)}{\log(10)} \right) \times 35$$

**Rationale:** This scaling ensures that vulnerabilities with very high CVSS scores receive a proportional boost while avoiding excessive clustering at the high end. The maximum contribution from CVSS is capped at 35 points.

### 3. **Remote Exploitation Factors (Max: 30 Points)**

- **Attack Vector (AV) = Network:** **20 points**
- **Privileges Required (PR) = None:** **10 points**
- **User Interaction (UI) = None:** **5 points**

**Rationale:** Vulnerabilities that can be exploited remotely without user interaction are more critical than those requiring local access or user engagement.

### 4. **Known Exploitable Vulnerabilities (KEV) (Max: 30 Points)**

- If the vulnerability has a known exploit (Has KEV = Yes): **30 points**

**Rationale:** Vulnerabilities known to be actively exploited should be remediated immediately.

### 5. **EPSS Score Contribution (Max: 40 Points)**

- **EPSS Percentile > 90%:** **40 points**
- **EPSS Percentile > 70%:** **20 points**
- **EPSS Percentile > 50%:** **5 points**

**Rationale:** The Exploit Prediction Scoring System (EPSS) indicates the likelihood of exploitation. Higher EPSS scores warrant immediate attention. The maximum contribution from EPSS is now capped at 40 points to provide more weight to high-risk vulnerabilities.

### 6. **Impact Metrics (Max: 10 Points)**

- **Confidentiality (SC) = High:** **5 points**
- **Integrity (SI) = High:** **5 points**

**Rationale:** Vulnerabilities affecting data confidentiality and integrity should be prioritized for mitigation. We have removed the Availability factor from the impact metrics.

## Total Score Calculation

The final risk score is the sum of the above components, with a cap at 100 to maintain consistency. The formula ensures better variance in the prioritization process, helping to identify the most critical vulnerabilities more effectively.

## Future Improvements

The above system was provided as a proof-of-concept, and is not necessarily a robust prioritization mechanism to be used in production environments, further refinements could include:

- **Exploit Database Integration:** Identifying publicly available exploits (e.g., Exploit-DB, Metasploit modules, Nuclei templates) for additional prioritization.
- **Patch Availability Check:** Prioritizing vulnerabilities with known fixes.
- **Business Impact Considerations:** Incorporating specific business risks for more tailored prioritization.
- **Vulnerability Score Provided by Vendor:** Incorporating vulnerability metrics provided by vendor which consider architectual or usage context.

This risk-based approach ensures that remediation efforts focus on the most impactful vulnerabilities, helping to reduce overall risk effectively.
