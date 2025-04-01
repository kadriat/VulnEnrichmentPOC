# Vulnerability Enrichment Script

## Overview

This script is designed to enrich vulnerability data from a provided CSV file containing scan results by fetching additional details from the National Vulnerability Database (NVD) and Exploit Prediction Scoring System (EPSS). The script prioritizes vulnerabilities based on a risk-based scoring algorithm, which includes CVSS scores, asset criticality, EPSS percentiles, exploitability, and other relevant factors.

## Features

- Parse a CSV file containing vulnerability scan results.
- Enrich vulnerabilities with detailed information from NVD and EPSS.
- Assign a risk score based on multiple metrics to prioritize remediation efforts.
- Output a new CSV file with enriched data, including risk scores and other relevant information.

## Data Enrichment

The script enriches each CVE entry with the following additional data:

- **CVSS Metrics** (including Attack Vector, Attack Complexity, Privileges Required, User Interaction, etc.)
- **EPSS** (Exploit Prediction Scoring System) score and percentile.
- **Impact Metrics** for confidentiality, integrity, and availability.
- **Known Exploitability (KEV)** indicator (whether there is an active known exploit for the CVE meeting CISA KEV criteria <https://www.cisa.gov/known-exploited-vulnerabilities>).
- **CVE Description** from the NVD.
- **NVD Link** to the full CVE details page.

## Risk Scoring Algorithm

A refined risk score is calculated for each vulnerability based on the following factors:

1. **Asset Criticality** (numeric score with higher values indicating more critical assets)
2. **CVSS Score** (using logarithmic scaling)
3. **Exploitability Factors** (such as attack vector, privileges required, user interaction)
4. **Known Exploitability** (Has KEV)
5. **EPSS Score** (with tiered contributions based on percentile)
6. **Impact Metrics** (Confidentiality, Integrity)

The final risk score helps prioritize vulnerabilities for immediate remediation, with higher scores indicating more critical vulnerabilities.

## Requirements

- Python 3.x
- `requests` library for HTTP requests
- `beautifulsoup4` to scrape information from web pages

To install the required Python packages:

```sh
pip install requests
pip3 install beautifulsoup4
```

## Usage

1. Clone the repository:

    ```sh
    git clone https://github.com/kadriat/VulnEnrichmentPOC.git
    cd VulnEnrichmentPOC
    ```

2. Prepare a CSV file (vulns.csv) with the following columns: Host, CVE ID, CVSS Score, Asset Criticality

3. Place the vulns.csv file in the same directory as the script.

4. Provide your NVD API key in the script or as an environment variable

    ```sh
    export NVD_API_KEY=your_key
    ```

5. Run the script:

    ```sh
    python3 vuln_enrichment.py
    ```

6. The enriched data will be saved to a new CSV file, enriched_vulns.csv.

## Prioritization Algorithm

Refer [Prioritization Algorithm](./Prioritization.md)

## Output

The enriched CSV file includes the following columns:
Host, CVE ID, CVSS Score (from original CSV), Asset Criticality (from original CSV), Description (CVE description), NVD Link (link to NVD CVE page), Has KEV (in CISA KEV catalog), EPSS (Exploit Prediction Scoring System score), EPSS Percentile, Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR), User Interaction (UI), Confidentiality (SC), Integrity (SI), Availability (SA), Risk Score (calculated score based on various factors), Top Ten (whether the script assesses the vulnerability to be one of the top ten vulnerabilities requiring immediate remediation)

## Future Improvements

The current solution relies on remediation recommendations provided within the vulnerability descriptions. However, we are constrained in the level of detail we can offer regarding specific remediation actions. This limitation arises from the lack of information on the detection method or the vulnerability's path.

To address this, incorporating additional component details—such as the vulnerable component and the corresponding fixed version—could enhance accuracy. Nonetheless, without insights into how or where the vulnerability was identified, providing precise remediation guidance remains a challenge. As this script is a minimum viable solution as part of a POC, the decision was made not to include this information.

Potential areas for future enhancements include:

- Integration with Additional Exploit Databases: For example, leveraging resources like Exploit-DB, Metasploit modules, Nuclei templates, as indicators of exploit maturity and weaponization.
- Inclusion of Product-Specific Information: Adding data such as CPEs (ideally this is included in the NVD data, but there is currently a substantial backlog of missing metadata in the NVD).
- Patch Availability and Version Checks: Incorporating checks for vulnerable and fixed versions or patch availability.
- Additional Contextual Data: Factoring in additional contextual data to refine risk assessments.
- Better handling for server side errors. As-is the script will continue for 500/503 errors, leading to incomplete data.
