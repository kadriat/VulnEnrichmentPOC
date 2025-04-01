import csv
import requests
import time
import re
import math
import logging
import os
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    filename='vulnerability_enrichment.log',  # Log to file
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

CVSS_COMPONENTS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

def fetch_nvd_data(cve_id, api_key, max_retries=10, base_delay=5):
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
    headers = {
        'User-Agent': 'VulnEnricher/1.0',
        'apiKey': api_key
    }

    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()  # Successfully fetched data

        except requests.exceptions.HTTPError as e:
            if response.status_code == 403:
                logging.warning(f"403 Forbidden for {cve_id}, retrying in {base_delay * (2 ** attempt)} seconds... (Attempt {attempt+1}/{max_retries})")
                time.sleep(base_delay * (2 ** attempt))  # Exponential backoff
            else:
                logging.error(f"Error fetching NVD data for {cve_id} (URL: {url}): {e}")
                raise

        except requests.exceptions.Timeout as e:
            if attempt < 2:  # Retry 2 times after a timeout
                logging.warning(f"Timeout fetching NVD data for {cve_id}, retrying in {base_delay * (2 ** attempt)} seconds... (Attempt {attempt+1}/{max_retries})")
                time.sleep(base_delay * (2 ** attempt))  # Exponential backoff
            else:
                logging.error(f"Timeout error fetching NVD data for {cve_id} after {attempt+1} attempts: {e}")
                raise

        except requests.exceptions.RequestException as e:
            logging.error(f"Request error fetching NVD data for {cve_id} (URL: {url}): {e}")
            raise

    logging.error(f"Failed to fetch NVD data for {cve_id} after {max_retries} attempts.")
    return None  # Return None if all retries fail

def extract_cvss_vector_from_nvd(nvd_data, cve_id):
    """Extract CVSS vector from NVD API when available, otherwise scrape it."""
    if not nvd_data or "vulnerabilities" not in nvd_data:
        return "", "", "", ""

    cve_details = nvd_data["vulnerabilities"][0]["cve"]
    metrics = cve_details.get("metrics", {}).get("cvssMetricV31", [{}])[0]
    description = cve_details.get("descriptions", [{}])[0].get("value", "")
    has_kev = "Yes" if cve_details.get("hasKev", False) else "No"  # Fixed the location of hasKev check
    cpe_data = cve_details.get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [{}])[0].get("criteria", "")

    cvss_vector = metrics.get("cvssData", {}).get("vectorString", "")
    if not cvss_vector or not re.match(r'^CVSS:3.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$', cvss_vector):
        logging.warning(f"Invalid or missing CVSS vector in API response for {cve_id}, falling back to HTML scraping.")
        html_content = fetch_nvd_html(cve_id)
        if html_content:
            extracted_vector = extract_cvss_vector_from_source(html_content, cve_id)
            if extracted_vector != "":
                cvss_vector = extracted_vector  # Ensure the scraped value is used

    return cvss_vector, description, has_kev, cpe_data

def fetch_nvd_html(cve_id, max_retries=10, base_delay=5):
    """Fetch the CVE details page from NVD for scraping CVSS metrics if needed."""
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    headers = {'User-Agent': 'VulnEnricher/1.0'}
    for attempt in range(1, max_retries + 1):
        try:
            logging.info(f"Attempting to fetch NVD HTML page for {cve_id} from {url} (Attempt {attempt}/{max_retries})")
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            logging.info(f"Successfully fetched NVD HTML page for {cve_id}")
            return response.text
        except requests.exceptions.HTTPError as e:
            if response.status_code == 503:
                logging.warning(f"503 Service Unavailable for {cve_id}, retrying in {base_delay * attempt} seconds... (Attempt {attempt}/{max_retries})")
                time.sleep(base_delay * attempt)  # Exponential backoff
            else:
                logging.error(f"HTTP error while fetching NVD HTML page for {cve_id}: {e}")
                break  # Stop retrying for other HTTP errors
        except requests.exceptions.Timeout as e:
            logging.warning(f"Timeout error while fetching NVD HTML page for {cve_id}, retrying in {base_delay * attempt} seconds... (Attempt {attempt}/{max_retries})")
            time.sleep(base_delay * attempt)  # Exponential backoff
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error while fetching NVD HTML page for {cve_id}: {e}")
            break  # Stop retrying on other request errors
    logging.error(f"Failed to fetch NVD HTML page for {cve_id} after {max_retries} attempts.")
    return None

def extract_cvss_vector_from_source(html_content, cve_id):
    """Extract CVSS vector from the NVD HTML page."""
    try:
        logging.info(f"Parsing HTML content to extract CVSS vector for {cve_id}")
        soup = BeautifulSoup(html_content, 'html.parser')
        cvss_elem = soup.find('span', {'data-testid': 'vuln-cvss3-cna-vector'})
        if cvss_elem:
            vector = cvss_elem.text.strip()
            logging.debug(f"Extracted CVSS vector from HTML for {cve_id}: {vector}")
        else:
            vector = ""
            logging.warning(f"No CVSS vector element found in HTML for {cve_id}")
        return vector
    except Exception as e:
        logging.error(f"Error parsing CVSS vector from NVD HTML for {cve_id}: {e}")
        return ""

def fetch_epss_data(cve_id):
    """Fetch EPSS score from FIRST API."""
    url = f'https://api.first.org/data/v1/epss?cve={cve_id}'
    try:
        response = requests.get(url, headers={'User-Agent': 'VulnEnricher/1.0'})
        response.raise_for_status()  # Raise an error for bad status codes
        if response.status_code == 200:
            data = response.json()
            if "data" in data and data["data"]:
                logging.info(f"Successfully fetched EPSS data for {cve_id}")
                return data["data"][0].get("epss", ""), data["data"][0].get("percentile", "")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching EPSS data for {cve_id}: {e}")
    return "", ""


def calculate_risk_score(vuln):
    """Calculate a refined risk score based on multiple factors with improved variance."""
    score = 0

    # Asset Criticality (non-linear scaling for better distinction)
    asset_criticality = int(vuln.get("Asset Criticality", 1))
    score += min((asset_criticality ** 1.5) * 5, 60)

    # CVSS Score Contribution (logarithmic scaling, increased weight)
    cvss_score = float(vuln.get("CVSS Score", 0))
    score += (math.log(cvss_score + 1) / math.log(10)) * 35

    # Exploitability Factors
    if vuln.get("Attack Vector (AV)") == "N":
        score += 15
    if vuln.get("Privileges Required (PR)") == "N":
        score += 10
    if vuln.get("User Interaction (UI)") == "N":
        score += 5

    # Known Exploitability
    if vuln.get("Has KEV") == "Yes":
        score += 30

    # EPSS Score Contribution (adjusted for higher weight on critical values)
    epss_percentile = vuln.get("EPSS Percentile")
    if epss_percentile != "":
        epss_percentile = float(epss_percentile)
        if epss_percentile > 0.9:
            score += 40
        elif epss_percentile > 0.7:
            score += 20
        elif epss_percentile > 0.5:
            score += 5

    # Impact Metrics Contribution (Availability removed)
    impact_bonus = 0
    if vuln.get("Confidentiality (SC)") == "H":
        impact_bonus += 5
    if vuln.get("Integrity (SI)") == "H":
        impact_bonus += 5
    score += impact_bonus

    return min(score, 100)  # Cap at 100


def parse_cvss_vector(cvss_vector):
    """Parses a CVSS vector string into a dictionary."""
    if not cvss_vector or "CVSS:" not in cvss_vector:
        logging.warning(f"Unexpected CVSS vector format: {cvss_vector}")
        return {comp: "" for comp in CVSS_COMPONENTS}

    try:
        parts = cvss_vector.replace("CVSS:3.0/", "").split('/')
        vector_dict = {k: v for k, v in (part.split(':') for part in parts if ':' in part)}
        return {comp: vector_dict.get(comp, "") for comp in CVSS_COMPONENTS}
    except ValueError as e:
        logging.error(f"Error parsing CVSS vector '{cvss_vector}': {e}")
        return {comp: "" for comp in CVSS_COMPONENTS}

def enrich_vulnerabilities(vulnerabilities, api_key):
    """Enrich vulnerabilities with data from the NVD API and EPSS."""
    enriched_vulns = []
    for vuln in vulnerabilities:
        cve_id = vuln.get("CVE ID")
        if not cve_id:
            continue
        nvd_data = fetch_nvd_data(cve_id, api_key)
        cvss_vector, description, has_kev, cpe_data = extract_cvss_vector_from_nvd(nvd_data, cve_id)
        epss_score, epss_percentile = fetch_epss_data(cve_id) or ("", "")

        # Parse the CVSS vector
        vector_parts = parse_cvss_vector(cvss_vector)

        # Assign parsed values to the vulnerability dictionary
        vuln["Description"] = description
        vuln["NVD Link"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        vuln["Has KEV"] = has_kev
        vuln["EPSS"] = epss_score
        vuln["EPSS Percentile"] = epss_percentile
        vuln["CPE Data"] = cpe_data
        vuln["Attack Vector (AV)"] = vector_parts.get("AV", "")
        vuln["Attack Complexity (AC)"] = vector_parts.get("AC", "")
        vuln["Privileges Required (PR)"] = vector_parts.get("PR", "")
        vuln["User Interaction (UI)"] = vector_parts.get("UI", "")
        vuln["Scope (S)"] = vector_parts.get("S", "")
        vuln["Confidentiality (C)"] = vector_parts.get("C", "")
        vuln["Integrity (I)"] = vector_parts.get("I", "")
        vuln["Availability (A)"] = vector_parts.get("A", "")
        vuln["Risk Score"] = calculate_risk_score(vuln)

        enriched_vulns.append(vuln)

        # Handle rate limiting
        rate_limit_remaining = int(nvd_data.get("X-RateLimit-Remaining", 1)) if nvd_data else 1
        if rate_limit_remaining == 0:
            time.sleep(5)
        else:
            time.sleep(0.6)

    output_top_ten(enriched_vulns)
    return enriched_vulns

def save_enriched_vulns(enriched_vulns):
    """Save enriched vulnerabilities to a new CSV file, sorted by Risk Score."""
    if not enriched_vulns:
        print("No enriched vulnerabilities to save.")
        return

    # Sort vulnerabilities by Risk Score in descending order
    enriched_vulns = sorted(enriched_vulns, key=lambda x: float(x.get("Risk Score", 0)), reverse=True)

    # Add "Top Ten" column to indicate the top ten largest risk scores
    for i, vuln in enumerate(enriched_vulns):
        vuln["Top Ten"] = "Yes" if i < 10 else "No"

    fieldnames = enriched_vulns[0].keys()
    output_file = "enriched_vulns.csv"
    with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(enriched_vulns)

    print(f"Enriched vulnerabilities saved to {output_file}")


def output_top_ten(enriched_vulns):
    """Output the top ten vulnerabilities by risk score to terminal and log."""
    # Sort vulnerabilities by risk score in descending order
    top_vulns = sorted(enriched_vulns, key=lambda x: x.get("Risk Score", 0), reverse=True)[:10]

    # Output to terminal
    print("\nTop Ten Vulnerabilities:")
    for i, vuln in enumerate(top_vulns, 1):
        print(f"{i}. CVE: {vuln['CVE ID']}, Risk Score: {vuln['Risk Score']}, Description: {vuln['Description']}")

    # Log the top ten to the log file
    logging.info("\nTop Ten Vulnerabilities:")
    for i, vuln in enumerate(top_vulns, 1):
        logging.info(f"{i}. CVE: {vuln['CVE ID']}, Risk Score: {vuln['Risk Score']}, Description: {vuln['Description']}")

def parse_vuln_csv(file_path):
    """Parse vulnerabilities from the CSV file with validation."""
    vulnerabilities = []
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if not row.get("CVE ID"):
                logging.warning(f"Skipping row with missing CVE ID: {row}")
                continue
            row["CVSS Score"] = float(row.get("CVSS Score", 0))  # Default to 0 if missing
            row["Asset Criticality"] = int(row.get("Asset Criticality", 1))  # Default to 1 if missing
            vulnerabilities.append(row)
    return vulnerabilities

def main():
    file_path = "vulns.csv"
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        raise ValueError("NVD_API_KEY environment variable is not set.")
    vulnerabilities = parse_vuln_csv(file_path)
    enriched_vulnerabilities = enrich_vulnerabilities(vulnerabilities, api_key)
    save_enriched_vulns(enriched_vulnerabilities)

if __name__ == "__main__":
    main()
