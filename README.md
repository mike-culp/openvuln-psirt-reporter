# Cisco PSIRT Reporter

A Python tool for querying Cisco PSIRT advisories using the Cisco OpenVuln API and generating structured **CSV and optional HTML reports** filtered by configurable product groups.

The tool retrieves Cisco security advisories, classifies them by product family, supports severity filtering using Cisco’s Security Impact Rating (SIR), supports filtering by minimum CVSS score, enriches results with CISA Known Exploited Vulnerabilities (KEV) intelligence, and enriches advisories with Cisco **Bug API defect intelligence**.

The resulting reports provide operational visibility into vulnerabilities affecting Cisco products, including CVEs, severity, KEV exploitation status, and associated Cisco defect information.

This tool is intended for:

* Security engineers
* Vulnerability management teams
* Network security operations teams
* Cisco platform administrators

who need fast visibility into Cisco security advisories impacting their environment.

---

# Quick Start

Run the PSIRT reporter in just a few steps.

## 1. Clone the Repository

```
git clone https://github.com/mike-culp/openvuln-psirt-reporter.git
cd openvuln-psirt-reporter
```

## 2. Install Dependencies

```
pip install -r requirements.txt
```

## 3. Set Cisco API Credentials

macOS / Linux

```
export OPENVULN_CLIENT_ID="your_client_id"
export OPENVULN_CLIENT_SECRET="your_client_secret"
```

Windows PowerShell

```
$env:OPENVULN_CLIENT_ID="your_client_id"
$env:OPENVULN_CLIENT_SECRET="your_client_secret"
```

---

# Obtain Cisco API Credentials

This tool requires credentials for the Cisco OpenVuln API.

To obtain them:

1. Visit the Cisco API Console
   https://apiconsole.cisco.com

2. Create a new application

3. Enable the **Cisco PSIRT / OpenVuln API**

4. Copy the generated **Client ID** and **Client Secret**

5. Set them as environment variables before running the script

---

# Running the Reporter

Run the tool from the root of the repository.

### Recommended (module execution)

```
python -m src.main
```

Example:

```
python -m src.main --group netsec --days 30
```

Example with HTML report output:

```
python -m src.main --group netsec --days 30 --html
```

### Legacy script entrypoint

For convenience and backwards compatibility:

```
python src/psirt_reporter.py
```

Example:

```
python src/psirt_reporter.py --group netsec --days 30 --html
```

Both methods produce identical results.

Generated reports are written to:

```
output/
```

---

# CLI Help

To view all available options:

```
python -m src.main --help
```

This displays all supported command line options including:

* product group filtering
* date range filtering
* severity filtering
* CVSS filtering
* KEV prioritization
* optional HTML reporting
* verbose debugging output

---

# Example Commands

## NetSec Advisories From the Last 30 Days

```
python -m src.main --group netsec --days 30
```

## Generate HTML Report

```
python -m src.main --group netsec --days 30 --html
```

Generates both:

```
output/psirt_<groups>_<start>_to_<end>.csv
output/psirt_<groups>_<start>_to_<end>.html
```

---

## Only Known Exploited Vulnerabilities

```
python -m src.main --kev-only
```

---

## Only High or Critical Severity

```
python -m src.main --sir critical high
```

---

## Minimum CVSS Score

```
python -m src.main --min-cvss 8.0
```

---

## NetSec + High Severity + CVSS + KEV + HTML

```
python -m src.main \
  --group netsec \
  --sir critical high \
  --min-cvss 8.0 \
  --kev-only \
  --html
```

---

# Overview

Cisco publishes security advisories through the OpenVuln API. These advisories often include many products and versions, making it difficult to quickly determine relevance.

This tool automates the process by:

1. Querying Cisco PSIRT advisories
2. Filtering to products of interest
3. Classifying advisories by product group
4. Filtering advisories by Cisco Security Impact Rating (SIR)
5. Filtering advisories by minimum CVSS score
6. Checking advisories against the CISA Known Exploited Vulnerabilities catalog
7. Enriching advisories with Cisco Bug API defect intelligence
8. Producing structured CSV reports
9. Optionally generating an HTML report for operational visibility
10. Discovering new Cisco product names for classification improvement

---

# Architecture

High-level workflow of the PSIRT reporter.

```
+----------------------+
| Cisco OpenVuln API   |
+----------+-----------+
           |
           v
   +---------------+
   | Advisory Pull |
   |  (API Client) |
   +-------+-------+
           |
           v
   +---------------+
   | Product       |
   | Classification|
   | YAML rules    |
   +-------+-------+
           |
           v
   +----------------------+
   | Severity Filtering   |
   | Cisco SIR            |
   +-----------+----------+
               |
               v
   +----------------------+
   | CVSS Filtering       |
   +-----------+----------+
               |
               v
   +------------------------------+
   | KEV Intelligence Enrichment  |
   | CISA KEV Catalog             |
   +---------------+--------------+
                   |
                   v
   +------------------------------+
   | Cisco Bug API Enrichment     |
   | Defect IDs + Version Data    |
   +---------------+--------------+
                   |
                   v
           +----------------------+
           | Report Generation    |
           | CSV + Optional HTML  |
           +----------------------+
```

---

# Features

## Cisco OpenVuln API Integration

Uses Cisco’s OAuth2 client credentials flow to authenticate and retrieve Cisco PSIRT advisories.

---

## Cisco Bug API Integration

The tool enriches advisories with Cisco defect intelligence.

Capabilities include:

* retrieving Cisco **bug IDs**
* extracting **affected software versions**
* extracting **fixed software versions**
* retrieving **bug severity and status**

### Bug API Access Requirements

The Cisco Bug API is **not publicly accessible to all users**.

Access is available only to:

* Cisco customers with an active **Cisco Smart Net Total Care / Total Care** contract
* Cisco **partners**
* Cisco **employees**

Users without Bug API access can still use the tool to retrieve Cisco PSIRT advisories and KEV intelligence via the OpenVuln API, but **defect enrichment data will not be available**.

If Bug API access is unavailable, the script will continue to function normally and simply skip the enrichment step.

Note: The Bug API is used to correlate PSIRT advisories with Cisco defect records, enabling extraction of affected and fixed software versions for more precise vulnerability analysis.

---

## CISA Known Exploited Vulnerabilities (KEV) Integration

The tool downloads the CISA KEV catalog and checks whether CVEs associated with advisories are actively exploited in the wild.

---

## Product Group Classification

Uses a YAML configuration file to classify advisories into logical product groups.

Configuration file:

```
config/product_groups.yaml
```

Example groups include:

* NetSec
* Enterprise Networking
* Data Center
* Wireless
* Collaboration
* Cloud
* Observability

---

## Flexible Date Filtering

Supports:

* last **N days**
* explicit **start/end dates**

Examples:

```
python -m src.main --days 30
```

```
python -m src.main --start-date 2026-01-01 --end-date 2026-03-01
```

---

## Severity Filtering (Cisco SIR)

Filter advisories using Cisco’s Security Impact Rating:

* critical
* high
* medium
* low

Example:

```
python -m src.main --sir critical high
```

---

## CVSS Filtering

Filter advisories using a minimum CVSS score:

```
python -m src.main --min-cvss 8.0
```

---

## HTML Reporting

Optional HTML reports provide:

* advisory summary statistics
* severity distribution
* KEV indicators
* product group breakdown
* advisory tables with Cisco advisory links

---

## CSV Reporting

Structured CSV output includes:

* advisory metadata
* CVEs
* severity
* KEV indicator
* friendly product names
* Cisco bug IDs
* affected versions
* fixed versions

---

## Product Discovery Mode

The script extracts all raw Cisco product names returned by the API and writes them to:

```
output/unique_product_names.txt
```

This helps maintain accurate product classification rules.

---

## Verbose Debug Mode

The CLI supports a `--verbose` flag for detailed debugging output.

Verbose mode includes:

* API request diagnostics
* Bug API batch progress indicators
* product discovery preview
* enrichment debugging information

Example:

```
python -m src.main --group netsec --days 30 --verbose
```

---

# Script Flow (High Level)

1. Load product classification rules
2. Parse CLI arguments
3. Resolve query date range
4. Authenticate with Cisco OpenVuln API
5. Retrieve PSIRT advisories
6. Classify advisories by product group
7. Apply severity and CVSS filtering
8. Retrieve CISA KEV catalog
9. Enrich advisories with Cisco Bug API data
10. Extract unique Cisco product names
11. Generate CSV report
12. Optionally generate HTML report

---

# External Data Sources

## Cisco OpenVuln API

https://apix.cisco.com/security/advisories

---

## Cisco Bug API

Cisco Bug Search API

Used to retrieve:

* Cisco defect IDs
* affected versions
* fixed versions
* defect metadata

---

## CISA Known Exploited Vulnerabilities Catalog

https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

# Development Workflow

This repository uses a two-branch workflow:

* **main** — stable releases
* **dev** — active development

New features are developed in `dev` and merged into `main` when stable.

---

# Roadmap

Future development will focus on improving advisory intelligence, vulnerability prioritization, and operational reporting.

---

## v2.1 – Version-Aware Vulnerability Analysis

Planned capabilities:

* filter advisories by specific Cisco software versions
* determine whether a given version is affected or fixed
* enable targeted vulnerability analysis for deployed platforms

Example concept:

```
--product ftd 7.2.2.1
```

---

## v2.2 – Guided Product Integration

Detect new Cisco product names returned by the API and guide users through safely adding them to classification rules.

---

## v3 – Reporting and Visualization Improvements

Planned enhancements include:

* color-coded severity indicators
* KEV highlighting
* severity distribution charts
* advisory counts by product group
* improved HTML report dashboards
