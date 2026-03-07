# Cisco PSIRT Reporter

A Python tool for querying Cisco PSIRT advisories using the Cisco OpenVuln API and generating structured CSV reports filtered by configurable product groups.

The tool retrieves Cisco security advisories, classifies them by product family, and produces an operationally useful CSV report containing CVEs, severity, affected products, and advisory metadata.

This tool is intended for security engineers, vulnerability management teams, and operations teams who need quick visibility into Cisco security advisories affecting their environment.

---

# Overview

Cisco publishes security advisories through the OpenVuln API. These advisories often include many products and versions, making it difficult to quickly determine relevance.

This tool automates the process by:

1. Querying Cisco PSIRT advisories
2. Filtering to products of interest
3. Classifying advisories by product group
4. Producing a structured CSV report
5. Discovering new product name patterns to improve classification

---

# Features

## Cisco OpenVuln API Integration
Uses Cisco’s OAuth2 client credentials flow to authenticate and query advisories from the OpenVuln API.

## Product Group Classification
Uses a YAML configuration file to classify advisories into logical product groups with friendly names.

Example supported products:

- Adaptive Security Appliance (ASA)
- Secure Firewall Threat Defense (FTD)
- Firepower Management Center (FMC)
- Firepower Extensible Operating System (FXOS)

## Flexible Date Filtering

Supports:

- last **N days**
- explicit **start and end dates**

## CSV Reporting

Generates structured CSV output including:

- advisory metadata
- severity
- CVEs
- affected products
- friendly product names

## Product Discovery Mode

Extracts all raw product names returned by Cisco to help improve product matching rules.

---

# Script Flow (High Level)

1. Load product classification rules from YAML
2. Parse command line arguments
3. Resolve query date range
4. Authenticate with Cisco API
5. Retrieve advisories from OpenVuln API
6. Classify advisories by product group
7. Filter advisories based on selected groups
8. Extract unique product names for analysis
9. Export results to CSV

---

# Prerequisites

## Cisco API Access

Before using this script you must have access to the Cisco OpenVuln API.

You need:

- A registered Cisco developer application
- A valid **Client ID**
- A valid **Client Secret**

If you do not yet have API credentials, register an application on the Cisco Developer Platform and request access to the OpenVuln API.

---

## Python Requirements

Python 3.10+ recommended.

Required Python packages:
