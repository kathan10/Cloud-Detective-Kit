#  Cloud Detective Kit

> An Automated Cloud Digital Forensics and Incident Response (DFIR) Toolkit for AWS

![Python](https://img.shields.io/badge/Python-3.11-blue)
![AWS](https://img.shields.io/badge/AWS-CloudTrail-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

##  Overview

Cloud Detective Kit is an automated Digital Forensics and Incident Response (DFIR) toolkit developed for Amazon Web Services (AWS). The project assists investigators in collecting cloud forensic evidence, analyzing AWS CloudTrail logs, identifying suspicious activities, reconstructing attack timelines, mapping detected techniques to the MITRE ATT&CK framework, and generating structured HTML forensic reports.

The objective of the project is to simplify cloud forensic investigations by automating repetitive investigation tasks while preserving evidence for analysis.

---

##  Project Objectives

- Automate AWS CloudTrail evidence collection.
- Normalize collected forensic evidence.
- Detect suspicious activities using rule-based analysis.
- Reconstruct chronological attack timelines.
- Assign investigation risk scores.
- Map suspicious activities to MITRE ATT&CK techniques.
- Generate investigator-friendly HTML forensic reports.

---

#  Features

### Evidence Collection

- AWS CloudTrail log collection
- JSON evidence storage
- Evidence normalization

### Detection Engine

The toolkit performs rule-based detection for activities including:

- Root account usage
- Console login events
- IAM policy modifications
- IAM user activities
- EC2 instance enumeration
- Security group modifications
- S3 access analysis
- STS AssumeRole activities
- Suspicious API usage

### Timeline Reconstruction

The project automatically reconstructs cloud events into a chronological timeline to assist investigators in understanding the attack sequence.

### Risk Assessment

Each suspicious activity is assigned a severity level and contributes to the overall investigation risk score.

### MITRE ATT&CK Mapping

Detected events are mapped to relevant MITRE ATT&CK techniques to improve investigation context.

### HTML DFIR Report

The toolkit automatically generates a structured HTML report containing:

- Executive Summary
- Investigation Summary
- Suspicious Activities
- Timeline Analysis
- MITRE ATT&CK Mapping
- Risk Summary
- Recommendations

---

#  Project Workflow

```
AWS CloudTrail Logs
          │
          ▼
 Evidence Collection
          │
          ▼
 Data Normalization
          │
          ▼
 Rule-Based Analysis
          │
          ▼
 Timeline Reconstruction
          │
          ▼
 Risk Scoring
          │
          ▼
 MITRE ATT&CK Mapping
          │
          ▼
 HTML DFIR Report
```

---

# Project Structure

```
Cloud-Detective-Kit/
│
├── docs/
│
├── evidence/
│
├── src/
│   ├── analyzers/
│   ├── collectors/
│   ├── reporters/
│   └── utils/
│
├── requirements.txt
├── README.md
└── LICENSE
```

---

#  Technologies Used

| Technology | Purpose |
|------------|----------|
| Python 3.11 | Core Development |
| boto3 | AWS API Integration |
| AWS CloudTrail | Evidence Collection |
| JSON | Evidence Storage |
| HTML | Investigation Report |
| SHA-256 | Evidence Integrity |
| MITRE ATT&CK | Threat Mapping |

---

# ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/kathan10/Cloud-Detective-Kit.git
```

Move into the project directory

```bash
cd Cloud-Detective-Kit
```

Install dependencies

```bash
pip install -r requirements.txt
```

Configure AWS credentials

```bash
aws configure
```

---

#  Usage

Run the CloudTrail collector

```bash
python src/collectors/cloudtrail_collector.py
```

Run the analysis engine

```bash
python src/analyzers/run_analysis.py
```

Generate the HTML forensic report

```bash
python src/reporters/report_generator.py
```

---

#  Generated Report

The generated HTML report includes:

- Executive Summary
- Investigation Details
- Timeline Analysis
- Suspicious Activities
- Risk Summary
- MITRE ATT&CK Mapping
- Recommendations

---

#  Evidence Integrity

The toolkit stores collected evidence in JSON format and preserves evidence integrity throughout the investigation workflow.

---

#  Academic Context

This project was developed as part of the **M.Sc. Cybersecurity** program to demonstrate practical implementation of Digital Forensics and Incident Response techniques in cloud environments.

---

#  Future Improvements

Future enhancements may include:

- Multi-cloud support
- Additional AWS evidence collectors
- PDF report generation
- SIEM integration
- Automated IOC extraction
- Additional detection rules

---

# Author

**Kathan Majithiya**

M.Sc. Cybersecurity

Digital Forensics | Incident Response | Cloud Security

---

#  License

This project is licensed under the MIT License.

---

## Support

If you found this project useful, consider giving it a ⭐ on GitHub.
