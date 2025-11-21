# ERP System – Cybersecurity Track

## Overview
This repository contains the cybersecurity-focused deliverables for the ERP system developed for Konecta. It focuses on **Access Control Policies**, **Incident Response Plan**, **Security Requirements**, and **Security Validation**, ensuring the ERP system meets industry-standard cybersecurity practices.

> **Note:** The source code is not included in this repository; only documentation, testing reports, and validation results are provided.

## 📁 Repository Structure

ERP-Cybersecurity/
├── ERP Project - Cybersecurity team.pdf # Complete security documentation
├── Automated_Static_Scan.sh # SAST automation script
├── Automated_Dynamic_Run.sh # DAST automation script
└── reports/ # Generated security reports
├── combined_static_report.csv # Consolidated SAST findings
└── combined_dynamic_report.csv # Consolidated DAST findings


## 🛡️ Cybersecurity Deliverables

### 1. Security Documentation
- **ERP Security Architecture**: Architecture overview and description of implemented security controls
- **RBAC Policy**: Role-based access control framework with user roles, permissions, and enforcement guidelines
- **Security Requirements**: Functional and non-functional security requirements for the ERP system
- **Incident Response Plan (IRP)**: Documented procedures for detecting, responding to, and recovering from security incidents
- **Security Validation Report**: Consolidated report from testing and validation activities

### 2. Static Analysis (SAST)
**Tools Used**: `Snyk`, `Gitleaks`, `Semgrep`, custom scripts

**Purpose**: Identify potential vulnerabilities in system components without executing the code

**Scope**: All backend services and modules (Authentication, HR, Finance, Inventory, Reporting)

**Deliverables**:
- PDF reports highlighting findings and severity
- CSV reports with consolidated findings
- Recommendations for remediation

### 3. Dynamic Analysis (DAST)
**Tools Used**: `Docker CLI`, `ffuf`, `Nikto`, `tcp-probe`, `netcat`, `psql`, custom scripts

**Purpose**: Test the ERP system in runtime to validate access control, input validation, and API security

**Target Services**:
- Authentication Service (8081)
- HR Service (8083) 
- Finance Service (8082)
- API Gateway (8080)
- Frontend (4200)
- Report Service (8085)

**Deliverables**:
- Dynamic testing reports with severity and detailed logs
- Evidence of RBAC enforcement, SQL injection tests, and privilege escalation checks

### 4. Security Validation
- **RBAC Enforcement**: Verification that users only access authorized resources
- **Compliance Checks**: Security requirements reviewed against system behavior (GDPR, ISO 27001)
- **Consolidated Reports**: Aggregated results from static and dynamic tests for full coverage
- **Penetration Test Simulations**: Comprehensive testing scenarios with evidence collection

## Quick Start

### Prerequisites
- Kali Linux environment (or similar)
- Docker and Docker Compose
- Required tools: `jq`, `curl`, `nc`, `nikto`, `ffuf`, `gitleaks`, `snyk`, `semgrep`

### Installation & Usage
```bash
# Clone the repository
git clone https://github.com/<username>/ERP-Cybersecurity.git
cd ERP-Cybersecurity

# Make scripts executable
chmod +x Automated_Static_Scan.sh Automated_Dynamic_Run.sh

# Run security scans
./Automated_Static_Scan.sh    # Static analysis
./Automated_Dynamic_Run.sh    # Dynamic analysis (ensure services are running)
