# ERP System – Cybersecurity Track

## Overview
This repository contains the cybersecurity-focused deliverables for the ERP system developed for Konecta. It focuses on **Access Control Policies, Incident Response Plan, Security Requirements, Security validation**, ensuring the ERP system meets industry-standard cybersecurity practices.  

**Note:** The source code is not included in this repository; only documentation, testing reports, and validation results are provided.


## Cybersecurity Deliverables

### 1. Security Documentation
- **ERP Security Architecture**: Architecture overview and description of implemented security controls.
- **RBAC Policy**: Role-based access control framework, including user roles, permissions, and enforcement guidelines.
- **Security Requirements**: Functional and non-functional security requirements for the ERP system.
- **Security Validation Report**: Consolidated report from testing and validation activities.

### 2. Static Analysis
- **Tools Used**: Snyk, Gitleaks, Semgrep,custom scripts
- **Purpose**: Identify potential vulnerabilities in system components without executing the code.
- **Deliverables**:
  - PDF reports highlighting findings and severity
  - Recommendations for remediation
- **Scope**:
  - All backend services and modules were analyzed (HR, Inventory, Reporting).

### 3. Dynamic Analysis
- **Tools Used**: Docker cli, nmap, fuff, Nikto, tcp port, custom scripts
- **Purpose**: Test the ERP system in runtime to validate access control, input validation, and API security.
- **Deliverables**:
  - Dynamic testing reports with severity and detailed logs
  - Evidence of RBAC enforcement, SQL injection tests, and privilege escalation checks

### 4. Incident Response Plan (IRP)
- Documented procedures for detecting, responding to, and recovering from security incidents.
- Includes escalation procedures, containment strategies, and post-incident review.

### 5. Security Validation
- **RBAC Enforcement**: Verification that users only access authorized resources.
- **Compliance Checks**: All security requirements reviewed against system behavior.
- **Consolidated Reports**: Aggregated results from static and dynamic tests for full coverage.

---

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/<username>/ERP-Cybersecurity.git
   cd ERP-Cybersecurity

