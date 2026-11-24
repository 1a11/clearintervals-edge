# Security Policy

## Vulnerability Severity

We classify vulnerabilities based on their actual security impact and the conditions required for exploitation.

| Severity | Description |
|---|---|
| **Critical** | Critical security control bypass, gateway identity compromise, or unauthorized access to data belonging to other users or sources. |
| **High** | Authentication or authorization bypass, data source impersonation, credential compromise, or breach of data stream isolation. |
| **Medium** | Significant exposure of sensitive information, buffer integrity violations, or bypass of individual security controls. |
| **Low** | Limited security weaknesses with reproducible but minor impact. |

Severity is determined by the maintainers after reproducing and evaluating the reported vulnerability. The assigned severity may differ from the researcher's initial assessment.

## Vulnerability Scope

### In Scope

We are interested in reproducible vulnerabilities affecting the gateway's security mechanisms, including:

- Authentication and authorization bypass.
- Device and data source identity spoofing.
- Reuse or unauthorized transfer of registration licenses and credentials.
- Bypass of certificate validation or cryptographic security mechanisms.
- Unauthorized data submission or modification on behalf of other sources.
- Isolation failures between bindings and data streams.
- Data spoofing, tampering, corruption, or replay through the gateway buffer.

### Out of Scope

The following issues are not eligible:

- Extraction of credentials or secrets from containers.
- Docker, container runtime, or underlying OS vulnerabilities unrelated to gateway code.
- Container escapes or unauthorized access to the host system.
- Third-party dependency vulnerabilities without demonstrated impact on the gateway.
- Exploitation requiring prior root or administrator privileges.
- Attacks requiring physical access to hardware.
- Configuration issues requiring administrative access to the gateway.
- Functional bugs without security implications.
- Performance or stability issues that do not compromise documented security controls.
- Theoretical vulnerabilities without a reproducible exploitation scenario.
- Automated scanner findings without demonstrated security impact.
- Denial-of-service attacks requiring physical access or unreasonable attacker resources.
- Build system issues and credential leaks unrelated to a vulnerability in the gateway's security boundary.

## Reporting Requirements

We accept reports of previously unknown, reproducible vulnerabilities with a demonstrated security impact.

A report should include:

- **Affected version:** The project version, release, or commit hash.
- **Description:** A concise explanation of the vulnerability and its potential impact.
- **Reproduction steps:** A clear, step-by-step exploitation scenario.
- **Proof of Concept:** A working PoC sufficient to reproduce and verify the issue.
- **Impact assessment:** An explanation of what an attacker could achieve by exploiting the vulnerability.

Reports should be submitted following the responsible disclosure instructions described in this repository's `SECURITY.md`.

## Testing Rules

Security testing is permitted exclusively on local builds and infrastructure owned or controlled by the researcher.

The following activities are prohibited:

- Testing against production environments.
- Testing against infrastructure belonging to third parties.
- Accessing, modifying, or disrupting data that does not belong to the researcher.
- Continuing exploitation after a vulnerability has been successfully confirmed.

Once a vulnerability is confirmed, testing and further exploitation must stop. Additional verification should be coordinated with the maintainers.

## Rewards

Rewards are provided in the form of merchandise. There is no cash alternative.

The type and value of merchandise awarded depend on the number and severity of valid vulnerabilities reported. Critical and high-severity findings receive priority.

Rewards are issued only after independent reproduction and confirmation by the maintainers.

Priority is given to the first complete and valid report of a vulnerability. Duplicate reports are not eligible for additional rewards.

## Coordinated Disclosure

Please do not publicly disclose vulnerability details, reproduction steps, or PoC code without prior agreement from the maintainers.

We ask researchers to allow reasonable time for investigation and remediation before any coordinated public disclosure.

The maintainers reserve the right to determine vulnerability eligibility, severity, and reward allocation based on the demonstrated impact and quality of the submitted report.
