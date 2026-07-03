# KEV Additions — July 2026

CVEs added to the CISA Known Exploited Vulnerabilities catalog this month: **2**


## CVE-2026-45659 — Microsoft SharePoint Server Deserialization of Untrusted Data Vulnerability
- **Vendor/Product:** Microsoft / SharePoint Server
- **Added to KEV:** 2026-07-01
- **Remediation due:** 2026-07-04
- **Known ransomware use:** Unknown
- **Description:** Microsoft SharePoint Server contains a deserialization of untrusted data vulnerability which allows an authorized attacker to execute code over a network.
- **Required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## CVE-2026-48558 — SimpleHelp Authentication Bypass Vulnerability
- **Vendor/Product:** SimpleHelp  / SimpleHelp
- **Added to KEV:** 2026-06-29
- **Remediation due:** 2026-07-02
- **Known ransomware use:** Unknown
- **Description:** SimpleHelp contains an authentication bypass vulnerability in the OIDC authentication flow. When OIDC authentication is configured, identity tokens submitted during login are accepted without verifying their cryptographic signature. In a vulnerable configuration, a remote, unauthenticated attacker can submit a forged token containing arbitrary identity claims to obtain a fully authenticated technician session. In some configurations, this may also allow bypass of multi-factor authentication.
- **Required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

---
*Data: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · Tracker by [Tayven Cyber Security](https://tayvensec.com)*
