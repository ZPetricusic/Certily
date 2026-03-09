# Certily - The ADCS Honeypot Template Creator

```
_________                __  .__.__
\_   ___ \  ____________/  |_|__|  | ___.__. 
/    \  \/_/ __ \_  __ \   __\  |  |<   |  |
\     \___\  ___/|  | \/|  | |  |  |_\___  |
 \______  /\___  >__|   |__| |__|____/ ____|
        \/     \/                    \/
```

> A PowerShell module used to deploy deceptive Active Directory Certificate Services (ADCS) certificate templates, using targeted ACEs to appear vulnerable to well-known ESC exploitation techniques enumerated by widely used tools, such as Certipy, Certify, and Locksmith.

---

## Before We Begin

This module has been explained in further detail on our blogposts ([Lying to your fACE | Easy way to setup ADCS Honeypot](https://adhdmurky.github.io/posts/post2/) and [Lying to your fACE | Easy way to setup ADCS Honeypot | Part #2](https://kerberpoasting.medium.com/lying-to-your-face-easy-way-to-setup-adcs-honeypot-part-2-b59042058919)) if you'd like to understand the reasoning further. Also, the related talk at [BSides Zagreb 2026](https://bsideszagreb.com/) has been recorded if you prefer to ingest your content that way. Anyway, thanks for checking out Certily, hope you find it useful! :)

## Overview

Certily can be used to create honeypot certificate templates in an Active Directory environment. The templates appear exploitable to attackers during enumeration (e.g. via tools like Certipy or Certify), but are hardened through the use of deny-read (and deny-write, in the case of ESC4) ACLs over the `Domain Users` group to prevent actual exploitation.

The module can also be configured to optionally trigger a [Canary Token](https://canarytokens.org/) alert every time a Certily template is requested. This is especially useful for 'one-man-band' IT or security teams, where resources are sparse.

### How It Works

1. First, a certificate template is created in AD with a **genuinely vulnerable configuration**
2. Protective properties are then modified in AD - e.g. requiring manager approval (`msPKI-Enrollment-Flag`) or a recovery agent signature (`msPKI-RA-Signature`)
3. Those protective properties are hidden from `Domain Users` via deny-read ACLs, so enumeration tools see only the "vulnerable" configuration
4. Exploitation attempts fail with the appropriate error message (e.g., that a certificate requires a RA signature or that it is pending)
5. An appropriate security event will be generated (4662/F for ESC4 and 4886/S for the others)
6. Uhh, profit?

---

## Supported ESC Types

| ESC Type | Description | Protection Mechanism |
|----------|-------------|----------------------|
| **ESC1** | Client authentication with user-controlled SAN | RA Signature or CA Manager Approval |
| **ESC2** | Any Purpose EKU template + SAN | RA Signature or CA Manager Approval |
| **ESC3** | Certificate Request Agent EKU present | RA Signature or CA Manager Approval |
| **ESC4** | Vulnerable ACE allowing template modification | Explicit deny-write on critical properties + RA Signature or CA Manager Approval |
| **ESC9** | `NO_SECURITY_EXTENSION` flag set | RA Signature (automatic) |
| **ESC15** | Legacy schema version 1 template + SAN | CA Manager Approval (automatic) |

---

## Prerequisites

- Domain Admin or Enterprise Admin privileges
- Active Directory Certificate Services (ADCS) installed and configured
- The following PowerShell modules must be available:
  - `ActiveDirectory`
  - `ADCSAdministration`

---

## Installation

Clone or download this repository, then import the module:

```powershell
Import-Module .\Certily.psd1
```

Usage instructions are displayed automatically when the module is loaded.

---

## Usage

### Create a Honeypot Template

```powershell
New-CertilyTemplate -TemplateName <string> -ESCType <ESC1|ESC2|ESC3|ESC4|ESC9|ESC15> [-UseCanaryTokens]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-TemplateName` | Yes | The name of the certificate template to create |
| `-ESCType` | Yes | The ESC vulnerability type to simulate |
| `-UseCanaryTokens` | No | Set up a WMI event subscription to fire a Canary Token alert on enrollment |

> **Note:** Canary Token alerting is not supported for ESC4 templates, as ESC4 relies on AD object (template) modifications, which are monitored using the 4662 event ID after a SACL is set. However, depending on the targeted DC, the event may or may not trigger on a DC configured for the Canary token, hence why it is not supported. ESC3 honeypots are also supported but are uncommon in real environments - consider ESC1 or ESC2 for more convincing lures.

#### Examples

```powershell
# Deploy an ESC1 honeypot with Canary Token alerting
New-CertilyTemplate -TemplateName "ESC1-Test" -ESCType "ESC1" -UseCanaryTokens

# Deploy a convincingly named ESC2 honeypot
New-CertilyTemplate -TemplateName "TotallyLegitTemplate" -ESCType "ESC2"

# Deploy an ESC3 honeypot with alerting
New-CertilyTemplate -TemplateName "CertificateRequestAgent" -ESCType "ESC3" -UseCanaryTokens

# Deploy an ESC4 honeypot
New-CertilyTemplate -TemplateName "ESC4-Test" -ESCType "ESC4"

# Deploy an ESC9 honeypot with alerting
New-CertilyTemplate -TemplateName "Cert4NDES" -ESCType "ESC9" -UseCanaryTokens

# Deploy an ESC15 honeypot
New-CertilyTemplate -TemplateName "ESC15-Test" -ESCType "ESC15"
```

---

### Remove a Honeypot Template

```powershell
Remove-CertilyTemplate -TemplateName <string> [-RemoveCanaryToken]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-TemplateName` | Yes | Name of the template to remove |
| `-RemoveCanaryToken` | No | Also remove the WMI event subscription created for this template |

```powershell
# Remove a template and its associated Canary Token WMI trigger
Remove-CertilyTemplate -TemplateName "ESC1-Test" -RemoveCanaryToken
```

> **Warning:** `Remove-CertilyTemplate` can remove **any** certificate template from AD. Always verify the correct template is selected before confirming deletion.

---

## Detection & Alerting

Certily supports two alerting approaches:

### 1. Canary Token Alerts (via WMI)
When `-UseCanaryTokens` is specified, Certily creates a WMI event subscription that listens for Security Event **4886** (Certificate Services received a certificate request) matching the honeypot template name. On detection, it fires an HTTP POST to a [canarytokens.org](https://canarytokens.org/nest/) Web Bug URL containing the raw event log message.

> WMI-based alerting is best-effort. For production environments, ship event logs to a SIEM for more reliable detection.

### 2. Windows Event Logs
Certily configures **local** audit policy for **Certification Services** (success + failure) - DS Access is not configured as this should be deployed on the Domain Controllers. The following events are relevant for monitoring:

| Event ID | Source | Meaning |
|----------|--------|---------|
| **4886/S** | Security | A certificate was requested - watch for your template name in the message |
| **4662/F** | Security | Directory Services Access - triggered on ESC4 write-failure attempts (requires DS Access auditing for Failure events) |

> Certily only modifies the **local** audit policy. Ensure no conflicting GPO overrides this setting.

### ESC4-Specific: Failure SACL
For ESC4 templates, Certily additionally sets a **Failure SACL** on the AD object, auditing `WriteDacl`, `WriteOwner`, `WriteProperty`, and `GenericWrite` attempts by Domain Users. This generates Event ID **4662/F** when an attacker tries (and fails) to modify the template's critical properties.

---

## Module Structure

```
Certily/
├── Certily.psd1            # Module manifest
├── Certily.psm1            # Module entry point (loads help on import)
└── src/
    ├── ACL.ps1             # ACL & SACL management (Set-TemplateACL, Hide-Properties, etc.)
    ├── canary.ps1          # Canary Token & WMI subscription management
    ├── constants.ps1       # Enums, GUIDs, and shared constants
    ├── newTemplate.ps1     # New-CertilyTemplate (main creation function)
    ├── removeTemplate.ps1  # Remove-CertilyTemplate (cleanup function)
    ├── templateConfigs.ps1 # Per-ESC template attribute definitions
    └── utils.ps1           # Helper utilities (OID generation, admin checks, etc.)
```

---

## Security Considerations

- **DC Consistency:** Certily pins all AD operations to a single domain controller (the current logon DC) to avoid replication race conditions during template creation and hardening.
- **Auditing:** The module enables `Certification Services` auditing locally. Verify this isn't overridden by a GPO in your environment.
- **Deny ACLs:** Protection is enforced via deny-read and deny-write ACLs applied to `Domain Users`. These do not affect Domain/Enterprise Admins or Domain Computers.

---

## Authors

**Josip Pavičić** ([@ADHDMurky](https://www.linkedin.com/in/josip-pavi6-5b29b7255/)) & **Zdravko Petričušić** ([@_zpetricusic](https://x.com/_zpetricusic))

---

## Tags

`ActiveDirectory` · `ADCS` · `Honeypot` · `ESC1` · `ESC2` · `ESC3` · `ESC4` · `ESC9` · `ESC15` · `Canaries` · `PowerShell`
