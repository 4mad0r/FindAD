# findAD

🔎 **findAD** is a lightweight tool to enumerate and check **Active Directory delegations** (Unconstrained, Constrained, and Resource-Based Constrained Delegations).  
It helps red/blue teams quickly identify delegation configurations that can be abused in Kerberos delegation attacks.

---

## ✨ Features

- Detect **Unconstrained Delegation (UCD)** via `userAccountControl` flag.
- Detect **Constrained Delegation (KCD)** via `msDS-AllowedToDelegateTo` (+ optional S4U/Protocol Transition).
- Detect **Resource-Based Constrained Delegation (RBCD)** via `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- Parses RBCD Security Descriptors and resolves **SIDs to human-readable accounts**.
- Works against any LDAP endpoint (389/636).

---

## ⚡ Quick start

### Installation
```bash
git clone https://github.com/youruser/findAD.git
cd findAD
pip install ldap3

```
##  Arguments
-d DC           Domain Controller IP or FQDN
-u USER         Bind user (UPN recommended)
-p PASS         Password (prompted if omitted)
-b BASE_DN      Base DN (if omitted, defaultNamingContext is queried)
-P PORT         LDAP port (default 389 or 636 if -s)
-s              Use LDAPS (636 by default if no -P)
-t TIMEOUT      Timeout in seconds (default: 10)
-f FILTER       LDAP filter (default: (objectClass=computer))
