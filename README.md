# findAD

🔎 **findAD** is a lightweight tool to enumerate and check **Active Directory delegations** (Unconstrained, Constrained, and Resource-Based Constrained Delegations).  
It helps red/blue teams quickly identify delegation configurations that can be abused in Kerberos delegation attacks.

---

## ✨ Features

- Detect **Unconstrained Delegation (UCD)** via `userAccountControl` flag.
- Detect **Constrained Delegation (KCD)** via `msDS-AllowedToDelegateTo` (+ optional S4U/Protocol Transition).
- Detect **Resource-Based Constrained Delegation (RBCD)** via `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- Parses RBCD Security Descriptors and resolves **SIDs to human-readable accounts**.
- Colorized output (red = vulnerable) or JSON mode for automation.
- Works against any LDAP endpoint (389/636).
- Short flags for connection, long flags for checks.

---

## ⚡ Quick start

### Installation
```bash
git clone https://github.com/youruser/findAD.git
cd findAD
pip install ldap3
