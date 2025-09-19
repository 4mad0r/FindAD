#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""

Lightweight tool to enumerate and check Active Directory delegations:
- Unconstrained Delegation (UCD)     -> userAccountControl: TRUSTED_FOR_DELEGATION (0x80000)
- Constrained Delegation (KCD)       -> msDS-AllowedToDelegateTo (+ optional S4U flag 0x1000000)
- Resource-Based Constrained (RBCD)  -> msDS-AllowedToActOnBehalfOfOtherIdentity (Security Descriptor)

Requirements:
  pip install ldap3

Quick examples:
  # Unconstrained
  python3 findAD.py -d DC_IP -u user@domain.local -p 'Passw0rd' --check-unconstrained

  # Constrained (KCD)
  python3 findAD.py -d DC_IP -u user@domain.local -p 'Passw0rd' --check-constrained

  # RBCD
  python3 findAD.py -d DC_IP -u user@domain.local -p 'Passw0rd' --check-rbcd

  # All checks (UCD + KCD + RBCD) + JSON
  python3 findAD.py -d DC_IP -u user@domain.local -p 'Passw0rd' -a --json

  # Change base DN and widen scope to include service users with SPN
  python3 findAD.py -d DC_IP -u user@domain.local -p 'Passw0rd' \
      -b 'DC=domain,DC=local' \
      -f '(|(objectClass=computer)(&(objectClass=user)(servicePrincipalName=*)))' \
      --check-constrained --check-rbcd
"""

import argparse
import getpass
import json
import sys
from ldap3 import Server, Connection, ALL, BASE

# ===== ANSI colors (use --no-color to disable) =====
class Color:
    RED   = "\033[91m"
    YEL   = "\033[93m"
    GRN   = "\033[92m"
    BOLD  = "\033[1m"
    RESET = "\033[0m"

def disable_colors():
    Color.RED = Color.YEL = Color.GRN = Color.BOLD = Color.RESET = ""

# ===== userAccountControl flags =====
UAC_TRUSTED_FOR_DELEGATION    = 0x80000      # 524288 (Unconstrained)
UAC_WORKSTATION_TRUST_ACCOUNT = 0x200        # 512 (Computer)
UAC_TRUSTED_TO_AUTH_FOR_DELEG = 0x1000000    # 16777216 (S4U - Protocol Transition)

def build_parser():
    epilog = r"""

Checks and how to read them
---------------------------
1) Unconstrained Delegation (UCD)
   - Detection: TRUSTED_FOR_DELEGATION bit in userAccountControl.
   - Risk: HIGH. Host can receive/forward user TGTs.
   - Output: marked as VULNERABLE (red) when the bit is set.

2) Constrained Delegation (KCD)
   - Detection: msDS-AllowedToDelegateTo contains target SPNs.
   - S4U (optional): TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION enables protocol transition.
   - Risk:
       * With S4U -> HIGH (marked VULNERABLE).
       * Without S4U -> MEDIUM/Contextual (still marked VULNERABLE because delegation is enabled).
   - Note: real risk depends on who controls the account, target SPNs, and exposure.

3) Resource-Based Constrained Delegation (RBCD)
   - Detection: msDS-AllowedToActOnBehalfOfOtherIdentity present on the TARGET object (Security Descriptor).
   - Risk: HIGH. Principals listed in the DACL can act on the resource.
   - Output: VULNERABLE when attribute is present.

----------------------------------------------------------------------------------------------------------
  __ _           _    _    ____  
 / _(_)_ __   __| |  / \  |  _ \ 
| |_| | '_ \ / _` | / _ \ | | | |
|  _| | | | | (_| |/ ___ \| |_| |
|_| |_|_| |_|\__,_/_/   \_\____/

"""
    p = argparse.ArgumentParser(
        description="Active Directory delegation enumeration (UCD, KCD, RBCD).",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=epilog
    )

    # Connection (short flags)
    p.add_argument('-d', required=True, metavar="DC", help='Domain Controller IP or FQDN')
    p.add_argument('-u', required=True, metavar="USER", help='Bind user (UPN recommended, e.g., user@domain.local)')
    p.add_argument('-p', metavar="PASS", help='Password (prompted if omitted)')
    p.add_argument('-b', dest='base_dn', help='Base DN (if omitted, defaultNamingContext is queried)')
    p.add_argument('-P', dest='port', type=int, default=None, help='LDAP port (defaults 389 or 636 if -s)')
    p.add_argument('-s', dest='use_ssl', action='store_true', help='Use LDAPS (636 by default if -P not specified)')
    p.add_argument('-t', dest='timeout', type=int, default=10, help='LDAP operation timeout in seconds')

    # Search scope
    p.add_argument('-f', dest='filter', default='(objectClass=computer)',
                   help="LDAP filter (default: '(objectClass=computer)')")

    # Checks (keep long for clarity)
    p.add_argument('--check-unconstrained', action='store_true', help='Check Unconstrained Delegation (UCD)')
    p.add_argument('--check-constrained',   action='store_true', help='Check Constrained Delegation (KCD)')
    p.add_argument('--check-rbcd',          action='store_true', help='Check Resource-Based Constrained Delegation (RBCD)')
    p.add_argument('-a', '--all',           action='store_true', help='Run all checks (UCD + KCD + RBCD)')

    # Output
    p.add_argument('--json', action='store_true', help='JSON output (for automation)')
    p.add_argument('--verbose', action='store_true', help='Verbose mode (show attributes and details)')
    p.add_argument('--no-color', action='store_true', help='Disable colored output')

    return p

def get_default_naming_context(conn, verbose=False):
    # Try to read defaultNamingContext and fallback to namingContexts, then to '*' and '+'
    try:
        conn.search('', '(objectClass=*)', BASE, attributes=['defaultNamingContext', 'namingContexts'])
    except Exception:
        conn.search('', '(objectClass=*)', BASE, attributes=['*', '+'])

    if not conn.entries:
        return None

    e = conn.entries[0]
    try:
        if 'defaultNamingContext' in e.entry_attributes_as_dict:
            return str(e['defaultNamingContext'].value)
    except Exception:
        pass

    ncs = e.entry_attributes_as_dict.get('namingContexts', [])
    if ncs:
        return str(ncs[0])
    return None

def connect_ldap(dc, user, password, use_ssl=False, port=None, timeout=10, verbose=False):
    server = Server(dc, port=port, use_ssl=use_ssl, get_info=ALL)
    if verbose:
        print(f"[*] Connecting to LDAP {dc}:{port or ('636' if use_ssl else '389')} (use_ssl={use_ssl})")
    try:
        conn = Connection(server, user=user, password=password, receive_timeout=timeout, auto_bind=True)
        return conn
    except Exception as e:
        print(f"[!] LDAP bind/connect error: {e}")
        sys.exit(1)

def safe_int(val, default=0):
    try:
        if val is None:
            return default
        return int(val)
    except Exception:
        try:
            return int(str(val))
        except Exception:
            return default

def check_unconstrained(conn, base_dn, ldap_filter, verbose=False):
    attributes = ['userAccountControl', 'sAMAccountName']
    try:
        conn.search(search_base=base_dn, search_filter=ldap_filter, attributes=attributes)
    except Exception as e:
        print(f"[!] Search error (UCD): {e}")
        return []

    results = []
    for entry in conn.entries:
        dn = str(entry.entry_dn)
        uac_val = safe_int(entry.userAccountControl.value, 0)
        if uac_val & UAC_TRUSTED_FOR_DELEGATION:
            results.append({
                'dn': dn,
                'sAMAccountName': str(entry.sAMAccountName) if 'sAMAccountName' in entry else None,
                'userAccountControl': uac_val,
                'flags': {
                    'workstation_trust_account': bool(uac_val & UAC_WORKSTATION_TRUST_ACCOUNT),
                    'trusted_for_delegation': True
                },
                'vulnerable': True
            })
    return results

def check_constrained(conn, base_dn, ldap_filter, verbose=False):
    attributes = ['msDS-AllowedToDelegateTo', 'userAccountControl', 'servicePrincipalName', 'sAMAccountName']
    try:
        conn.search(search_base=base_dn, search_filter=ldap_filter, attributes=attributes)
    except Exception as e:
        print(f"[!] Search error (KCD): {e}")
        return []

    results = []
    for entry in conn.entries:
        allowed = entry['msDS-AllowedToDelegateTo'].values if 'msDS-AllowedToDelegateTo' in entry else []
        if allowed:
            dn = str(entry.entry_dn)
            uac_val = safe_int(entry.userAccountControl.value, 0)
            s4u = bool(uac_val & UAC_TRUSTED_TO_AUTH_FOR_DELEG)
            spns = entry['servicePrincipalName'].values if 'servicePrincipalName' in entry else []
            sam = str(entry['sAMAccountName'].value) if 'sAMAccountName' in entry else None
            results.append({
                'dn': dn,
                'sAMAccountName': sam,
                'userAccountControl': uac_val,
                's4u_protocol_transition': s4u,
                'allowed_to_delegate_to': list(allowed),
                'servicePrincipalName': list(spns),
                'vulnerable': True,
                'severity': 'HIGH' if s4u else 'MEDIUM'
            })
    return results

def check_rbcd(conn, base_dn, ldap_filter, verbose=False):
    attributes = ['msDS-AllowedToActOnBehalfOfOtherIdentity', 'sAMAccountName']
    try:
        conn.search(search_base=base_dn, search_filter=ldap_filter, attributes=attributes)
    except Exception as e:
        print(f"[!] Search error (RBCD): {e}")
        return []

    results = []
    for entry in conn.entries:
        dn = str(entry.entry_dn)
        sam = str(entry['sAMAccountName'].value) if 'sAMAccountName' in entry else None
        sd_raw = entry['msDS-AllowedToActOnBehalfOfOtherIdentity'].value if 'msDS-AllowedToActOnBehalfOfOtherIdentity' in entry else None
        if sd_raw:
            try:
                size = len(sd_raw) if hasattr(sd_raw, '__len__') else None
            except Exception:
                size = None
            results.append({
                'dn': dn,
                'sAMAccountName': sam,
                'rbcd_sd_present': True,
                'rbcd_sd_size': size,
                'vulnerable': True
            })
    return results

def print_section_title(title):
    print(f"\n{Color.BOLD}{title}{Color.RESET}")

def print_vuln_line(prefix, dn, extra=None, severity=None):
    tag = f"{Color.RED}[VULNERABLE]{Color.RESET}"
    sev = f" {Color.YEL}(sev: {severity}){Color.RESET}" if severity else ""
    line = f"  - {tag} {prefix}: {dn}{sev}"
    print(line)
    if extra:
        for k, v in extra.items():
            if v is None:
                continue
            if isinstance(v, list):
                print(f"      {k} ({len(v)}):")
                for it in v:
                    print(f"        - {it}")
            else:
                print(f"      {k}: {v}")

def main():
    args = build_parser().parse_args()

    if args.no_color:
        disable_colors()

    # If no specific check is provided, default to --all for convenience
    if not any([args.check_unconstrained, args.check_constrained, args.check_rbcd, args.all]):
        args.all = True

    if args.all:
        args.check_unconstrained = args.check_constrained = args.check_rbcd = True

    password = args.p if args.p else getpass.getpass(prompt='Password: ')
    port = args.port if args.port is not None else (636 if args.use_ssl else 389)

    conn = connect_ldap(args.d, args.u, password, use_ssl=args.use_ssl, port=port, timeout=args.timeout, verbose=args.verbose)

    base_dn = args.base_dn or get_default_naming_context(conn, verbose=args.verbose)
    if not base_dn:
        print("[!] Could not obtain defaultNamingContext; specify -b / --base-dn explicitly")
        sys.exit(1)
    if args.verbose:
        print(f"[*] Using base DN: {base_dn}")

    out = {}

    if args.check_unconstrained:
        out['unconstrained'] = check_unconstrained(conn, base_dn, args.filter, verbose=args.verbose)

    if args.check_constrained:
        out['constrained'] = check_constrained(conn, base_dn, args.filter, verbose=args.verbose)

    if args.check_rbcd:
        out['rbcd'] = check_rbcd(conn, base_dn, args.filter, verbose=args.verbose)

    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    # Human-readable output with colors
    if args.check_unconstrained:
        print_section_title("[*] Unconstrained Delegation (UCD)")
        items = out.get('unconstrained') or []
        if not items:
            print("    (none found)")
        for r in items:
            print_vuln_line("UCD", r['dn'], extra={
                'sAMAccountName': r.get('sAMAccountName'),
                'userAccountControl': r.get('userAccountControl'),
                'flags': r.get('flags'),
            })

    if args.check_constrained:
        print_section_title("[*] Constrained Delegation (KCD)")
        items = out.get('constrained') or []
        if not items:
            print("    (none found)")
        for r in items:
            sev = r.get('severity')
            print_vuln_line("KCD", r['dn'], extra={
                'sAMAccountName': r.get('sAMAccountName'),
                'S4U/ProtocolTransition': r.get('s4u_protocol_transition'),
                'AllowedToDelegateTo': r.get('allowed_to_delegate_to'),
                'Own SPNs': r.get('servicePrincipalName') if args.verbose else None
            }, severity=sev)

    if args.check_rbcd:
        print_section_title("[*] Resource-Based Constrained Delegation (RBCD)")
        items = out.get('rbcd') or []
        if not items:
            print("    (none found)")
        for r in items:
            print_vuln_line("RBCD", r['dn'], extra={
                'sAMAccountName': r.get('sAMAccountName'),
                'SD length (bytes)': r.get('rbcd_sd_size')
            })

if __name__ == '__main__':
    main()
