# Legal Disclaimer

## Authorized Use Only

PortHawk is designed exclusively for **authorized penetration testing, security research,
and network administration** on systems you own or have explicit written permission to scan.

---

## Before You Scan Anything

You must obtain **written authorization** from the system owner before running PortHawk
against any target. "I think it's fine" is not written authorization.

This includes:
- Systems you administer but do not own (e.g., employer infrastructure)
- Cloud instances (check your provider's acceptable use policy — AWS, GCP, and Azure
  all have policies about port scanning that may require advance notification)
- Systems on shared networks (scanning a /24 affects everyone on that subnet)

---

## Legal Risk

Unauthorized port scanning is a criminal offense in many jurisdictions:

| Country | Law | What it covers |
|---------|-----|---------------|
| USA | Computer Fraud and Abuse Act (CFAA) | Unauthorized access to computer systems |
| UK | Computer Misuse Act 1990 | Unauthorized access, intent to impair |
| Germany | §202a StGB | Unauthorized data access |
| EU | Directive 2013/40/EU | Attacks against information systems |

This list is not exhaustive. Your country likely has equivalent laws.

---

## What This Tool Does Not Do

PortHawk:
- Does **not** exploit vulnerabilities — it only identifies open ports and services
- Does **not** attempt authentication bypass or credential brute-forcing
- Does **not** modify or delete data on target systems
- Does **not** store results anywhere outside your local machine

That said, identifying open ports and services is the first step in many attack chains.
That is exactly why it belongs in the hands of defenders and authorized testers.

---

## Liability

The author (Jakob Bartoschek) and any contributors to PortHawk assume **zero liability**
for any misuse of this tool. You are responsible for knowing and following the laws of
your jurisdiction before running any network scan.

If you're unsure whether you have authorization, you don't.
