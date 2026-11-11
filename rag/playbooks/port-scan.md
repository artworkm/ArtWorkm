# Playbook: Network port scanning

## What it looks like
One source host makes connection attempts to many destination ports or hosts. Sequential port access, repeated connection failures and service-probing patterns may indicate reconnaissance. Related MITRE ATT&CK technique: T1046 Network Service Discovery. External scanning may also relate to T1595 Active Scanning.

## First checks (analyst)
1. Identify the source, destination hosts, ports and time range.
2. Determine whether the scanning originates internally or externally.
3. Check whether the source belongs to an authorized vulnerability scanner.
4. Identify exposed services and any unexpected successful connections.
5. Review subsequent activity for exploitation attempts or unusual authentication.

## Containment (needs human approval)
- Restrict confirmed unauthorized scanning at appropriate network boundaries.
- Investigate an internal source host for compromise before isolating it.
- Review exposed services and disable unnecessary access through an approved change.
- Preserve firewall, flow and endpoint logs for investigation.

## Prevention
Maintain an inventory of authorized systems and exposed services. Close unnecessary ports, restrict administrative interfaces and apply network segmentation. Use firewalls and intrusion-detection monitoring. Schedule authorized vulnerability scans and distinguish their expected activity from unapproved reconnaissance.
