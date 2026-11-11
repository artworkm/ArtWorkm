# Playbook: Botnet command-and-control activity

## What it looks like
A host repeatedly communicates with unusual external destinations, possibly using periodic connections, suspicious DNS requests, uncommon protocols or unexpected outbound traffic. Such patterns may indicate malware communicating with command-and-control infrastructure. Related MITRE ATT&CK techniques include T1071 Application Layer Protocol and other command-and-control techniques.

## First checks (analyst)
1. Identify the affected host, user, process and external destination.
2. Examine DNS queries, connection timing, destination reputation and traffic volume.
3. Check endpoint security alerts and running processes.
4. Compare the activity with known legitimate software and business services.
5. Determine whether other hosts show similar communication patterns.

## Containment (needs human approval)
- Isolate a confirmed compromised endpoint using an approved response procedure.
- Block verified malicious domains or IP addresses at suitable network controls.
- Preserve endpoint, DNS and network evidence before remediation.
- Escalate suspected credential theft or lateral movement.

## Prevention
Maintain endpoint detection and response coverage. Restrict unnecessary outbound connections and monitor unusual DNS and network behaviour. Keep systems patched, enforce least privilege and educate users about malicious attachments and downloads. Review threat-intelligence indicators carefully because reputation data can be incomplete or outdated.
