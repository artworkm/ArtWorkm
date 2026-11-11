from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLAYBOOKS = ROOT / "rag" / "playbooks"
PLAYBOOKS.mkdir(parents=True, exist_ok=True)

documents = {
    "brute-force.md": """# Playbook: Brute-force login attacks

## What it looks like
Repeated failed login attempts from one source IP, or attempts against one account from many IP addresses. Password spraying and credential stuffing may produce similar patterns. Related MITRE ATT&CK technique: T1110 Brute Force.

## First checks (analyst)
1. Determine the number and frequency of failed logins.
2. Check whether a successful login followed the failures.
3. Identify targeted accounts and whether any are privileged or service accounts.
4. Compare source IPs, locations, user agents and normal login patterns.
5. Check whether the activity matches a known vulnerability scan or legitimate user behaviour.

## Containment (needs human approval)
- Temporarily rate-limit or block confirmed malicious source IPs.
- Require password resets for accounts with evidence of compromise.
- Revoke suspicious active sessions and tokens.
- Apply account protection measures without unnecessarily locking out legitimate users.

## Prevention
Enable multi-factor authentication, progressive login delays and rate limiting. Use strong password policies and breached-password checks. Monitor authentication failures and successful logins together. Alert on unusual login locations, impossible travel and repeated attempts across multiple accounts. Preserve authentication logs for investigation.
""",

    "sql-injection.md": """# Playbook: SQL injection attacks

## What it looks like
Unexpected SQL syntax or database commands appearing in web requests, query parameters, headers or form fields. Indicators include suspicious quote characters, UNION SELECT patterns, boolean conditions and database error messages. Related MITRE ATT&CK technique: T1190 Exploit Public-Facing Application.

## First checks (analyst)
1. Identify the affected endpoint, parameter and application.
2. Determine whether the requests were blocked, generated errors or returned unexpected data.
3. Review web server, application and database logs around the event.
4. Check whether the same source attempted other endpoints or payload variations.
5. Ask the application owner to verify whether sensitive records may have been accessed.

## Containment (needs human approval)
- Apply a temporary web application firewall rule for confirmed malicious patterns.
- Restrict access to the affected endpoint if exploitation is ongoing.
- Preserve relevant request, application and database logs.
- Escalate suspected data exposure to the incident-response team.

## Prevention
Use parameterized queries and prepared statements. Avoid building SQL commands by concatenating untrusted input. Apply least-privilege database permissions and validate input using appropriate allowlists. Keep application frameworks and database software updated. Test applications with authorized security testing and monitor database errors and unusual query activity.
""",

    "ddos-dos.md": """# Playbook: Denial-of-service and distributed denial-of-service

## What it looks like
A sudden increase in traffic, connection requests or resource consumption that makes a service slow or unavailable. A DoS attack may originate from one source, while DDoS commonly involves many distributed sources. Related MITRE ATT&CK techniques: T1498 Network Denial of Service and T1499 Endpoint Denial of Service.

## First checks (analyst)
1. Confirm the affected service, network segment and start time.
2. Compare traffic volume and request rates with normal baselines.
3. Examine source distribution, protocols, ports and traffic patterns.
4. Check CPU, memory, connection counts and application response times.
5. Rule out legitimate traffic spikes, deployments or infrastructure failures.

## Containment (needs human approval)
- Engage the hosting provider, network operations team or DDoS protection provider.
- Apply suitable rate limits, filtering or upstream mitigation.
- Protect critical services and communicate availability impacts.
- Preserve traffic statistics and relevant network logs.

## Prevention
Use upstream DDoS protection, traffic filtering, rate limiting and resilient infrastructure. Configure sensible connection and request limits. Monitor bandwidth, connection counts and service health. Maintain an incident-response contact list and test mitigation procedures before an emergency.
""",

    "port-scan.md": """# Playbook: Network port scanning

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
""",

    "botnet-c2.md": """# Playbook: Botnet command-and-control activity

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
""",

    "web-attack.md": """# Playbook: Web application attacks

## What it looks like
Suspicious HTTP requests targeting public-facing applications. Indicators can include unexpected paths, traversal sequences, unusual parameters, malicious scripts, authentication abuse and attempts to exploit application vulnerabilities. Related MITRE ATT&CK technique: T1190 Exploit Public-Facing Application.

## First checks (analyst)
1. Identify the affected application, endpoint, source and request time.
2. Review HTTP method, path, parameters, response status and application logs.
3. Determine whether the request was blocked or reached vulnerable application code.
4. Check for unexpected file access, authentication changes or database activity.
5. Correlate the event with other requests from the same source and related alerts.

## Containment (needs human approval)
- Apply targeted WAF rules or temporary access restrictions.
- Disable an affected vulnerable feature if exploitation is confirmed and business impact is understood.
- Preserve web, application and database logs.
- Escalate suspected data exposure or unauthorized access.

## Prevention
Follow secure development practices and validate untrusted input. Apply authentication, authorization and session-management controls consistently. Keep application dependencies patched. Use a web application firewall as an additional defensive layer, not a substitute for secure code. Perform authorized security testing and monitor unusual request patterns.
""",
}

for filename, content in documents.items():
    path = PLAYBOOKS / filename
    path.write_text(content.strip() + "\n", encoding="utf-8")
    print(f"Created: {path.name}")

print(f"\nTotal playbooks created: {len(documents)}")