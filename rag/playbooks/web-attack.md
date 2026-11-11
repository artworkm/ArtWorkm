# Playbook: Web application attacks

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
