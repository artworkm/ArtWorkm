# Playbook: SQL injection attacks

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
