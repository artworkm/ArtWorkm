# Playbook: Brute-force login attacks

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
