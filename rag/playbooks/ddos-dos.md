# Playbook: Denial-of-service and distributed denial-of-service

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
