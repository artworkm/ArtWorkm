QUERY_FOR_LABEL = {
    "BruteForce": (
        "brute force password guessing repeated failed logins mitigation"
    ),
    "SQLInjection": (
        "SQL injection attack on web application prevention and response"
    ),
    "DoS": (
        "network denial of service attack mitigation"
    ),
    "DDoS": (
        "distributed denial of service flood mitigation"
    ),
    "PortScan": (
        "network service discovery port scanning reconnaissance"
    ),
    "WebAttack": (
        "web application attack exploiting public-facing application"
    ),
    "Bot": (
        "botnet command and control communication infected host"
    ),
}


ATTACK_HINT = {
    "BruteForce": "T1110 Brute Force",
    "SQLInjection": "T1190 Exploit Public-Facing Application",
    "WebAttack": "T1190 Exploit Public-Facing Application",
    "PortScan": (
        "T1046 Network Service Discovery "
        "(also T1595 Active Scanning)"
    ),
    "DoS": (
        "T1499 Endpoint Denial of Service / "
        "T1498 Network Denial of Service"
    ),
    "DDoS": "T1498 Network Denial of Service",
    "Bot": (
        "T1071 Application Layer Protocol "
        "(command and control)"
    ),
}