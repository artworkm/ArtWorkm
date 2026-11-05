import re
import time
from collections import defaultdict, deque


# Store failed login timestamps by organization and source IP.
failed_logins = defaultdict(deque)

# Brute-force detection settings.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300  # 5 minutes


def check_bruteforce(*args):
    """
    Supports both interfaces:

    Legacy Phase 1B:
        check_bruteforce(source_ip, success) -> bool

    Phase 1C:
        check_bruteforce(org_id, source_ip, success)
        -> (label, confidence, severity) or None
    """

    if len(args) == 2:
        # Preserve the original Phase 1B interface.
        org_id = "legacy"
        source_ip, success = args
        new_interface = False

    elif len(args) == 3:
        # New organization-aware Phase 1C interface.
        org_id, source_ip, success = args
        new_interface = True

    else:
        raise TypeError(
            "check_bruteforce expects either 2 or 3 arguments"
        )

    if not source_ip or success is not False:
        return None if new_interface else False

    current_time = time.time()
    tracker_key = (org_id, source_ip)
    attempts = failed_logins[tracker_key]

    # Remove attempts older than the five-minute window.
    while attempts and current_time - attempts[0] > BRUTE_FORCE_WINDOW:
        attempts.popleft()

    attempts.append(current_time)

    detected = len(attempts) >= BRUTE_FORCE_THRESHOLD

    if new_interface:
        if detected:
            return ("BruteForce", 0.90, "high")
        return None

    return detected


# Basic SQL injection patterns.
SQL_INJECTION_PATTERN = re.compile(
    r"(\bunion\b\s+.*?\bselect\b|"
    r"\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|"
    r"(--|#)|"
    r"\bdrop\b\s+table\b|"
    r"\binsert\b\s+into\b)",
    re.IGNORECASE | re.DOTALL
)


def check_sql_injection(value: str) -> bool:
    """
    Original Phase 1B interface.
    Return True if the supplied text matches a basic SQL injection pattern.
    """

    if not value:
        return False

    return bool(SQL_INJECTION_PATTERN.search(value))


def check_sqli(path: str):
    """
    Phase 1C interface.
    Return a detection tuple when a SQL injection pattern is found,
    otherwise return None.
    """

    if check_sql_injection(path):
        return ("SQLInjection", 0.95, "high")

    return None