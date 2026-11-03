
import re
import time
from collections import defaultdict, deque


# Store failed login timestamps for each source IP.
failed_logins = defaultdict(deque)

# Brute-force detection settings.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300  # 5 minutes


def check_bruteforce(source_ip: str, success: bool) -> bool:
    """
    Return True if an IP address has at least five
    failed login attempts within five minutes.
    """

    if not source_ip or success is not False:
        return False

    current_time = time.time()
    attempts = failed_logins[source_ip]

    # Remove attempts older than five minutes.
    while attempts and current_time - attempts[0] > BRUTE_FORCE_WINDOW:
        attempts.popleft()

    attempts.append(current_time)

    return len(attempts) >= BRUTE_FORCE_THRESHOLD


# Basic SQL injection patterns.
SQL_INJECTION_PATTERN = re.compile(
    r"(\bunion\b.*\bselect\b|"
    r"\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|"
    r"(--|#)|"
    r"\bdrop\b\s+table\b|"
    r"\binsert\b\s+into\b)",
    re.IGNORECASE
)


def check_sql_injection(value: str) -> bool:
    """
    Return True if the supplied text matches
    a basic SQL injection pattern.
    """

    if not value:
        return False

    return bool(SQL_INJECTION_PATTERN.search(value))
