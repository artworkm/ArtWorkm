from app import rules


def test_bruteforce_triggers_on_fifth_failure():
    for _ in range(4):
        assert rules.check_bruteforce(
            1, "9.9.9.1", False
        ) is None

    result = rules.check_bruteforce(
        1, "9.9.9.1", False
    )

    assert result[0] == "BruteForce"


def test_successful_logins_never_trigger():
    for _ in range(10):
        assert rules.check_bruteforce(
            1, "9.9.9.2", True
        ) is None


def test_bruteforce_counts_are_per_organization():
    for _ in range(4):
        rules.check_bruteforce(
            1, "9.9.9.3", False
        )

    result = rules.check_bruteforce(
        2, "9.9.9.3", False
    )

    assert result is None


def test_sqli_detected():
    result = rules.check_sqli(
        "/login?u=admin' OR 1=1 --"
    )

    assert result[0] == "SQLInjection"


def test_normal_path_not_flagged():
    assert rules.check_sqli("/products/42") is None