"""Password policy (docs/SECURITY.md §2).

Rules enforced exactly once, at write time (user create, admin reset, self
change): minimum 12 characters, the password must not contain the username
(case-insensitive) and the password must not be in a deterministic built-in
list of the ~50 most common leaked passwords (no network lookup).
Violation reasons are Chinese and mapped to ``validation_failed`` by callers.
"""

from __future__ import annotations

MIN_PASSWORD_LENGTH = 12

# Deterministic, self-contained list of common leaked passwords. Kept small on
# purpose (docs/SECURITY.md §2: 拒绝常见泄露密码); long/common patterns are
# additionally caught by length and username checks. Values are lowercase.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456",
        "password",
        "12345678",
        "qwerty",
        "123456789",
        "12345",
        "1234",
        "111111",
        "1234567",
        "dragon",
        "123123",
        "baseball",
        "abc123",
        "football",
        "monkey",
        "letmein",
        "shadow",
        "master",
        "666666",
        "qwertyuiop",
        "123321",
        "mustang",
        "1234567890",
        "michael",
        "654321",
        "superman",
        "1qaz2wsx",
        "7777777",
        "121212",
        "000000",
        "qazwsx",
        "123qwe",
        "keyword",
        "charlie",
        "aa123456",
        "123456789a",
        "password1",
        "admin",
        "admin123",
        "root",
        "toor",
        "passw0rd",
        "iloveyou",
        "princess",
        "welcome",
        "sunshine",
        "flower",
        "login",
        "starwars",
        "trustno1",
        "p@ssword",
        "password1234",
        "qwerty1234",
        "111111111111",
        "123456789012",
        "password123456",
    }
)

REASON_TOO_SHORT = "密码长度至少 12 位"
REASON_CONTAINS_USERNAME = "密码不能包含用户名"
REASON_COMMON_PASSWORD = "密码为常见弱密码"  # noqa: S105 (a reason string, not a credential)


def validate_password(password: str, username: str) -> list[str]:
    """Return the list of violated rules (empty means the password is valid).

    ``username`` is only used for the substring check; an empty username skips
    that rule.
    """
    violations: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        violations.append(REASON_TOO_SHORT)
    if username and username.lower() in password.lower():
        violations.append(REASON_CONTAINS_USERNAME)
    if password.lower() in COMMON_PASSWORDS:
        violations.append(REASON_COMMON_PASSWORD)
    return violations
