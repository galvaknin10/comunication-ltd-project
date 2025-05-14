# Password Policy
MIN_PASSWORD_LENGTH = 8
MAX_LOGIN_ATTEMPTS = 3
FORCE_PASSWORD_CHANGE_AFTER_LOGINS = 3

# Common passwords to block
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "1234567890",
    "qwerty", "letmein", "admin", "welcome", "abc123",
    "iloveyou", "123123", "000000", "1q2w3e4r", "monkey",
    "football", "dragon", "baseball", "master", "sunshine"
}


# Regex validation pattern (at least one of each: upper, lower, digit, special char)
PASSWORD_COMPLEXITY_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).+$"
GUIDLINE_DESCRIPTION = "password needs to contain at least one of each: upper, lower, digit, special char"
