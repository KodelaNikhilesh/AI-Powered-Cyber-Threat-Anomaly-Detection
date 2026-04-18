import string
import random
import math

# ==============================
# PASSWORD ANALYSIS
# ==============================
def analyze_password(password: str) -> dict:
    score = 0

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    if len(password) >= 8:
        score += 2
    if has_upper:
        score += 2
    if has_lower:
        score += 2
    if has_digit:
        score += 2
    if has_special:
        score += 2

    # Strength
    if score <= 2:
        strength = "Very Weak"
    elif score <= 4:
        strength = "Weak"
    elif score <= 6:
        strength = "Moderate"
    elif score <= 8:
        strength = "Strong"
    else:
        strength = "Very Strong"

    # Entropy + crack time
    charset = 0
    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digit:
        charset += 10
    if has_special:
        charset += 32

    if charset == 0:
        charset = 1

    entropy = len(password) * math.log2(charset)

    guesses_per_sec = 1e9
    seconds = (2 ** entropy) / guesses_per_sec

    crack_time = format_time(seconds)

    return {
        "score": score,
        "strength": strength,
        "crack_time": crack_time
    }


# ==============================
# TIME FORMAT
# ==============================
def format_time(seconds):
    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds/60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds/3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds/86400)} days"
    elif seconds < 315360000:
        return f"{int(seconds/31536000)} years"
    else:
        return "Centuries+"


# ==============================
# PASSWORD GENERATOR
# ==============================
def generate_password(options: dict) -> str:
    chars = ""

    if options.get("upper"):
        chars += string.ascii_uppercase
    if options.get("lower"):
        chars += string.ascii_lowercase
    if options.get("digits"):
        chars += string.digits
    if options.get("special"):
        chars += string.punctuation

    length = int(options.get("length", 12))

    if not chars:
        chars = string.ascii_letters + string.digits

    return "".join(random.choice(chars) for _ in range(length))


# ==============================
# 🔥 PASSWORD ENHANCEMENT
# ==============================
def enhance_password(pwd: str) -> str:

    if not pwd:
        return ""

    base = pwd.capitalize()

    replacements = {
        'a': '@',
        's': '$',
        'i': '1',
        'o': '0',
        'e': '3'
    }

    for k, v in replacements.items():
        base = base.replace(k, v)

    numbers = ''.join(random.choice(string.digits) for _ in range(3))
    special = ''.join(random.choice("@#$%^&*") for _ in range(2))

    return base + special + numbers