"""Built-in demonstration wordlist.

This list is used exclusively for educational purposes in the
SQL Injection lab. It combines:

  - The 200 most common passwords (HIBP / SecLists / RockYou top)
  - Common name + number combos students tend to use in demos
  - Password-policy-compliant variants ("P@ssw0rd", "Admin@123" …)

The list is intentionally short (< 500 entries) so the demo
completes in seconds and students see the "wow moment" quickly.
No custom wordlists, GPU tools, or Hashcat are used.
"""

WORDLIST: list[str] = [
    # ── Top 100 most common passwords ──────────────────────────
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine",
    "master", "welcome", "shadow", "ashley", "football",
    "jesus", "michael", "ninja", "mustang", "password1",
    "123456a", "abc123", "letmein", "monkey", "1234567890",
    "superman", "batman", "thomas", "charlie", "donald",
    "password123", "qwerty123", "iloveyou1", "admin", "admin123",
    "root", "toor", "pass", "test", "guest",
    "login", "hello", "welcome1", "changeme", "secret",
    "god", "sex", "love", "money", "freedom",
    "killer", "hacker", "maggie", "princess", "pepper",

    # ── Policy-compliant common variants ───────────────────────
    "Password1", "Password1!", "P@ssw0rd", "P@ssword1",
    "Admin@123", "Admin@2024", "Admin@2025", "Admin@2026",
    "Test@1234", "Test@123!", "Welcome1!", "Welcome@1",
    "Qwerty@1", "Qwerty123!", "Summer2024!", "Summer@2024",
    "Winter2024!", "Spring2024!", "Autumn2024!",
    "Hello@123", "Hello1234!", "Secure@123", "Secure1234!",
    "MyP@ssw0rd", "MyPassword1", "MyPass@123",
    "ChangeMe1!", "ChangeMe@1", "Default@1", "Default123!",

    # ── Names + years / numbers ─────────────────────────────────
    "alice123", "alice2024", "bob123", "charlie123",
    "david123", "eve12345", "frank123", "grace123",
    "henry123", "iris1234", "jack1234", "kate1234",
    "liam1234", "mia12345", "noah1234", "olivia12",
    "peter123", "quinn123", "rachel12", "sam12345",
    "tina1234", "umar1234", "vicky123", "will1234",

    # ── SQLiLab demo-context passwords ─────────────────────────
    "sqlilab", "sqlilab1", "SQLiLab1!", "sqlinjection",
    "hackme", "hackme123", "hacked", "hacked123",
    "demo1234", "demo@123", "demo@2024", "demoadmin",
    "student1", "student123", "student@1", "Student@1",
    "learner1", "teacher1", "teacher@1",
    "cybersec1", "security1", "Security@1", "infosec1",
    "pentest1", "pentest@1", "redteam1", "blueteam1",

    # ── Common keyboard walks ───────────────────────────────────
    "qwerty", "qwerty1", "qwerty12", "qwerty123",
    "asdfgh", "asdfgh1", "asdfghjkl", "zxcvbn",
    "qazwsx", "qazwsxedc", "1qaz2wsx", "1q2w3e4r",
    "1q2w3e", "2wsx3edc", "q1w2e3r4",

    # ── Leetspeak variants ──────────────────────────────────────
    "p@ssw0rd", "p4ssword", "pa$$word", "passw0rd",
    "l3tm3in", "h@ck3r", "s3cur3", "4dmin",
    "s3cr3t", "m0nk3y", "sup3rman",

    # ── Vietnamese / regional common passwords ──────────────────
    "123456a", "123456b", "123456c", "123456@a",
    "abc@123", "abc@1234", "abcd1234", "abcde123",
    "mat_khau", "matkhau1", "matkhau123",
    "vietnam1", "viet1234", "hanoi123", "saigon12",
    "hcm12345", "hanoi2024",

    # ── Extra rockyou top entries ───────────────────────────────
    "1234qwer", "qwer1234", "pass1234", "pass@1234",
    "love1234", "baby1234", "cool1234", "cool@123",
    "star1234", "star@123", "moon1234", "fire1234",
    "life1234", "time1234", "game1234", "play1234",
    "king1234", "king@123", "queen123", "prince12",
    "hell0123", "hell@123",

    # ── Typical "complex" passwords from security-awareness demos
    "Tr0ub4dor&3", "correct-horse-battery-staple",
    "MyV0ice$My$Passw0rd",

    # ── Common admin/default credentials ───────────────────────
    "administrator", "administrator1", "Administrator1",
    "Admin@SQLiLab2024!", "Admin@SQLiLab2025!",
    "rootpassword", "rootpass123", "RootPass@1",
    "sysadmin1", "sysadmin@1", "SysAdmin@1",
]
