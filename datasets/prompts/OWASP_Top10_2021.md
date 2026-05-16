## OWASP Top 10 2021:
A01:2021: Broken Access Control - Prevents users from acting outside permissions. Failures expose data or actions via bypasses, privilege escalation, or misconfigurations.
A02:2021: Cryptographic Failures - Inadequate protection of sensitive data at rest or transit due to weak encryption, poor key management, or deprecated algorithms.
A03:2021: Injection - Flaws allowing untrusted data to execute commands or queries. Common in SQL, NoSQL, OS, or LDAP when inputs aren’t properly validated or sanitized.
A04:2021: Insecure Design - Weak or missing security controls due to flawed design. Cannot be fixed by secure coding alone; needs proper threat modeling and controls.
A05:2021: Security Misconfiguration - Improper settings, default credentials, or unnecessary features leave systems exposed. Requires consistent hardening and patching.
A06:2021: Vulnerable and Outdated Components - Using unsupported, unpatched libraries or frameworks exposes systems to known exploits. Maintain inventory and updates.
A07:2021: Identification and Authentication Failures - Weak authentication allows account hijacking via brute force, default creds, poor session management, or missing MFA.
A08:2021: Software and Data Integrity Failures - Trusting unverified code, plugins, or updates risks malicious tampering. Secure CI/CD pipelines and integrity checks are key.
A09:2021: Security Logging and Monitoring Failures - Inadequate logging and alerting prevent breach detection and response. Audit critical events and monitor suspicious actions.
A10:2021: Server-Side Request Forgery (SSRF) - Improper URL validation lets attackers force servers to fetch internal or external resources, bypassing network protections.
