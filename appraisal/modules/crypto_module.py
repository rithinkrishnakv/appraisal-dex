"""
SKILL: Cipher Sight [UNIQUE]
Cryptographic weakness detection engine.
Finds ECB mode, static IVs, weak key derivation, hardcoded secrets,
and broken random number generation.
"""

import re
from typing import List, Dict, Set, Tuple
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank

# Known weak / insecure algorithm strings
WEAK_ALGORITHMS = {
    "DES":      "DES (56-bit) — broken, key space exhausted by brute force in hours",
    "DESede":   "Triple-DES — deprecated, vulnerable to Sweet32 birthday attack",
    "RC2":      "RC2 — deprecated, multiple known weaknesses",
    "RC4":      "RC4 — cryptographically broken, prohibited in TLS 1.3",
    "Blowfish": "Blowfish with ECB mode — short block size (64-bit), birthday attacks",
    "MD5":      "MD5 — collision attacks demonstrated, not safe for integrity/authentication",
    "SHA-1":    "SHA-1 — collision attacks demonstrated (SHAttered), deprecated by NIST",
    "SHA1":     "SHA-1 — collision attacks demonstrated, deprecated",
}

ECB_PATTERNS = [
    r'AES/ECB',
    r'DES/ECB',
    r'"ECB"',
    r"Cipher\.getInstance\(['\"]AES['\"]",   # AES with no mode = ECB by default
    r"Cipher\.getInstance\(['\"]DES['\"]",
]

HARDCODED_KEY_PATTERNS = [
    (r'SecretKeySpec\s*\(\s*"([^"]{8,})"\.getBytes', "Hardcoded string key"),
    (r'IvParameterSpec\s*\(\s*new\s+byte\[\]\s*\{', "Hardcoded IV bytes"),
    (r'IvParameterSpec\s*\(\s*"([^"]+)"\.getBytes', "Hardcoded string IV"),
    (r'PBEKeySpec\s*\([^,]+,\s*"([^"]+)"\.getBytes', "Hardcoded PBE salt"),
    (r'new\s+SecretKeySpec\s*\(\s*Base64\.decode\s*\(\s*"([^"]+)"', "Base64-encoded hardcoded key"),
]

WEAK_RANDOM_PATTERNS = [
    r'new\s+Random\s*\(',
    r'Math\.random\s*\(',
    r'new\s+java\.util\.Random\s*\(',
]


class CryptoModule(BaseModule):
    SKILL_NAME  = "Cipher Sight"
    SKILL_TYPE  = SkillType.UNIQUE
    DESCRIPTION = "Cryptographic weakness fingerprinting: ECB, IV reuse, weak KDF, hardcoded keys"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        self._check_string_pool_secrets(ctx)
        self._check_algorithm_usage(ctx)
        self._check_ecb_mode(ctx)
        self._check_weak_random(ctx)
        self._check_hardcoded_keys_in_strings(ctx)
        self._check_kdf_weakness(ctx)
        return self._findings

    # ── Secret hunting in the DEX string pool ─────────────────────────────────

    def _check_string_pool_secrets(self, ctx: AnalysisContext):
        """
        Scan the DEX string pool for secrets: API keys, tokens, private keys,
        AWS credentials, hardcoded passwords, etc.
        """
        SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
            # (regex, label, description, tag)
            (r'AKIA[0-9A-Z]{16}',
             "AWS Access Key ID",
             "Hardcoded AWS Access Key ID found in DEX string pool",
             "aws"),
            (r'(?i)(aws_secret|aws_key|secretaccesskey)["\s:=]+([A-Za-z0-9/+=]{40})',
             "AWS Secret Access Key",
             "Hardcoded AWS Secret Key found",
             "aws"),
            (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
             "Private Key Material",
             "PEM-encoded private key found in binary",
             "private-key"),
            (r'-----BEGIN CERTIFICATE-----',
             "Embedded Certificate",
             "X.509 certificate embedded in binary",
             "certificate"),
            (r'(?i)(api[_-]?key|apikey)["\s:=]+([A-Za-z0-9_\-]{20,})',
             "Generic API Key",
             "Potential hardcoded API key found",
             "api-key"),
            (r'(?i)(password|passwd|pwd)["\s:=]+([^\s"\']{8,})',
             "Hardcoded Password",
             "Potential hardcoded password found in string pool",
             "password"),
            (r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
             "Hardcoded JWT Token",
             "JWT token found hardcoded in binary",
             "jwt"),
            (r'(?i)(firebase|fcm)[^\s"\']{0,20}(key|secret|token)["\s:=]+([A-Za-z0-9_\-:]{20,})',
             "Firebase Key",
             "Firebase API key or FCM server key hardcoded",
             "firebase"),
            (r'AIza[0-9A-Za-z\-_]{35}',
             "Google API Key",
             "Google API key found in binary",
             "google-api"),
            (r'(?i)(secret[_-]?key|signing[_-]?key|encryption[_-]?key)["\s:=]+([A-Za-z0-9+/=_\-]{16,})',
             "Cryptographic Key Material",
             "Potential hardcoded cryptographic key found",
             "crypto-key"),
            (r'(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}',
             "Hardcoded Basic Auth Header",
             "Base64-encoded Basic Auth credential found",
             "basic-auth"),
            (r'(?i)(stripe|sk_live|pk_live)[_-]?[A-Za-z0-9]{24,}',
             "Stripe API Key",
             "Stripe live API key found in binary",
             "stripe"),
            (r'(?i)(slack|xox[bpaso]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24})',
             "Slack Token",
             "Slack API token found hardcoded",
             "slack"),
            (r'(?i)(github|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36})',
             "GitHub Token",
             "GitHub personal access token found",
             "github"),
        ]

        string_pool = "\n".join(ctx.strings_pool)
        seen_ids: Set[str] = set()

        for pattern, label, description, tag in SECRET_PATTERNS:
            matches = re.findall(pattern, string_pool)
            if not matches:
                continue

            # Flatten tuple matches
            flat_matches = []
            for m in matches:
                if isinstance(m, tuple):
                    flat_matches.append(" ".join(str(x) for x in m if x))
                else:
                    flat_matches.append(str(m))

            finding_id = f"CRYPTO-SECRET-{tag.upper()}"
            if finding_id in seen_ids:
                continue
            seen_ids.add(finding_id)

            # Redact partially for the report (don't expose full secrets in reports)
            redacted = [self._redact(m) for m in flat_matches[:5]]

            self._add(Finding(
                id=finding_id,
                title=f"Hardcoded Secret in DEX String Pool: {label}",
                category="Hardcoded Credentials",
                description=(
                    f"{description}. "
                    "Secrets embedded in compiled bytecode can be extracted by any user "
                    "who downloads the APK. No reverse engineering skills required — "
                    "the strings are readable directly from the DEX string pool."
                ),
                technical_detail=(
                    f"Pattern matched: {label}\n"
                    f"Matches found: {len(flat_matches)}\n"
                    f"Samples (redacted): {redacted}"
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=[f"DEX string pool match: {r}" for r in redacted],
                affected_components=[ctx.package_name],
                remediation=(
                    "Never hardcode secrets in source code or resources. "
                    "Use Android Keystore for key material. "
                    "Load secrets from a secure server at runtime or use environment variables "
                    "managed by your CI/CD pipeline. "
                    "Rotate all exposed secrets immediately."
                ),
                references=[
                    "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
                    "https://cwe.mitre.org/data/definitions/798.html",
                ],
                tags=["hardcoded-secret", "credentials", tag],
            ))

    # ── Algorithm usage via string pool ──────────────────────────────────────

    def _check_algorithm_usage(self, ctx: AnalysisContext):
        string_pool = " ".join(ctx.strings_pool)
        for algo, description in WEAK_ALGORITHMS.items():
            if algo in string_pool:
                self._add(Finding(
                    id=f"CRYPTO-ALGO-{algo.upper().replace('-','_')}",
                    title=f"Weak/Broken Cryptographic Algorithm Detected: {algo}",
                    category="Weak Cryptography",
                    description=(
                        f"The algorithm string \"{algo}\" was found in the DEX string pool, "
                        f"indicating its use in the application. {description}."
                    ),
                    technical_detail=f"String \"{algo}\" found in DEX constants pool.",
                    cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                    evidence=[f'Algorithm string "{algo}" in DEX pool'],
                    affected_components=[ctx.package_name],
                    remediation=(
                        f"Replace {algo} with AES-256-GCM for symmetric encryption, "
                        "SHA-256 or SHA-3 for hashing, and RSA-OAEP or ECDH for asymmetric operations."
                    ),
                    tags=["weak-crypto", "algorithm", algo.lower()],
                ))

    # ── ECB mode detection ────────────────────────────────────────────────────

    def _check_ecb_mode(self, ctx: AnalysisContext):
        string_pool = " ".join(ctx.strings_pool)
        ecb_found = False
        for pattern in ECB_PATTERNS:
            if re.search(pattern, string_pool):
                ecb_found = True
                break

        # Also check for bare "AES" with no mode specifier
        bare_aes = re.search(r'Cipher\.getInstance\s*\(\s*["\']AES["\']', string_pool)

        if ecb_found or bare_aes:
            self._add(Finding(
                id="CRYPTO-ECB",
                title="AES in ECB Mode (or Bare AES Default) — Deterministic Encryption",
                category="Weak Cryptography",
                description=(
                    "ECB (Electronic Codebook) mode encrypts each 16-byte block independently. "
                    "Identical plaintext blocks produce identical ciphertext blocks. "
                    "This means data patterns are preserved in the ciphertext — "
                    "the classic example is the 'ECB penguin' where an encrypted image "
                    "retains its shape. For application data, this leaks structure "
                    "and enables chosen-plaintext attacks. "
                    "Using Cipher.getInstance(\"AES\") defaults to AES/ECB/PKCS5Padding on Android."
                ),
                technical_detail=(
                    "ECB mode or bare AES instantiation detected in string pool. "
                    "Bare 'AES' in Cipher.getInstance() defaults to AES/ECB/PKCS5Padding "
                    "on the Android platform."
                ),
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=["ECB mode string or bare AES cipher in DEX string pool"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Replace with AES/GCM/NoPadding (authenticated encryption). "
                    "Always specify mode and padding: Cipher.getInstance(\"AES/GCM/NoPadding\"). "
                    "Generate a random 12-byte IV per encryption operation with SecureRandom."
                ),
                pocs=[PoC(
                    type="python_script",
                    title="ECB Determinism Demo (Python)",
                    description="Shows why ECB leaks data patterns",
                    code=(
                        "from Crypto.Cipher import AES\n"
                        "import os\n\n"
                        "key = os.urandom(16)\n"
                        "# ECB: same plaintext = same ciphertext\n"
                        "cipher = AES.new(key, AES.MODE_ECB)\n"
                        "p1 = b'ATTACK_AT_DAWN!!' * 2  # repeating block\n"
                        "ct = cipher.encrypt(p1)\n"
                        "print('Block 1:', ct[:16].hex())\n"
                        "print('Block 2:', ct[16:].hex())\n"
                        "print('Equal?  ', ct[:16] == ct[16:])  # True — ECB is deterministic\n"
                    ),
                )],
                tags=["ecb", "weak-crypto", "aes", "deterministic"],
            ))

    # ── Weak random number generation ─────────────────────────────────────────

    def _check_weak_random(self, ctx: AnalysisContext):
        string_pool = " ".join(ctx.strings_pool)
        # Check string pool for class references
        for pattern in WEAK_RANDOM_PATTERNS:
            if re.search(pattern, string_pool):
                self._add(Finding(
                    id="CRYPTO-WEAKRNG",
                    title="Non-Cryptographic Random (java.util.Random / Math.random) Detected",
                    category="Weak Cryptography",
                    description=(
                        "java.util.Random or Math.random() is not cryptographically secure. "
                        "The output is predictable given the seed, which defaults to "
                        "System.currentTimeMillis(). "
                        "If used for security-sensitive operations (session tokens, CSRF tokens, "
                        "IV generation, key generation, OTP codes), the values can be predicted "
                        "by an attacker who knows the approximate time of generation."
                    ),
                    technical_detail="java.util.Random or Math.random reference in DEX string pool.",
                    cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                    evidence=["java.util.Random or Math.random in bytecode"],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Replace all security-sensitive randomness with java.security.SecureRandom. "
                        "Example: SecureRandom sr = new SecureRandom(); byte[] iv = new byte[12]; sr.nextBytes(iv);"
                    ),
                    tags=["weak-random", "rng", "predictable"],
                ))
                break

    # ── Hardcoded key patterns in string pool ──────────────────────────────────

    def _check_hardcoded_keys_in_strings(self, ctx: AnalysisContext):
        source = " ".join(ctx.strings_pool)
        for pattern, label in HARDCODED_KEY_PATTERNS:
            matches = re.findall(pattern, source)
            if matches:
                redacted = [self._redact(str(m)) for m in matches[:3]]
                self._add(Finding(
                    id=f"CRYPTO-HARDKEY-{label[:20].upper().replace(' ', '_')}",
                    title=f"Hardcoded Cryptographic Material: {label}",
                    category="Hardcoded Credentials",
                    description=(
                        f"{label} detected hardcoded in the application. "
                        "Hardcoded cryptographic keys or IVs can be extracted by anyone "
                        "who decompiles the APK. An attacker who recovers the key can "
                        "decrypt all data protected by it — past, present, and future."
                    ),
                    technical_detail=f"Pattern: {label}. Samples (redacted): {redacted}",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                    evidence=[f"Hardcoded {label} in DEX string pool: {r}" for r in redacted],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Generate keys using Android Keystore System — keys never leave secure hardware. "
                        "For symmetric keys: KeyGenerator with KeyGenParameterSpec. "
                        "Never derive keys from hardcoded strings."
                    ),
                    tags=["hardcoded-key", "crypto", "keystore"],
                ))

    # ── Key Derivation Function weakness ─────────────────────────────────────

    def _check_kdf_weakness(self, ctx: AnalysisContext):
        string_pool = " ".join(ctx.strings_pool)

        # Check for PBEKeySpec with low iterations
        if "PBEKeySpec" in string_pool or "PBKDF2" in string_pool:
            # Look for iteration count patterns
            low_iter = re.search(r'PBEKeySpec\s*\([^,]+,[^,]+,\s*(\d+)', string_pool)
            if low_iter:
                iters = int(low_iter.group(1))
                if iters < 10000:
                    self._add(Finding(
                        id="CRYPTO-KDF-ITER",
                        title=f"Weak PBKDF2 Iteration Count: {iters} (Minimum: 10,000)",
                        category="Weak Cryptography",
                        description=(
                            f"PBKDF2 is used with only {iters} iterations. "
                            "Low iteration counts allow offline brute-force attacks to run "
                            "millions of times faster. NIST SP 800-132 recommends a minimum "
                            "of 10,000 iterations; OWASP recommends 600,000 for PBKDF2-SHA256."
                        ),
                        technical_detail=f"PBEKeySpec with iteration count: {iters}",
                        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                        evidence=[f"PBEKeySpec iteration count: {iters}"],
                        affected_components=[ctx.package_name],
                        remediation=(
                            "Increase iteration count to at least 100,000 for PBKDF2-SHA256. "
                            "Consider using bcrypt or Argon2 instead, which are designed "
                            "to resist GPU-based attacks."
                        ),
                        tags=["kdf", "pbkdf2", "weak-crypto", "brute-force"],
                    ))
            elif "PBEKeySpec" in string_pool:
                # PBEKeySpec present but can't determine count — flag as review needed
                self._add(Finding(
                    id="CRYPTO-KDF-REVIEW",
                    title="PBKDF2/PBEKeySpec Usage — Iteration Count Requires Manual Review",
                    category="Weak Cryptography",
                    description=(
                        "PBKDF2 key derivation is used. "
                        "The iteration count could not be automatically determined. "
                        "Manual review is required to confirm it meets minimum standards "
                        "(OWASP: 600,000 for PBKDF2-SHA256; NIST: 10,000 minimum)."
                    ),
                    technical_detail="PBEKeySpec detected, iteration count requires manual inspection.",
                    cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                    evidence=["PBEKeySpec usage in DEX string pool"],
                    affected_components=[ctx.package_name],
                    remediation="Review and increase PBKDF2 iteration count to meet OWASP recommendations.",
                    tags=["kdf", "pbkdf2", "review-needed"],
                    _rank=Rank.D,
                ))

    # ── Redaction helper ──────────────────────────────────────────────────────

    @staticmethod
    def _redact(value: str, keep: int = 6) -> str:
        """Partially redact a secret for safe inclusion in reports."""
        v = value.strip()
        if len(v) <= keep * 2:
            return "*" * len(v)
        return v[:keep] + "..." + v[-3:] + f" [{len(v)} chars]"
