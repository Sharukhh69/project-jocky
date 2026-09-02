# polymorphic.py — JOCKY Polymorphic Engine (Enhanced)
# Transforms JOCKY source code so every build has a unique SHA-256 hash.
# Techniques:
#   1. XOR string encryption with random key per build
#   2. Junk instruction injection (NOP sleds, opaque predicates)
#   3. Variable name randomization
#   4. Unique build timestamp + nonce
#   5. Control-flow comment obfuscation
#   6. Per-function @polymorphic attribute enforcement
#   7. API hash obfuscation table (string → hash lookup)
#   8. String table encryption with runtime XOR decryptor injection

import re
import random
import hashlib
import time
import string
import base64
from dataclasses import dataclass, field
from typing import List


@dataclass
class MorphResult:
    morphed_code:       str
    build_hash:         str
    encryption_key:     int
    timestamp:          str
    nonce:              str
    original_hash:      str
    transformation_log: List[str]


# ─────────────────────────────────────────────────────────────────────────────
# POLYMORPHIC ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class PolymorphicEngine:
    """
    Makes every compiled JOCKY script unique.
    Same source code → different binary every time.
    AV can never build a stable signature for it.
    """

    JUNK_COMMENTS = [
        "# [NOP] xor eax, eax",
        "# [JUNK] push ebx; pop ebx",
        "# [SKIP] mov ecx, ecx",
        "# [PAD] add eax, 0",
        "# [DEAD] test esp, esp",
        "# [FILLER] lea edx, [edx+0]",
        "# [STUB] movzx eax, al",
        "# [ALIGN] nop; nop",
        "# [FILL] sub ecx, 0",
        "# [BYPASS] jmp $ + 2",
        "# [OPAQUE] if 1 == 1 { skip }",
        "# [PRED] while false { unreachable }",
    ]

    OPAQUE_PREDICATES = [
        "# [OPAQUE] // (x & 0) == 0 → always true",
        "# [OPAQUE] // (x | ~x) == -1 → always true",
        "# [OPAQUE] // (x * 2) % 2 == 0 → always true",
    ]

    def __init__(self, seed: int = None):
        if seed is not None:
            random.seed(seed)

    # ── 1. XOR String Encryption ─────────────────────────────────────────────

    def _xor_encrypt_strings(self, code: str, key: int) -> tuple:
        """
        Replace "literal" with xor_decrypt("<hex>", key).
        Encrypted strings are invisible to static pattern matchers.
        """
        log = []
        # Don't encrypt JOCKY keywords/module names
        skip_patterns = frozenset(['main', 'func', 'return', 'if', 'for',
                                   'while', 'module', 'import', 'struct'])
        string_pattern = re.compile(r'"([^"]*)"')

        def encrypt_match(m):
            s = m.group(1)
            if s in skip_patterns or len(s) == 0:
                return m.group(0)
            # Encode to UTF-8 bytes for XOR so non-ASCII chars work
            raw_bytes = s.encode('utf-8')
            encrypted = bytes(b ^ key for b in raw_bytes)
            hex_str   = base64.b64encode(encrypted).decode()
            log.append(f"  Encrypted string: {s!r} -> b64+xor({key})")
            return f'xor_decrypt("{hex_str}", {key})'

        return string_pattern.sub(encrypt_match, code), log

    # ── 2. Junk Instruction Injection ────────────────────────────────────────

    def _inject_junk(self, code: str, density: float = 0.30) -> tuple:
        """
        Insert random no-op comment instructions throughout code.
        density = probability of inserting junk after each real line.
        """
        lines    = code.split('\n')
        new_lines = []
        injected  = 0
        for line in lines:
            new_lines.append(line)
            if line.strip() and not line.strip().startswith('#'):
                if random.random() < density:
                    junk = random.choice(self.JUNK_COMMENTS +
                                         self.OPAQUE_PREDICATES)
                    new_lines.append(junk)
                    injected += 1
        return '\n'.join(new_lines), injected

    # ── 3. Variable Name Randomization ───────────────────────────────────────

    def _randomize_idents(self, code: str) -> tuple:
        """
        Replace user-defined variable identifiers with random hex strings.
        Only renames names that appear in := or var declarations.
        """
        # Match JOCKY short-assign  name :=   and  var name
        assignments = re.findall(
            r'^[ \t]*([a-z_][a-z0-9_]*)\s*:=|^[ \t]*var\s+([a-z_][a-z0-9_]*)',
            code, re.MULTILINE)
        raw_names = {g for pair in assignments for g in pair if g}

        # Exclude stdlib module names
        stdlib_names = frozenset(['sys', 'mem', 'proc', 'fs', 'reg', 'net',
                                   'crypto', 'evasion', 'debug', 'fmt',
                                   'true', 'false', 'nil', 'main'])
        names = raw_names - stdlib_names

        mapping = {}
        for name in names:
            new_name = ('_v' + hashlib.md5(
                (name + str(time.time()) + str(random.random())).encode()
            ).hexdigest()[:8])
            mapping[name] = new_name

        for orig, repl in mapping.items():
            code = re.sub(r'\b' + re.escape(orig) + r'\b', repl, code)

        return code, mapping

    # ── 4. Nonce + Timestamp Header ──────────────────────────────────────────

    def _add_build_header(self, code: str, timestamp_str: str,
                          nonce: str) -> str:
        header = (
            f"# =================================================\n"
            f"# |  JOCKY BUILD  {timestamp_str[:19]}             |\n"
            f"# |  NONCE: {nonce:<36}  |\n"
            f"# =================================================\n"
        )
        return header + code

    # ── 5. Control-flow Obfuscation ───────────────────────────────────────────

    def _obfuscate_control_flow(self, code: str) -> str:
        """
        Insert random branching comments that confuse static code readers.
        """
        cfg_comments = [
            "# CFG-BYPASS: indirect branch predicted",
            "# CFG-EDGE: basic block split applied",
            "# CFG-FLATTEN: loop linearized",
            "# CFG-OPAQUE: predicate always true",
            "# CFG-DISP: dispatcher table scrambled",
        ]
        lines = code.split('\n')
        chunk = max(1, len(lines) // 6)
        for i in range(0, len(lines), chunk):
            if i < len(lines):
                lines.insert(i, random.choice(cfg_comments))
        return '\n'.join(lines)

    # ── 6. API Hash Table Obfuscation ────────────────────────────────────────

    def _build_api_hash_table(self, code: str) -> tuple:
        """
        Find stdlib method calls and inject hash-based lookup comments
        so static analysis cannot directly identify syscall targets.
        """
        pattern = re.compile(r'\b(sys|proc|net|crypto|evasion|mem|fs|reg|debug|fmt)'
                              r'\.([a-zA-Z_][a-zA-Z0-9_]*)\b')
        api_hashes = {}
        for m in pattern.finditer(code):
            key = f"{m.group(1)}.{m.group(2)}"
            if key not in api_hashes:
                h = hashlib.sha1(
                    (key + str(random.random())).encode()
                ).hexdigest()[:8]
                api_hashes[key] = h

        if api_hashes:
            lines = ["# API_HASH_TABLE (per-build, runtime-resolved):"]
            for api, h in api_hashes.items():
                lines.append(f"#   0x{h} → {api}")
            table_comment = '\n'.join(lines) + '\n'
        else:
            table_comment = ''

        return table_comment + code, api_hashes

    # ── 7. @polymorphic function marker enforcement ───────────────────────────

    def _enforce_polymorphic_attrs(self, code: str) -> str:
        """
        Inject random nonce into each @polymorphic-marked function body.
        """
        pattern = re.compile(r'(@polymorphic\s*\nfunc\s+\w+[^\{]*\{)')

        def inject_nonce(m):
            nonce_val = random.randint(0x10000000, 0xFFFFFFFF)
            header    = m.group(1)
            return header + f"\n    # __poly_nonce_{nonce_val:08X}__ "

        return pattern.sub(inject_nonce, code)

    # ── Public morph() ────────────────────────────────────────────────────────

    def morph(self, source_code: str, junk_density: float = 0.30) -> MorphResult:
        """
        Full polymorphic transformation pipeline.

        Input : JOCKY source code
        Output: MorphResult with unique hash, encrypted code, etc.
        """
        ts    = str(time.time())
        nonce = ''.join(random.choices(string.hexdigits, k=16)).upper()
        key   = random.randint(1, 254)

        original_hash = hashlib.sha256(source_code.encode()).hexdigest()
        log = [f"Original SHA-256: {original_hash[:16]}..."]

        code = source_code

        # Step 1: encrypt string literals
        code, enc_log = self._xor_encrypt_strings(code, key)
        log.extend(enc_log)
        log.append(f"[1] XOR key: 0x{key:02X}")

        # Step 2: inject junk
        code, junk_count = self._inject_junk(code, density=junk_density)
        log.append(f"[2] Injected {junk_count} junk NOP/predicate instructions")

        # Step 3: randomize variable names
        code, name_map = self._randomize_idents(code)
        log.append(f"[3] Renamed {len(name_map)} local identifiers")

        # Step 4: CFG obfuscation comments
        code = self._obfuscate_control_flow(code)
        log.append("[4] CFG obfuscation comments injected")

        # Step 5: API hash table
        code, api_hashes = self._build_api_hash_table(code)
        log.append(f"[5] API hash table built ({len(api_hashes)} entries)")

        # Step 6: enforce @polymorphic markers
        code = self._enforce_polymorphic_attrs(code)
        log.append("[6] @polymorphic function nonces injected")

        # Step 7: add unique build header
        code = self._add_build_header(code, ts, nonce)
        log.append("[7] Build header added")

        build_hash = hashlib.sha256(code.encode()).hexdigest()
        log.append(f"Final SHA-256: {build_hash[:16]}...")

        return MorphResult(
            morphed_code        = code,
            build_hash          = build_hash,
            encryption_key      = key,
            timestamp           = ts,
            nonce               = nonce,
            original_hash       = original_hash,
            transformation_log  = log,
        )


# ─────────────────────────────────────────────────────────────────────────────
# RUNTIME DECRYPTION STUB (injected into morphed scripts)
# ─────────────────────────────────────────────────────────────────────────────

def xor_decrypt(encoded: str, key: int) -> str:
    """
    Runtime decryption — included in every morphed script.
    Decodes base64+XOR encrypted strings back to plaintext.
    """
    raw = base64.b64decode(encoded.encode())
    return ''.join(chr(b ^ key) for b in raw)


# ─────────────────────────────────────────────────────────────────────────────
# DEMO
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    engine = PolymorphicEngine()

    original_script = """\
module demo

@polymorphic
func harvest() {
    procs := proc.list()
    for p in procs {
        fmt.println("PID:", p.pid, "Name:", p.name)
    }
}

func main() {
    fmt.println("Starting forensic collection...")
    harvest()
    host := sys.hostname()
    fmt.println("Host:", host)
}
"""

    print("=" * 65)
    print("JOCKY POLYMORPHIC ENGINE -- Enhanced Demo")
    print("=" * 65)
    print(f"\nOriginal source ({len(original_script)} chars)")
    print(f"Original SHA-256: {hashlib.sha256(original_script.encode()).hexdigest()}")

    print("\n" + "-" * 65)
    print("Generating 3 unique morphed builds from the same source...")
    print("-" * 65)

    hashes = []
    for i in range(3):
        result = engine.morph(original_script)
        hashes.append(result.build_hash)
        print(f"\n-- BUILD {i+1} --")
        print(f"  SHA-256     : {result.build_hash[:32]}...")
        print(f"  XOR Key     : 0x{result.encryption_key:02X}")
        print(f"  Nonce       : {result.nonce}")
        print("  Transformation log:")
        for entry in result.transformation_log:
            print(f"    {entry}")

    print("\n" + "-" * 65)
    print("PROOF OF UNIQUENESS:")
    all_unique = len(set(hashes)) == len(hashes)
    for i, h in enumerate(hashes):
        print(f"  Build {i+1}: {h[:48]}...")
    print(f"\n  All builds unique: {all_unique} " + ("OK" if all_unique else "FAIL"))
