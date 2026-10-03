#!/usr/bin/env python3
"""keyguard: stop wallet keys and bot tokens before they reach a commit.

Run with no arguments (or as a git pre-commit hook) to scan staged files.

Exit codes: 0 clean, 1 secrets found, 2 the scan could not run.
"""

from __future__ import annotations

import argparse
import bisect
import fnmatch
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

__version__ = "1.0.0"

EXIT_CLEAN, EXIT_FOUND, EXIT_ERROR = 0, 1, 2

ALLOW_MARK = "keyguard:allow"
IGNORE_FILE = ".keyguardignore"
MAX_BYTES = 5 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
SAFE_ENV_SUFFIXES = {"example", "sample", "template", "dist", "defaults"}


class ScanError(Exception):
    """The scan could not run: not a git repo, git failed, bad path."""


class Finding(NamedTuple):
    path: str
    line: int
    kind: str
    detail: str
    secret: str  # never printed, only used to tell findings apart


# --- ed25519, just enough to derive a public key ---------------------------
# A Solana keypair is 64 bytes: a 32-byte seed followed by its public key.
# Deriving the public key from the seed and comparing tells a real keypair
# apart from any other 64 bytes, such as a transaction signature.

_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_GX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_GY = 4 * pow(5, _P - 2, _P) % _P
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _point_add(a: tuple, b: tuple) -> tuple:
    t1 = (a[1] - a[0]) * (b[1] - b[0]) % _P
    t2 = (a[1] + a[0]) * (b[1] + b[0]) % _P
    t3 = 2 * a[3] * b[3] * _D % _P
    t4 = 2 * a[2] * b[2] % _P
    e, f, g, h = t2 - t1, t4 - t3, t4 + t3, t2 + t1
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def ed25519_public(seed: bytes) -> bytes:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar = (scalar & ((1 << 254) - 8)) | (1 << 254)
    point, result = _G, (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    inverse = pow(result[2], _P - 2, _P)
    x, y = result[0] * inverse % _P, result[1] * inverse % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def is_solana_keypair(raw: bytes) -> bool:
    return len(raw) == 64 and ed25519_public(raw[:32]) == raw[32:]


BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(text: str) -> bytes:
    number = 0
    for char in text:
        number = number * 58 + BASE58.index(char)
    zeros = len(text) - len(text.lstrip("1"))
    return b"\0" * zeros + number.to_bytes((number.bit_length() + 7) // 8, "big")


def b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    text = ""
    while number:
        number, digit = divmod(number, 58)
        text = BASE58[digit] + text
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + text


# --- detectors -------------------------------------------------------------

BYTE_ARRAY = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*,?\s*\]")
BASE58_KEY = re.compile(r"(?<![0-9A-Za-z])[1-9A-HJ-NP-Za-km-z]{80,90}(?![0-9A-Za-z])")
HEX_KEYPAIR = re.compile(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{128})(?![0-9a-fA-F])")
HEX_KEY = re.compile(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])")
WORD_RUN = re.compile(r"(?<![A-Za-z])(?:[a-z]{3,8}[ \t]+){11,}[a-z]{3,8}(?![A-Za-z])")

# 32 bytes of hex is a private key, a tx hash, a topic or a digest: nothing in
# the value says which. So a 64-hex string only counts when the code just before
# it names it as a key, and does not name it as something public.
KEY_HINT_STRONG = re.compile(r"priv(?:ate)?[\s_-]?key|secret[\s_-]?key|mnemonic", re.I)
KEY_HINT_WEAK = re.compile(r"key|secret|seed|signer|deployer|accounts|wallet|(?<![a-z])pk(?![a-z])", re.I)
KEY_HINT_PUBLIC = re.compile(
    r"pub|hash|(?<![a-z])tx|digest|topic|root|sha|sum|addr|sig(?!ner)|bytes32|salt|slot"
    r"|(?<![a-z])id(?![a-z])",
    re.I,
)

# The default Anvil and Hardhat accounts. Everyone has these, so they are not secrets.
PUBLIC_TEST_KEYS = {
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
    "4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    "dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
}

# Keys that ship inside public tooling: the Infura key in forge-std's StdChains.sol.
PUBLIC_TOKENS = {"b9794ad1ddf84dfb8c34d6bb5dca2001"}

# (kind, pattern). A group named "s" marks the secret part; otherwise it is the whole match.
TOKEN_PATTERNS = [
    (kind, re.compile(pattern))
    for kind, pattern in [
        ("Telegram bot token", r"(?<![0-9A-Za-z])\d{8,10}:(?P<s>[A-Za-z0-9_-]{34,36})(?![A-Za-z0-9_-])"),
        (
            "Discord bot token",
            r"(?<![A-Za-z0-9_-])[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}"
            r"(?![A-Za-z0-9_-])",
        ),
        ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"),
        ("PEM private key", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
        ("extended private key", r"\bxprv[1-9A-HJ-NP-Za-km-z]{107}\b"),
        ("RPC API key", r"alchemy\.com/v2/(?P<s>[A-Za-z0-9_-]{32})(?![A-Za-z0-9_-])"),
        ("RPC API key", r"infura\.io/v3/(?P<s>[0-9a-f]{32})(?![0-9a-f])"),
        ("RPC API key", r"helius[\w.-]*/?\?api-key=(?P<s>[0-9a-f-]{36})(?![0-9a-f-])"),
        ("RPC API key", r"quiknode\.pro/(?P<s>[0-9a-f]{40})(?![0-9a-f])"),
    ]
]


def looks_real(secret: str) -> bool:
    # Placeholders like 0x000...0 or xxxx...x have almost no variety.
    return len(set(secret.lower())) >= 6


def valid_mnemonic(words: list[str]) -> bool:
    """True when the words are a BIP39 phrase with a correct checksum."""
    if len(set(words)) < 6 or words == sorted(words):
        # Too repetitive to be a real wallet (the public "test test ... junk"
        # phrase lands here), or an alphabetical slice of the wordlist itself.
        return False
    bits = 0
    for word in words:
        bits = (bits << 11) | WORD_INDEX[word]
    check_bits = len(words) // 3
    entropy = (bits >> check_bits).to_bytes(len(words) * 4 // 3, "big")
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - check_bits)
    return bits & ((1 << check_bits) - 1) == expected


def find_mnemonics(run: str):
    """Yield (offset, words) for each seed phrase inside a run of lowercase words."""
    words = [(m.start(), m.group()) for m in re.finditer(r"[a-z]+", run)]
    index = 0
    while index < len(words):
        for size in (24, 21, 18, 15, 12):
            window = [word for _, word in words[index:index + size]]
            if len(window) == size and all(w in WORD_INDEX for w in window) and valid_mnemonic(window):
                yield words[index][0], window
                index += size - 1
                break
        index += 1


def label_before(text: str, starts: list[int], offset: int) -> str:
    """The bit of code just before a value, which is where its name would be."""
    number = bisect.bisect_right(starts, offset)
    line_start = starts[number - 1]
    before = text[max(line_start, offset - 80):offset]
    if number > 1 and not before.strip("\"'`[( \t"):
        # The value opens its line, so the name may be on the line above:
        # "const KEY =" then the value, or "accounts: [" then the value.
        above = text[max(starts[number - 2], line_start - 81):line_start - 1].rstrip()
        if above.endswith(("=", ":", "(", "[")):
            before = above
    return re.split(r"[;,}]", before)[-1]


def scan_text(text: str) -> list[tuple[int, str, str, str]]:
    """Return (line, kind, detail, secret) for every secret found in the text."""
    lines = text.split("\n")
    starts = [0]
    for line in lines[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    found = []

    def add(offset: int, kind: str, detail: str, secret: str) -> None:
        number = bisect.bisect_right(starts, offset)
        if ALLOW_MARK not in lines[number - 1]:
            found.append((number, kind, detail, secret))

    for match in BYTE_ARRAY.finditer(text):
        values = [int(value) for value in re.findall(r"\d+", match.group())]
        if max(values) <= 255 and is_solana_keypair(bytes(values)):
            raw = bytes(values)
            add(match.start(), "Solana keypair", f"address {b58encode(raw[32:])}", raw.hex())

    for match in BASE58_KEY.finditer(text):
        raw = b58decode(match.group())
        if is_solana_keypair(raw):
            add(match.start(), "Solana private key", f"address {b58encode(raw[32:])}", raw.hex())

    for match in HEX_KEYPAIR.finditer(text):
        raw = bytes.fromhex(match.group(1))
        if is_solana_keypair(raw):
            add(match.start(), "Solana private key", f"address {b58encode(raw[32:])}", raw.hex())

    for match in HEX_KEY.finditer(text):
        key = match.group(1).lower()
        if key in PUBLIC_TEST_KEYS or not looks_real(key):
            continue
        label = label_before(text, starts, match.start())
        named_key = KEY_HINT_WEAK.search(label) and not KEY_HINT_PUBLIC.search(label)
        if KEY_HINT_STRONG.search(label) or named_key:
            add(match.start(), "EVM private key", f"{key[:4]}... (64 hex chars)", key)

    for match in WORD_RUN.finditer(text):
        for offset, words in find_mnemonics(match.group()):
            detail = f"{len(words)} words, starts with '{words[0]}'"
            add(match.start() + offset, "seed phrase", detail, " ".join(words))

    for kind, pattern in TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            secret = match.group("s") if "s" in pattern.groupindex else match.group()
            if looks_real(secret) and secret not in PUBLIC_TOKENS:
                add(match.start(), kind, f"{secret[:6]}... ({len(secret)} chars)", secret)

    return sorted(found)


# --- files and git ---------------------------------------------------------


def is_env_file(path: str) -> bool:
    name = os.path.basename(path)
    return name == ".env" or (
        name.startswith(".env.") and name.rsplit(".", 1)[-1] not in SAFE_ENV_SUFFIXES
    )


def load_ignore() -> list[str]:
    try:
        lines = Path(IGNORE_FILE).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def is_ignored(path: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/") and (path.startswith(pattern) or f"/{pattern}" in f"/{path}"):
            return True
        if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern):
            return True
    return False


def scan_blob(path: str, data: bytes, ignore: list[str], in_git: bool) -> list[Finding]:
    if is_ignored(path, ignore):
        return []
    findings = []
    if in_git and is_env_file(path):
        findings.append(Finding(path, 1, "env file", "env files should stay out of git", f"env:{path}"))
    if len(data) <= MAX_BYTES and b"\0" not in data[:8192]:
        text = data.decode("utf-8", "replace")
        findings += [Finding(path, *hit) for hit in scan_text(text)]
    return findings


def git(*args: str, stdin: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(["git", *args], input=stdin, capture_output=True)
    except OSError as error:
        raise ScanError(f"could not run git: {error}") from None
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise ScanError(message or f"git {args[0]} failed")
    return result.stdout


def read_file(path: str) -> bytes | None:
    if os.path.islink(path) or not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as handle:
            return handle.read(MAX_BYTES + 1)
    except OSError:
        return None


def scan_staged(ignore: list[str]) -> tuple[list[Finding], int]:
    names = git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    paths = [name for name in names.decode("utf-8", "surrogateescape").split("\0") if name]
    findings = []
    for path in paths:
        try:
            data = git("cat-file", "blob", f":{path}")
        except ScanError:
            continue  # a submodule entry, not a file
        findings += scan_blob(path, data, ignore, in_git=True)
    return findings, len(paths)


def scan_tracked(ignore: list[str]) -> tuple[list[Finding], int]:
    names = git("ls-files", "-z").decode("utf-8", "surrogateescape").split("\0")
    findings, count = [], 0
    for path in filter(None, names):
        data = read_file(path)
        if data is not None:
            count += 1
            findings += scan_blob(path, data, ignore, in_git=True)
    return findings, count


def scan_paths(targets: list[str], ignore: list[str]) -> tuple[list[Finding], int]:
    files = []
    for target in targets:
        if os.path.isdir(target):
            for folder, subfolders, names in os.walk(target):
                subfolders[:] = [name for name in subfolders if name not in SKIP_DIRS]
                files += [os.path.join(folder, name) for name in names]
        elif os.path.isfile(target):
            files.append(target)
        else:
            raise ScanError(f"no such file or folder: {target}")
    try:
        tracked = set(git("ls-files", "-z").decode("utf-8", "surrogateescape").split("\0"))
    except ScanError:
        tracked = set()  # not in a git repo
    findings, count = [], 0
    for path in files:
        data = read_file(path)
        if data is not None:
            count += 1
            shown = os.path.relpath(path)
            findings += scan_blob(shown, data, ignore, in_git=shown in tracked)
    return findings, count


def scan_history(ignore: list[str]) -> tuple[list[Finding], int]:
    """Scan every version of every file that any branch or tag has ever held."""
    paths = {}
    for line in git("rev-list", "--all", "--objects").decode("utf-8", "replace").splitlines():
        sha, _, path = line.partition(" ")
        if path:
            paths.setdefault(sha, path)
    if not paths:
        return [], 0
    feed = "".join(f"{sha}\n" for sha in paths).encode()
    blobs = []
    for line in git("cat-file", "--batch-check", stdin=feed).decode().splitlines():
        sha, kind, size = line.split()[:3]
        if kind == "blob" and int(size) <= MAX_BYTES:
            blobs.append(sha)

    # rev-list walks newest first, so the last blob seen holding a secret is the oldest.
    oldest = {}
    with tempfile.TemporaryFile() as handle:
        handle.write("".join(f"{sha}\n" for sha in blobs).encode())
        handle.seek(0)
        reader = subprocess.Popen(["git", "cat-file", "--batch"], stdin=handle, stdout=subprocess.PIPE)
        for sha in blobs:
            size = int(reader.stdout.readline().split()[2])
            data = reader.stdout.read(size)
            reader.stdout.read(1)
            for finding in scan_blob(paths[sha], data, ignore, in_git=True):
                oldest[(finding.kind, finding.secret)] = (finding, sha)
        reader.wait()

    findings = []
    for finding, sha in oldest.values():
        log = git("log", "--all", "--format=%h on %ad", "--date=short", f"--find-object={sha}")
        commits = log.decode().splitlines()
        where = f", first committed in {commits[-1]}" if commits else ""
        findings.append(finding._replace(detail=finding.detail + where))
    return sorted(findings), len(blobs)


def install(force: bool) -> int:
    hooks = Path(git("rev-parse", "--git-path", "hooks").decode().strip())
    target = hooks / "pre-commit"
    source = Path(__file__).resolve()
    if target.exists() and not force and target.read_bytes() != source.read_bytes():
        print(f"keyguard: {target} already exists. Run with --install --force to replace it.")
        return EXIT_ERROR
    hooks.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755)
    print(f"keyguard: installed as {target}. Commits in this repo are now checked.")
    return EXIT_CLEAN


def report(findings: list[Finding], scanned: int, scope: str, blocking: bool) -> int:
    if not findings:
        if not blocking:
            print(f"keyguard: no secrets found in {scanned} {scope}")
        return EXIT_CLEAN
    print(f"keyguard: {len(findings)} possible secret(s) in {scope}\n")
    width = max(len(f"{f.path}:{f.line}") for f in findings)
    for f in findings:
        print(f"  {f'{f.path}:{f.line}':<{width}}  {f.kind}: {f.detail}")
        if os.environ.get("GITHUB_ACTIONS") and scope != "file versions in git history":
            print(f"::error file={f.path},line={f.line},title=keyguard::{f.kind}")
    print()
    if blocking:
        print("Commit blocked. Take the secret out of the file and commit again.")
    print(
        f'Not a real secret? Put "{ALLOW_MARK}" in a comment on that line,'
        f" or add the path to {IGNORE_FILE}."
    )
    if blocking:
        print("To skip this check once: git commit --no-verify")
    else:
        print("If a real key was ever pushed, treat it as stolen: move the funds and rotate it.")
    return EXIT_FOUND


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keyguard",
        description="Find wallet keys, seed phrases and bot tokens before they are committed."
        " With no arguments, scans the files staged for the next commit.",
    )
    parser.add_argument("paths", nargs="*", help="files or folders to scan instead of staged files")
    parser.add_argument("--all", action="store_true", help="scan every file tracked by git")
    parser.add_argument("--history", action="store_true", help="scan every past version of every file")
    parser.add_argument("--install", action="store_true", help="install as this repo's pre-commit hook")
    parser.add_argument("--force", action="store_true", help="with --install, replace an existing hook")
    parser.add_argument("--version", action="version", version=f"keyguard {__version__}")
    args = parser.parse_args(argv)

    try:
        if args.install:
            return install(args.force)
        targets = [os.path.abspath(path) for path in args.paths]
        try:
            os.chdir(git("rev-parse", "--show-toplevel").decode().strip())
        except ScanError:
            if not targets:
                raise ScanError("not inside a git repository") from None
        ignore = load_ignore()
        if args.history:
            return report(*scan_history(ignore), scope="file versions in git history", blocking=False)
        if args.all:
            return report(*scan_tracked(ignore), scope="tracked files", blocking=False)
        if targets:
            return report(*scan_paths(targets, ignore), scope="files", blocking=False)
        return report(*scan_staged(ignore), scope="staged files", blocking=True)
    except ScanError as error:
        print(f"keyguard: {error}", file=sys.stderr)
        return EXIT_ERROR


# The BIP39 English wordlist. A seed phrase is 12 to 24 of these words.
BIP39_WORDS = """
abandon ability able about above absent absorb abstract absurd abuse access accident account accuse
achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust
admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport
aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always
amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce
annual another answer antenna antique anxiety any apart apology appear apple approve april arch
arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist
artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract
auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful
awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely
bargain barrel base basic basket battle beach bean beauty because become beef before begin behave
behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind
biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse
blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom
bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk
broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet
bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus
cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital
captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch
category cattle caught cause caution cave ceiling celery cement census century cereal certain chair
chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken
chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city
civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock
clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin
collect color column combine come comfort comic common company concert conduct confirm congress
connect consider control convince cook cool copper copy coral core corn correct cost cotton couch
country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy
cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise
crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion
custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris
decade december decide decline decorate decrease deer defense define defy degree delay deliver
demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design
desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet
differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss
disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate
donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink
drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn
earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder
electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ
empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy
enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode
erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact
example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit
exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade
faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue
fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber
fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit
fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly
foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil
foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic
garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift
giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow
glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape
grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar
gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard
head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire
history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host
hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid
ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate indoor industry infant inflict inform
inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside
inspire install intact interest into invest invite involve iron island isolate issue item ivory
jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle
junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite
kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later
latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal
legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life
lift light like limb limit link lion liquid list little live lizard load loan lobster local lock
logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics
machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual
maple marble march margin marine market marriage mask mass master match material math matrix matter
maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu
mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum
minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment
monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse
move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth
naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve
nest net network neutral never news next nice night noble noise nominee noodle normal north nose
notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure
observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic
omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary
organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner
oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent
park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear
peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase
physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place
planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond
pony pool popular portion position possible post potato pottery poverty powder power practice praise
predict prefer prepare present pretty prevent price pride primary print priority prison private
prize problem process produce profit program project promote proof property prosper protect proud
provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push
put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack
radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor
ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse
region regret regular reject relax release relief rely remain remember remind remove render renew
rent reopen repair repeat replace report require rescue resemble resist resource response result
retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle
right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof
rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle
sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save
say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script
scrub sea search season seat second secret section security seed seek segment select sell seminar
senior sense sentence series service session settle setup seven shadow shaft shallow share shed
shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug
shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing
siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice
slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow
soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort
soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice
spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze
squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo
stick still sting stock stomach stone stool story stove strategy street strike strong struggle
student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit
summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect
sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup
system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten
tenant tennis tent term test text thank that theme then theory there they thing this thought three
thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast
tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top
topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic
tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip
trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn
turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover
under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil
update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant
vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture
venue verb verify version very vessel veteran viable vibrant vicious victory video view village
vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote
voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way
wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel
when where whip whisper wide width wife wild will win window wine wing wink winner winter wire
wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle
wrist write wrong yard year yellow you young youth zebra zero zone zoo
""".split()
WORD_INDEX = {word: index for index, word in enumerate(BIP39_WORDS)}


if __name__ == "__main__":
    sys.exit(main())
