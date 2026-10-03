"""Every secret in these tests is generated at run time, so this repo holds
no key-shaped strings and keyguard can scan itself in CI."""

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import keyguard


def solana_keypair():
    seed = os.urandom(32)
    return seed + keyguard.ed25519_public(seed)


def hex_key():
    return os.urandom(32).hex()


def mnemonic(count=12):
    entropy = os.urandom(count * 4 // 3)
    check_bits = count // 3
    bits = (int.from_bytes(entropy, "big") << check_bits) | (
        hashlib.sha256(entropy).digest()[0] >> (8 - check_bits)
    )
    return [keyguard.BIP39_WORDS[(bits >> (11 * i)) & 2047] for i in reversed(range(count))]


def kinds(text):
    return [kind for _, kind, _, _ in keyguard.scan_text(text)]


class Ed25519Test(unittest.TestCase):
    def test_rfc8032_vector(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")  # keyguard:allow
        public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        self.assertEqual(keyguard.ed25519_public(seed).hex(), public)

    def test_matches_reference_implementation(self):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            self.skipTest("cryptography is not installed")
        for _ in range(20):
            seed = os.urandom(32)
            expected = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            self.assertEqual(keyguard.ed25519_public(seed), expected)

    def test_base58_round_trip(self):
        for raw in (os.urandom(64), b"\0\0" + os.urandom(30), b"\0"):
            self.assertEqual(keyguard.b58decode(keyguard.b58encode(raw)), raw)


class SolanaTest(unittest.TestCase):
    def test_keypair_json_on_one_line(self):
        raw = solana_keypair()
        hits = keyguard.scan_text(json.dumps(list(raw)))
        self.assertEqual([hit[1] for hit in hits], ["Solana keypair"])
        self.assertIn(keyguard.b58encode(raw[32:]), hits[0][2])

    def test_keypair_json_pretty_printed(self):
        text = "{\n" + json.dumps(list(solana_keypair()), indent=2) + "\n}"
        hits = keyguard.scan_text(text)
        self.assertEqual([(hit[0], hit[1]) for hit in hits], [(2, "Solana keypair")])

    def test_base58_and_hex_forms(self):
        raw = solana_keypair()
        self.assertEqual(kinds(f'KEY = "{keyguard.b58encode(raw)}"'), ["Solana private key"])
        self.assertEqual(kinds(f"value: {raw.hex()}"), ["Solana private key"])

    def test_other_64_byte_values_are_not_keypairs(self):
        signature = os.urandom(64)
        self.assertEqual(kinds(json.dumps(list(signature))), [])
        self.assertEqual(kinds(f"sig {keyguard.b58encode(signature)}"), [])
        self.assertEqual(kinds(f"blob = {signature.hex()}"), [])


class EvmTest(unittest.TestCase):
    def test_named_keys_are_found(self):
        key = hex_key()
        for line in (
            f"PRIVATE_KEY={key}",
            f'const signer = new Wallet("0x{key}")',
            f'accounts: ["0x{key}"]',
            f"forge script --private-key 0x{key}",
            f'const DEPLOYER =\n  "0x{key}";',
            f"pk = '{key.upper()}'",
        ):
            with self.subTest(line=line):
                self.assertEqual(kinds(line), ["EVM private key"])

    def test_hashes_and_public_values_are_left_alone(self):
        value = hex_key()
        for line in (
            f"txHash: 0x{value}",
            f'"blockHash": "0x{value}"',
            f"tx = 0x{value}",
            f"publicKey = '{value}'",
            f"keyHash = 0x{value}",
            f"merkle root 0x{value}",
            f"0x{value}",
            f"private_code = 0x{value}{value}",
        ):
            with self.subTest(line=line):
                self.assertEqual(kinds(line), [])

    def test_false_positives_seen_in_real_repos(self):
        value = hex_key()
        for text in (
            # checksum files, where the "name" comes after the value
            f"{value}  pk.bin\n{value}  secret.ct\n{value}  seed.ct",
            # Solidity visibility keywords and storage slots
            f"bytes32 private constant INITIALIZABLE_STORAGE = 0x{value};",
            f"uint256 private constant HALF_N = 0x{value};",
            f"bytes32 private constant REENTRANCY_GUARD_STORAGE =\n    0x{value};",
            f"function test_WithDefaultDeployer() external pure {{\n    bytes32 salt = 0x{value};",
            # a cache keyed by digests, after prose that mentions keys
            f'{{"{value}": "store the wallet key safely"}}, "{value}": "x"}}',
        ):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])

    def test_public_test_keys_and_placeholders_are_left_alone(self):
        anvil = "ac0974bec39a17e36ba4a6b4d238ff94" + "4bacb478cbed5efcae784d7bf4f2ff80"
        self.assertEqual(kinds(f"PRIVATE_KEY=0x{anvil}"), [])
        self.assertEqual(kinds("PRIVATE_KEY=0x" + "0" * 63 + "1"), [])
        self.assertEqual(kinds("PRIVATE_KEY=0x" + "ab" * 32), [])


class MnemonicTest(unittest.TestCase):
    def test_valid_phrases_are_found(self):
        for count in (12, 15, 18, 21, 24):
            with self.subTest(count=count):
                words = mnemonic(count)
                hits = keyguard.scan_text(f'MNEMONIC="{" ".join(words)}"')
                self.assertEqual([hit[1] for hit in hits], ["seed phrase"])
                self.assertIn(f"{count} words", hits[0][2])

    def test_phrase_inside_a_sentence(self):
        text = "please use " + " ".join(mnemonic()) + " for the wallet"
        self.assertEqual(kinds(text), ["seed phrase"])

    def test_bad_checksum_is_not_a_phrase(self):
        words = mnemonic()
        words[-1] = keyguard.BIP39_WORDS[keyguard.WORD_INDEX[words[-1]] ^ 1]
        self.assertEqual(kinds(" ".join(words)), [])

    def test_wordlists_prose_and_test_phrases_are_left_alone(self):
        self.assertEqual(kinds(" ".join(keyguard.BIP39_WORDS)), [])
        self.assertEqual(kinds("test " * 11 + "junk"), [])
        prose = "the quick brown fox jumps over the lazy dog and then runs away into the forest again"
        self.assertEqual(kinds(prose), [])


class TokenTest(unittest.TestCase):
    def test_tokens_are_found(self):
        body = keyguard.b58encode(os.urandom(60))
        cases = {
            "Telegram bot token": f"TOKEN=7123456789:{body[:35]}",
            "Discord bot token": f"token = 'M{body[:25]}.{body[30:36]}.{body[40:70]}'",
            "GitHub token": "ghp_" + body[:36],
            "PEM private key": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "RPC API key": f"https://eth-mainnet.g.alchemy.com/v2/{body[:32]}",
        }
        for kind, text in cases.items():
            with self.subTest(kind=kind):
                self.assertEqual(kinds(text), [kind])
        infura = f"https://mainnet.infura.io/v3/{os.urandom(16).hex()}"
        self.assertEqual(kinds(infura), ["RPC API key"])

    def test_placeholders_are_left_alone(self):
        self.assertEqual(kinds("https://mainnet.infura.io/v3/" + "0" * 32), [])
        self.assertEqual(kinds("https://eth-mainnet.g.alchemy.com/v2/your-api-key"), [])
        self.assertEqual(kinds("TOKEN=123456789:" + "x" * 35), [])
        forge_std = "https://sepolia.infura.io/v3/" + "b9794ad1ddf84dfb" + "8c34d6bb5dca2001"
        self.assertEqual(kinds(forge_std), [])


class RulesTest(unittest.TestCase):
    def test_allow_mark_skips_a_line(self):
        key = hex_key()
        self.assertEqual(kinds(f"PRIVATE_KEY={key}  # keyguard:allow"), [])
        self.assertEqual(kinds(f"# keyguard:allow\nPRIVATE_KEY={key}"), ["EVM private key"])

    def test_line_numbers(self):
        text = f"a = 1\n\nPRIVATE_KEY={hex_key()}\nb = 2\nSECRET={hex_key()}\n"
        self.assertEqual([hit[0] for hit in keyguard.scan_text(text)], [3, 5])

    def test_env_file_names(self):
        for name in (".env", "app/.env", ".env.local", ".env.production"):
            self.assertTrue(keyguard.is_env_file(name), name)
        for name in (".env.example", "config/.env.sample", "env.py", ".envrc", "my.env"):
            self.assertFalse(keyguard.is_env_file(name), name)

    def test_ignore_patterns(self):
        patterns = ["fixtures/", "*.snap", "docs/keys.md"]
        for path in ("fixtures/a.json", "test/fixtures/a.json", "ui/app.snap", "docs/keys.md"):
            self.assertTrue(keyguard.is_ignored(path, patterns), path)
        for path in ("src/fixtures.py", "docs/other.md"):
            self.assertFalse(keyguard.is_ignored(path, patterns), path)

    def test_binary_files_are_skipped(self):
        data = b"\0\1\2" + f"PRIVATE_KEY={hex_key()}".encode()
        self.assertEqual(keyguard.scan_blob("a.bin", data, [], in_git=True), [])


class GitTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.repo)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "test")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args, check=True):
        return subprocess.run(["git", *args], capture_output=True, text=True, check=check)

    def run_keyguard(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = keyguard.main(list(argv))
        return code, out.getvalue()

    def test_staged_secret_blocks_and_output_hides_it(self):
        key = hex_key()
        Path("deploy.js").write_text(f"// deploy\nconst PRIVATE_KEY = '0x{key}';\n")
        Path("readme.txt").write_text("hello\n")
        self.git("add", ".")
        code, text = self.run_keyguard()
        self.assertEqual(code, keyguard.EXIT_FOUND)
        self.assertIn("deploy.js:2", text)
        self.assertIn("EVM private key", text)
        self.assertIn("Commit blocked", text)
        self.assertNotIn(key, text)
        self.assertNotIn(key[:8], text)

    def test_only_staged_content_counts(self):
        Path("notes.txt").write_text("nothing here\n")
        self.git("add", ".")
        Path("notes.txt").write_text(f"PRIVATE_KEY={hex_key()}\n")
        self.assertEqual(self.run_keyguard(), (keyguard.EXIT_CLEAN, ""))

    def test_env_file_is_blocked_and_can_be_ignored(self):
        Path(".env").write_text("DEBUG=1\n")
        Path(".env.example").write_text("DEBUG=\n")
        self.git("add", ".")
        code, text = self.run_keyguard()
        self.assertEqual(code, keyguard.EXIT_FOUND)
        self.assertIn(".env:1", text)
        self.assertNotIn(".env.example", text)
        Path(".keyguardignore").write_text("# local config\n.env\n")
        self.assertEqual(self.run_keyguard()[0], keyguard.EXIT_CLEAN)

    def test_all_and_paths_modes(self):
        Path("sub").mkdir()
        Path("sub/id.json").write_text(json.dumps(list(solana_keypair())))
        Path("untracked.txt").write_text(f"SECRET={hex_key()}\n")
        self.git("add", "sub")
        self.git("commit", "-q", "-m", "add")
        code, text = self.run_keyguard("--all")
        self.assertEqual(code, keyguard.EXIT_FOUND)
        self.assertIn("sub/id.json:1", text)
        self.assertNotIn("untracked.txt", text)
        os.chdir("sub")
        code, text = self.run_keyguard("../untracked.txt", ".")
        self.assertEqual(code, keyguard.EXIT_FOUND)
        self.assertIn("untracked.txt:1", text)
        self.assertIn("sub/id.json:1", text)

    def test_env_file_rule_in_paths_mode_needs_git_to_know_the_file(self):
        Path(".env").write_text("DEBUG=1\n")
        self.assertEqual(self.run_keyguard(".env")[0], keyguard.EXIT_CLEAN)
        self.git("add", ".env")
        self.assertEqual(self.run_keyguard(".env")[0], keyguard.EXIT_FOUND)

    def test_history_finds_a_removed_secret_once(self):
        key = hex_key()
        Path("config.py").write_text(f"PRIVATE_KEY = '{key}'\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "oops")
        first = self.git("rev-parse", "--short", "HEAD").stdout.strip()
        Path("config.py").write_text(f"PRIVATE_KEY = '{key}'\nDEBUG = True\n")
        self.git("commit", "-q", "-am", "more")
        Path("config.py").write_text("DEBUG = True\n")
        self.git("commit", "-q", "-am", "remove key")
        self.assertEqual(self.run_keyguard("--all")[0], keyguard.EXIT_CLEAN)
        code, text = self.run_keyguard("--history")
        self.assertEqual(code, keyguard.EXIT_FOUND)
        self.assertIn("1 possible secret(s)", text)
        self.assertIn(f"first committed in {first}", text)

    def test_installed_hook_blocks_a_real_commit(self):
        code, text = self.run_keyguard("--install")
        self.assertEqual(code, keyguard.EXIT_CLEAN)
        Path("ok.txt").write_text("fine\n")
        self.git("add", ".")
        self.assertEqual(self.git("commit", "-m", "clean", check=False).returncode, 0)
        Path("bot.py").write_text(f'MNEMONIC = "{" ".join(mnemonic())}"\n')
        self.git("add", ".")
        blocked = self.git("commit", "-m", "leak", check=False)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("seed phrase", blocked.stdout + blocked.stderr)
        self.assertEqual(self.git("commit", "--no-verify", "-m", "leak", check=False).returncode, 0)

    def test_install_keeps_an_existing_hook(self):
        hook = Path(".git/hooks/pre-commit")
        hook.parent.mkdir(exist_ok=True)
        hook.write_text("#!/bin/sh\nexit 0\n")
        self.assertEqual(self.run_keyguard("--install")[0], keyguard.EXIT_ERROR)
        self.assertEqual(hook.read_text(), "#!/bin/sh\nexit 0\n")
        self.assertEqual(self.run_keyguard("--install", "--force")[0], keyguard.EXIT_CLEAN)

    def test_outside_a_repo(self):
        with tempfile.TemporaryDirectory() as plain:
            os.chdir(plain)
            self.assertEqual(self.run_keyguard()[0], keyguard.EXIT_ERROR)
            Path("a.txt").write_text(f"SECRET={hex_key()}\n")
            self.assertEqual(self.run_keyguard("a.txt")[0], keyguard.EXIT_FOUND)
            self.assertEqual(self.run_keyguard("missing.txt")[0], keyguard.EXIT_ERROR)
            os.chdir(self.repo)


if __name__ == "__main__":
    unittest.main()
