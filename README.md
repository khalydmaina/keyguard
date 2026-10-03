# keyguard

Stop wallet keys before they reach a commit.

A pushed private key is gone. Bots watch public repos for them, and deleting
the commit afterwards does not help. `keyguard` is a git pre-commit hook that
checks what you are about to commit and blocks it when it finds a wallet key,
a seed phrase or a bot token.

It is built for crypto work: it knows what Solana keypairs, EVM keys and seed
phrases look like, and it checks them properly instead of guessing. It is one
Python file with no dependencies.

```
$ git commit -m "deploy script"
keyguard: 5 possible secret(s) in staged files

  .env:1               env file: env files should stay out of git
  bot/config.py:2      seed phrase: 12 words, starts with 'legal'
  bot/config.py:3      Telegram bot token: 8mVkbY... (35 chars)
  hardhat.config.js:5  EVM private key: 1c72... (64 hex chars)
  scripts/id.json:1    Solana keypair: address 5uKUjF5zZZQkL3tveA9YjcWbGWyrExERXcDAkTcyqc4A

Commit blocked. Take the secret out of the file and commit again.
```

The output never prints the secret itself, so it is safe in CI logs.

## Install

Download `keyguard.py`, then from inside the repo you want to protect:

```bash
python3 keyguard.py --install
```

That copies it to `.git/hooks/pre-commit`. Every commit in that repo is now
checked. To update, download the new file and run
`python3 keyguard.py --install --force`.

If you use the [pre-commit](https://pre-commit.com) framework instead:

```yaml
repos:
  - repo: https://github.com/khalydmaina/keyguard
    rev: v1
    hooks:
      - id: keyguard
```

## What it finds

| Secret | How it is checked |
|---|---|
| Solana keypair (the 64-number JSON from `solana-keygen`, or base58, or hex) | Derives the public key from the first 32 bytes and compares it with the last 32. Only a real keypair passes, so transaction signatures and other 64-byte values are never flagged. Shows the wallet address. |
| Seed phrase (12 to 24 words) | Every word must be in the BIP39 list and the checksum must be valid. |
| EVM private key (64 hex characters) | A key looks the same as a tx hash, so it only counts when the code just before it names it as a key: `PRIVATE_KEY=`, `accounts: [`, `new Wallet(`, `--private-key`. |
| Telegram, Discord and GitHub tokens | By their format. |
| RPC URLs with a key in them | Alchemy, Infura, Helius, QuickNode. |
| PEM private key blocks, `xprv` keys | By their header or prefix. |
| `.env` files | By name. `.env.example`, `.env.sample` and `.env.template` are fine. |

Things it deliberately leaves alone: the default Anvil and Hardhat test
accounts, the `test test ... junk` phrase, placeholders like `0x000...0`, and
the Infura key that ships inside forge-std.

## Check a whole repo

```bash
python3 keyguard.py --all        # every file git tracks right now
python3 keyguard.py --history    # every past version of every file
python3 keyguard.py path/to/dir  # any files or folders, git or not
```

`--history` answers "did I ever commit a key here?". It reports each secret
once, with the commit that first added it:

```
config.py:1  EVM private key: 9f2c... (64 hex chars), first committed in 3e1a9bc on 2026-03-14
```

If that repo was ever pushed, treat the key as stolen: move the funds to a
new wallet and rotate the token. Rewriting history does not undo a leak.

## Run it in CI

A hook only protects machines it is installed on. This catches everyone else:

```yaml
name: keyguard
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: khalydmaina/keyguard@v1
```

Add `with: { history: true }` and `fetch-depth: 0` on the checkout to scan the
full history instead.

## When it is wrong

- Put `keyguard:allow` in a comment on the line to accept that one line.
- Add paths to a `.keyguardignore` file at the repo root, one per line.
  `fixtures/` skips a folder, `*.snap` skips by name.
- `git commit --no-verify` skips the hook for one commit.

## Limits

- An EVM key with no name near it, for example a bare 64-hex line in a text
  file, is not flagged. Nothing separates it from a hash.
- A seed phrase is only found when its words sit on one line with spaces
  between them.
- A Solana key stored as only its 32-byte seed is not found.
- It covers the tokens listed above, not every API key format. For broad
  coverage use a general scanner like gitleaks alongside it.
- Tested on Linux and WSL. The hook needs `python3` on your PATH.

## Tests

```bash
python3 -m unittest discover -s tests
```

Every secret in the tests is generated while they run, so this repo contains
no key-shaped strings and scans itself clean in CI.

## License

MIT
