# 🔍 Hash Identifier — Xerxes Bytes

> *"We will find a way, or we will make a way."*
> — **Xerxes Bytes (XBS)** ⚔️

A **PyQt5 GUI hash type identification tool** that analyzes hash values by their length, character set, and structural patterns — instantly identifying the most likely algorithm(s) from a database of **35+ hash types**.

Features a dark hacker-style interface with live identification as you type.

Built and developed by **Xerxes Bytes** — a student-driven cybersecurity research team.

---

## ✨ Features

- 🔍 **35+ Hash Types** — MD5, SHA family, bcrypt, Argon2, NTLM, Unix crypt, MySQL, Cisco, and more
- ⚡ **Live Identification** — results update as you type
- 📋 **Multi-Hash Input** — paste multiple hashes at once (one per line)
- 🎯 **Confidence Scoring** — Exact Match / Likely Match / Possible
- 🖥️ **Dark GUI** — hacker-aesthetic PyQt5 terminal-style interface
- 📊 **Algorithm Notes** — security status and usage context for each hash type

---

## 📦 Installation

```bash
git clone https://github.com/ZopIros/Hash-Identifier-Xerxes-Bytes.git
cd Hash-Identifier-Xerxes-Bytes
pip install PyQt5
python hash_identifier.py
```

---

## 🚀 Usage

Just run the GUI:
```bash
python hash_identifier.py
```

Paste one or more hash values in the input box. Results appear instantly.

---

## 🗃️ Supported Hash Types

| Algorithm | Length | Notes |
|-----------|--------|-------|
| MD5 | 32 | Widely used, insecure |
| SHA-1 | 40 | Deprecated |
| SHA-256 | 64 | SHA-2 family, common |
| SHA-512 | 128 | SHA-2 family, strong |
| SHA3-256 / SHA3-512 | 64 / 128 | SHA-3 family |
| NTLM | 32 | Windows authentication |
| LM Hash | 32 | Legacy Windows |
| bcrypt | 60 | Adaptive, `$2y$...` format |
| Argon2i / Argon2id | variable | Memory-hard, recommended |
| scrypt | variable | Memory-hard |
| SHA-512 Crypt | 106 | Unix shadow `$6$...` |
| MySQL 4.1+ | 41 | `*` prefix format |
| PBKDF2-SHA256 | variable | Django default |
| BLAKE2b-512 | 128 | Modern, fast |
| RIPEMD-160 | 40 | Bitcoin addresses |
| Cisco IOS / Type 7 | variable | Network gear |
| CRC32 / Adler-32 | 8 | Checksums |
| DES Crypt | 13 | Old Unix |
| Whirlpool | 128 | ISO standard |
| Tiger-192 | 48 | Fast algorithm |
| + more... | | |

---

## 📸 Screenshot

```
┌─────────────────────────────────────────────────────┐
│  🔍 HASH IDENTIFIER ⚔️  Xerxes Bytes               │
│  "We will find a way, or we will make a way."       │
├─────────────────────────────────────────────────────┤
│  Paste hash value(s) below:                         │
│  ┌───────────────────────────────────────────────┐  │
│  │ 5f4dcc3b5aa765d61d8327deb882cf99              │  │
│  └───────────────────────────────────────────────┘  │
│  [ 🔍 IDENTIFY ]  [ ✕ Clear ]                       │
├────────────────┬───────────┬────────┬───────────────┤
│ Hash           │ Algorithm │ Length │ Confidence    │
├────────────────┼───────────┼────────┼───────────────┤
│ 5f4dcc3b5aa7…  │ MD5       │ 32     │ ✅ Exact Match │
│ 5f4dcc3b5aa7…  │ NTLM      │ 32     │ 🟡 Likely     │
└────────────────┴───────────┴────────┴───────────────┘
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational and authorized security research** only.

**Xerxes Bytes (XBS) assumes no responsibility for misuse.**

---

## 👤 Author

**Xerxes Bytes (XBS)**
🔗 [github.com/ZopIros](https://github.com/ZopIros)
⚔️ *"We will find a way, or we will make a way."*
