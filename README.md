# PathTraverser

**PathTraverser** — A lightweight CLI path-traversal / LFI scanner for authorized security testing.  
By **Mrutunjaya Senapati**

---

## Short description (15 words)
Lightweight CLI path traversal scanner for authorized security testing, payload-rich, logs findings, easy to extend.

## Summary (≤350 characters)
PathTraverser is a lightweight CLI path-traversal/LFI scanner for authorized security testing. It ships with extensive encoded and null-byte payloads, logs responses, flags likely file disclosures, supports single or batch URL scans, and is easy to extend with proxy, threading, and CSV export options. Includes README, MIT license, and CI templates.

---

## ⚠️ Legal / Safety Notice
**Use this tool ONLY** on systems you own or have **explicit written permission** to test. Unauthorized scanning or exploitation is illegal and unethical. The author is not responsible for misuse.

---

## Features
- Test a single URL or a list of URLs (batch).
- Large built-in payload list (encoded, null-byte, Windows/Linux variants).
- Logs responses and errors to `results/response_logs.txt`.
- Saves confirmed findings to `results/vulnerable_paths.txt`.
- Minimal dependencies, easy to run and extend.

---

## Requirements
- Python 3.8+
- Install dependencies:
```bash
pip install -r requirements.txt
