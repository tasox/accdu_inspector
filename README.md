# accdu_inspector
### Advanced Microsoft Access Database (ACCDB/ACCDU) Forensics & VBA Analyzer

`accdu_inspector` inspects Microsoft Access packages (`.accdu`, `.accdb`, `.accde`, `.accda`, `.zip`) for hidden code and artifacts.  
It extracts **VBA**, performs **MS‑OVBA decompression**, decodes **Base64/HEX** payloads, supports **YARA** scanning, and assigns a **suspicion score**.

---

## Features
- **VBA extraction** from OLE storages (when `olefile` is installed).
- **Pure‑Python MS‑OVBA decompressor** to recover compressed VBA (no external tools required).
- **Base64 & HEX detection/decoding** with artifacts exported to disk.
- **IOC extraction**: URLs, IPs, and file references (DLL/EXE, scripts, etc.).
- **Suspicion scoring** (0–100) using macros/LOLBins/IOCs/encodings/signatures.
- **YARA scanning** of raw files, blobs, decompressed VBA, Base64 and HEX artifacts (when `yara-python` is installed).
- **CSV/JSON reporting** and a **modules‑only** mode that prints recovered VBA to stdout.

---

## Installation
```bash
git clone https://github.com/tasox/accdu_inspector.git
cd accdu_inspector
pip install olefile oletools yara-python
```
> Optional deps:  
> • `olefile` – enumerate OLE streams (VBA)  
> • `oletools` – enables `olevba` output (if present)  
> • `yara-python` – enables `--yara` rule scanning

---

## Usage (Quick Start)
```bash
# JSON report
python accdu_inspector.py suspicious.accdu --out ./analysis --format json

# CSV report + YARA rules (directory)
python accdu_inspector.py ./samples --out ./out --format csv --yara ./rules

# Modules-only (prints VBA to stdout; no report files)
python accdu_inspector.py sample.accdu --modules-only
```

---

## Complete CLI Reference

| Flag | Type | Default | Description |
|---|---|---:|---|
| `input` | path | — | Path to a `.accdu`/`.accdb`/`.accde`/`.accda`/`.zip` file **or** an extracted folder to analyze. |
| `--out`, `-o` | path | `./accdu_report_YYYYMMDDTHHMMSSZ/` | Output directory for reports and exported artifacts. |
| `--format` , `-f` | `json` or `csv` | `json` | Select report format. |
| `--no-blobs` | flag | `False` | Don’t export raw suspicious blob files. |
| `--no-strings` | flag | `False` | Don’t write ASCII/UTF‑16 string dumps. |
| `--no-ole` | flag | `False` | Disable OLE/VBA extraction even if `olefile` is installed. |
| `--no-msovba` | flag | `False` | Disable pure‑Python MS‑OVBA decompression. |
| `--modules-only` | flag | `False` | Print recovered VBA (olevba + MS‑OVBA) to stdout and exit (no report files). |
| `--yara PATH` | file/dir | `None` | Compile YARA rules from a single `.yar/.yara` file or all rules in a directory (requires `yara-python`). |

> Note: There is **no** `-d` flag. Previous examples using `-d` were incorrect and are fixed here.

---

## Output Structure
```
accdu_report_YYYYMMDDTHHMMSSZ/
├── report.json / report.csv
├── blobs/           # exported suspicious raw blobs
├── strings/         # ASCII/UTF-16LE strings per file
├── vba/             # .bin, .txt, .msovba.txt, .olevba.txt
├── b64/             # decoded Base64 payloads (.b64.bin + .txt)
└── hex_blobs/       # long HEX sequences converted to binaries
```

---

## Suspicion Score (0–100)
- Heuristic macro/LOLBins keywords (up to 40)
- URLs/IPs present (+10/+5)
- DLL/EXE or other file references (+5)
- Signatures: OLE (+10), PE/MZ (+15)
- Base64 or HEX artifacts (+10 each)

---

## YARA Scanning
Use `--yara` to load rules and scan **raw files**, **exported blobs**, **MS‑OVBA‑decompressed VBA**, and **Base64/HEX artifacts**.

```bash
python accdu_inspector.py file.accdu --out ./out --yara ./rules
python accdu_inspector.py folder --format csv --yara ./malware_rules.yar
```
- JSON adds `yara_matches` per item (rule, tags, meta, matched string previews).  
- CSV adds `yara_count` with the match count per row.

### Good rule sources
- YARA‑Rules community (`YARA-Rules/rules` on GitHub)  
- Neo23x0’s **signature-base** (Florian Roth)  
- abuse.ch malware families and feeds  
- Elastic Security protections artifacts  
- Mandiant / vendor blogs and incident writeups  
- VirusTotal’s official YARA repository

> Always review rules and tailor them to your environment to reduce false positives.

---

## Example Output (JSON excerpt)
```json
{
  "relpath": "Forms/Form1.bin",
  "size": 48923,
  "entropy": 7.41,
  "suspicion": 78,
  "keyword_hits": ["CreateObject(", "Shell(", "Base64"],
  "iocs": {
    "urls": ["http://malicious.example.com"],
    "ips": ["192.168.56.101"],
    "files": ["payload.dll", "update.exe"]
  },
  "signatures": [{"sig":"OLE_CF","offset":0}],
  "yara_matches": [{"rule":"MAL_VBA_MacroDropper","tags":["vba","dropper"]}],
  "exported": {
    "vba_decompressed": ["out/vba/Form1.bin.msovba.txt"],
    "b64": ["out/b64/Form1.0.b64.bin"],
    "hex": ["out/hex_blobs/Form1.0.hexbin"]
  }
}
```

---

## License
MIT License © 2025 — *TasoX*