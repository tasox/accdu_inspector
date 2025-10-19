### Advanced Microsoft Access Database Forensics & VBA / Binary Artifact Analyzer  

---

## Overview

`accdu_inspector` is a forensic and malware analysis tool designed to inspect Microsoft Access databases (`.accdu`, `.accdb`, `.accde`, `.accda`, or extracted ZIPs).  
It reveals **hidden macros, VBA payloads, OLE streams, and binary blobs** embedded inside Access containers — even when they’re hex‑encoded, fragmented, or disguised in UTF‑16.

Built for DFIR and threat research workflows, it combines:

- Deep VBA marker detection (tolerant to null‑interleaving and Unicode obfuscation)  
- MS‑OVBA decompression (pure Python)  
- YARA rule scanning (raw + carved data)  
- Robust blob carving (magic‑based, entropy‑based, HEX ASCII, and UTF‑16 HEX)  
- Suspicion scoring based on multiple heuristics  
- Structured CSV/JSON reporting  

---

## What’s New in v1.1

| Enhancement | Description |
|--------------|--------------|
| **Fragmentation‑Free HEX Recovery** | Nearby HEX chunks are automatically merged into a single blob instead of being saved as multiple partial files. |
| **UTF‑16 / Null‑Interleaved HEX Detection** | Detects patterns like `4D5...` common in obfuscated Access payloads. |
| **Blob De‑duplication (SHA‑256)** | Repeated binary data is detected and stored only once. |
| **Tuning Flags** | Full control over carving thresholds, entropy sensitivity, and merging behavior. |
| **Integrated Carving Logic** | HEX, UTF‑16 HEX, and high‑entropy carving are unified under the same pipeline. |
| **Refined Scoring Engine** | Suspicion score now incorporates VBA presence, keyword density, and embedded file signatures. |

---

## How It Works

1. **Extracts all streams** from Access files, including hidden `MSysObjects` and `MSysAccessStorage`.  
2. **Scans for VBA markers** (`VBAPROJECT`, `dir`, `CMG=`, etc.) — even when obfuscated or stored as UTF‑16.  
3. **Carves embedded data** through four layers:
   - Signature‑based (MZ, OLE, ZIP, PDF, PNG, RAR, 7Z, etc.)
   - High‑entropy windows (detects compressed or encrypted blobs)
   - HEX ASCII runs (merged, no more fragmentation)
   - UTF‑16 HEX runs (merged)
4. **Runs YARA** (if provided) on all carved and decompressed content.
5. **Exports** structured reports, strings, and binary evidence.

---

## Installation

```bash
git clone https://github.com/tasox/accdu_inspector.git
cd accdu_inspector
pip install olefile oletools yara-python
```

---

## Command-Line Reference

| Flag | Description |
|------|--------------|
| `input` | Path to an `.accdu`, `.accdb`, `.accde`, `.accda`, `.zip`, or folder. |
| `--out`, `-o` | Output directory for results. |
| `--format`, `-f` | Output format: `json` or `csv`. |
| `--modules-only` | Prints all recovered VBA to stdout and exits. |
| `--dump-markers` | Displays a table of VBA markers with byte offsets during the run. |
| `--dump-markers-json <file>` | Saves marker map to JSON. |
| `--extract-from-markers` | Attempts MS‑OVBA decompression near marker offsets. |
| `--yara <path>` | Scan with YARA rules from a file or directory. |
| `--no-strings` | Skip string extraction. |
| `--no-ole` | Disable OLE VBA extraction. |
| `--no-msovba` | Disable pure‑Python MS‑OVBA decompression. |
| `--no-dedupe` | Disable SHA‑256 de‑duplication of carved blobs. |

### Tuning Parameters

| Flag | Default | Purpose |
|------|----------|----------|
| `--min-hex-chars` | 100 | Minimum continuous hex chars for ASCII HEX carving. |
| `--utf16-min-pairs` | 60 | Minimum UTF‑16 hex pairs to detect (for null‑interleaved sequences). |
| `--entropy-threshold` | 7.2 | Entropy threshold for “generic high‑entropy” blob carving. |
| `--carve-window` | 1024 | Size of sliding entropy window. |
| `--carve-min-size` | 256 | Minimum bytes for a blob to be saved. |
| `--merge-gap-chars` | 64 | Merge fragmented ASCII hex runs separated by ≤N chars. |
| `--merge-gap-bytes` | 64 | Merge fragmented UTF‑16 hex runs separated by ≤N bytes. |

---

## Carving & De‑duplication Behavior

1. **Signature carving**  
   Extracts binary data starting from known file headers (e.g., `MZ`, `OLE_CF`, `ZIP`, `7Z`).  

2. **Entropy carving**  
   Slides a 1 KB window and merges windows exceeding the threshold entropy (default 7.2).  

3. **HEX ASCII & UTF‑16 HEX carving**  
   Locates hex sequences representing binary data, cleans and merges nearby segments.  

4. **De‑duplication**  
   All blobs are hashed with SHA‑256. Identical data is only written once, preventing repeated fragments.  

---

## Heuristic Scoring (0–100)

| Component | Weight |
|------------|--------|
| Keyword presence | 0–40 |
| URLs/IPs/files | +10–20 |
| OLE/PE signatures | +15–25 |
| Embedded blobs | +15 |
| VBA markers | +15 |

High scores suggest suspicious or executable content.

---

## Example Workflows

### 1. Standard Scan
```bash
python accdu_inspector.py sample.accdu --out ./analysis
```

### 2. Marker‑Based VBA Extraction
```bash
python accdu_inspector.py suspect.accdu --out ./out --dump-markers --extract-from-markers
```

### 3. Deep Carving (Aggressive)
```bash
python accdu_inspector.py suspect.accdu --out ./out   --entropy-threshold 6.8 --min-hex-chars 80 --utf16-min-pairs 50   --merge-gap-chars 128 --merge-gap-bytes 128
```

### 4. YARA‑Enhanced DFIR Scan
```bash
python accdu_inspector.py ./samples --out ./out --yara ./rules
```

---

## Output Structure

```
accdu_report_20251019T000000Z/
├── report.json / report.csv
├── strings/
├── vba/
│   ├── *.bin
│   ├── *.txt
│   └── from_markers/
├── blobs/
│   └── carved/
│       ├── magic_*.bin
│       ├── hexascii_*.bin
│       └── hexutf16_*.bin
├── markers.json
└── yara/
```

---

## Best Practices

- Use `--dump-markers` during triage to locate hidden VBA signatures.  
- Combine with `--extract-from-markers` for auto‑recovery.  
- Adjust entropy thresholds when analyzing compressed or obfuscated payloads.  
- Review high‑entropy `.bin` files manually — often they’re encrypted or packed executables.  
- Re‑scan carved blobs with external tools (e.g., PEStudio, ExifTool, capa).  

---

## Recommended YARA Sources

- [YARA‑Rules/rules](https://github.com/YARA-Rules/rules)  
- [Neo23x0/signature‑base](https://github.com/Neo23x0/signature-base)  
- [Elastic Security Artifacts](https://github.com/elastic/protections-artifacts)  
- [abuse.ch Feeds](https://abuse.ch)  
- [Mandiant / VirusTotal YARA Repos](https://github.com/VirusTotal/yara)  

---

## License
MIT License © 2025 — *TasoX*

---