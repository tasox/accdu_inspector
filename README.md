# accdu_inspector

**accdu_inspector** is a static forensic analyzer for Microsoft Access add-ins and database packages (`.accdu`, `.accdb`, `.accda`, `.accde`, `.zip`).  
It identifies **hidden macros, embedded VBA blobs, URLs, domains, IPs, and suspicious payloads** — without executing the file.

---

## Features

- **Static & Safe** — never executes macros or database code.
- **Blob Extraction** — extracts binary data from hidden system objects like `MSysAccessStorage`.
- **IOC Detection** — identifies URLs, IP addresses, and domains from binary and text data.
- **String Extraction** — decodes ASCII and UTF-16LE strings from each file.
- **Entropy Analysis** — flags compressed or encrypted binary blobs.
- **Flexible Output** — export results in **JSON** or **CSV**.
- **Command-Line Interface** — simple, scriptable CLI with configurable options.

---

## Installation

Clone the repository or download the ZIP:

```bash
git clone https://github.com/tasox/accdu_inspector.git
cd accdu_inspector
```

The tool is pure Python 3 — **no external dependencies** are required.

---

## Usage

Basic example:

```bash
python accdu_inspector.py /path/to/suspicious.accdu --out ./analysis --format json
```

Scan an extracted folder:

```bash
python accdu_inspector.py ./extracted_access_files --out ./results --format csv
```

Skip string exports (faster scan):

```bash
python accdu_inspector.py sample.accdu --no-strings
```

Skip raw blob extraction:

```bash
python accdu_inspector.py sample.accdu --no-blobs
```

---

## Output Structure

After running the tool, you’ll find:

```
accdu_report_YYYYMMDDTHHMMSSZ/
│
├── report.json / report.csv     # Full structured report
├── blobs/                       # Extracted binary blobs
└── strings/                     # Extracted ASCII/UTF-16 strings per file
```

Each analyzed file entry includes:

| Field | Description |
|-------|--------------|
| `relpath` | Relative path within the archive/folder |
| `size` | File size in bytes |
| `entropy` | Shannon entropy score (0-8) |
| `signatures` | Detected binary signatures (OLE, ZIP, etc.) |
| `keyword_hits` | Suspicious VBA/PowerShell keywords |
| `iocs` | Extracted URLs, IPs, and domains |
| `suspicious` | Boolean flag indicating potential risk |
| `exported` | Paths to exported blob and string files |

---

## Example JSON Output

```json
[
  {
    "relpath": "VBA/_CodeModule.bin",
    "size": 5120,
    "entropy": 7.82,
    "signatures": [{"sig": "OLE_CF", "offset": 0}],
    "keyword_hits": ["CreateObject(", "PowerShell"],
    "iocs": {
      "urls": ["https://malicious.example.com/payload"],
      "ips": ["192.168.56.10"],
      "domains": ["malicious.example.com"]
    },
    "suspicious": true,
    "exported": {
      "blobs": ["./accdu_report_.../blobs/_CodeModule.bin"],
      "strings": "./accdu_report_.../strings/_CodeModule.txt"
    }
  }
]
```

---

## Typical Use Cases

- Digital forensics & incident response (DFIR)
- Malware triage of Access-based phishing payloads
- Reverse engineering of embedded VBA add-ins
- IOC extraction for threat intelligence feeds

---

## License

This project is released under the **MIT License**.

--- 
