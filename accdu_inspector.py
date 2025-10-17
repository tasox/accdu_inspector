#!/usr/bin/env python3

from __future__ import annotations
import argparse, os, zipfile, tempfile, shutil, re, json, csv, time, math
from datetime import datetime

# --- Config / patterns ---
SIGS = {
    'OLE_CF': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
    'ZIP': b'PK\x03\x04',
    'ZIP_EOCD': b'PK\x05\x06',
    '7Z': b'7z\xBC\xAF\x27\x1C',
    'RAR5': b'Rar!\x1A\x07\x00',
}

KEYWORDS = [
    'AutoExec','RunCode','CreateObject(','Wscript.Shell','URLDownloadToFile',
    'PowerShell','cmd.exe','WinExec(','Shell(','MSXML2.XMLHTTP','ADODB.Stream',
    'GetObject(','Chr(','Environ$','http://','https://','ftp://','FromBase64String',
    'StrReverse','ExecuteGlobal','Auto_open','OnLoad','OnOpen','OpenForm','RunMacro'
]

MIN_ASCII = 4
MIN_UTF16 = 4

# Correct, simplified patterns (no broken ranges)
RE_URL = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
RE_IP = re.compile(
    r'(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])'
)
RE_DOMAIN = re.compile(
    r'(?:(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)\.)+[a-z]{2,63}',
    re.IGNORECASE
)

# --- Utilities ---
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for v in freq.values():
        p = v / len(data)
        entropy -= p * math.log2(p)
    return entropy

def extract_ascii_strings(data: bytes, min_len: int=MIN_ASCII):
    res = []
    curr = []
    for b in data:
        if 32 <= b <= 126:
            curr.append(chr(b))
        else:
            if len(curr) >= min_len:
                res.append(''.join(curr))
            curr = []
    if len(curr) >= min_len:
        res.append(''.join(curr))
    return res

def extract_utf16le_strings(data: bytes, min_len: int=MIN_UTF16):
    res = []
    i = 0
    n = len(data)
    curr = []
    while i+1 < n:
        lo = data[i]
        hi = data[i+1]
        if hi == 0 and 32 <= lo <= 126:
            curr.append(chr(lo))
            i += 2
            continue
        else:
            if len(curr) >= min_len:
                res.append(''.join(curr))
            curr = []
            i += 2
    if len(curr) >= min_len:
        res.append(''.join(curr))
    return res

def find_signatures(data: bytes):
    found = []
    for name, sig in SIGS.items():
        idx = data.find(sig)
        if idx != -1:
            found.append({'sig': name, 'offset': idx})
    return found

def find_iocs(text: str):
    urls = RE_URL.findall(text)
    ips = RE_IP.findall(text)
    domains = RE_DOMAIN.findall(text)
    # deduplicate while preserving order
    def uniq(seq):
        seen=set(); out=[]
        for s in seq:
            key = s.lower()
            if key not in seen:
                seen.add(key); out.append(s)
        return out
    return {'urls': uniq(urls), 'ips': uniq(ips), 'domains': uniq(domains)}

# --- Core class ---
class AccduInspector:
    def __init__(self, source_path: str, out_dir: str|None=None, export_blobs: bool=True, export_strings: bool=True):
        self.source = os.path.abspath(source_path)
        self.export_blobs = export_blobs
        self.export_strings = export_strings
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        self.out_dir = os.path.abspath(out_dir) if out_dir else os.path.abspath(f'./accdu_report_{ts}')
        os.makedirs(self.out_dir, exist_ok=True)
        self.tmpdir = tempfile.mkdtemp(prefix='accdu_extract_')
        self.files_to_scan = []  # list of (abs_path, rel_path)
        self.summary = []

    def cleanup(self):
        try:
            shutil.rmtree(self.tmpdir)
        except Exception:
            pass

    def prepare(self):
        # If file is zip-like, extract; if it's a folder, walk; else treat as raw file
        if os.path.isfile(self.source):
            lower = self.source.lower()
            if lower.endswith(('.zip','.accdu','.accdb','.accde','.accda')):
                try:
                    with zipfile.ZipFile(self.source, 'r') as z:
                        z.extractall(self.tmpdir)
                        for root,_,files in os.walk(self.tmpdir):
                            for f in files:
                                absf = os.path.join(root,f)
                                rel = os.path.relpath(absf, self.tmpdir)
                                self.files_to_scan.append((absf, rel))
                    return
                except zipfile.BadZipFile:
                    # not a zip; fall through to add file itself
                    pass
            # treat as raw file
            self.files_to_scan.append((self.source, os.path.basename(self.source)))
        elif os.path.isdir(self.source):
            for root,_,files in os.walk(self.source):
                for f in files:
                    absf = os.path.join(root,f)
                    rel = os.path.relpath(absf, self.source)
                    self.files_to_scan.append((absf, rel))
        else:
            raise FileNotFoundError(self.source)

    def analyze_all(self):
        for absf, rel in self.files_to_scan:
            try:
                rec = self.analyze_file(absf, rel)
            except Exception as e:
                rec = {'relpath': rel, 'error': str(e)}
            self.summary.append(rec)

    def analyze_file(self, filepath: str, relpath: str) -> dict:
        with open(filepath, 'rb') as f:
            data = f.read()
        entropy = round(shannon_entropy(data),3)
        ascii_strings = extract_ascii_strings(data)
        utf16_strings = extract_utf16le_strings(data)
        all_text = '\n'.join(ascii_strings + utf16_strings)
        sigs = find_signatures(data)
        iocs = find_iocs(all_text)
        keyword_hits = [kw for kw in KEYWORDS if re.search(re.escape(kw), all_text, flags=re.IGNORECASE)]
        suspicious = bool(sigs or keyword_hits or iocs['urls'] or iocs['ips'] or iocs['domains'])
        exported = {'blobs':[], 'strings': None}

        # Export raw blob if suspicious and allowed
        if suspicious and self.export_blobs:
            blobs_dir = os.path.join(self.out_dir, 'blobs')
            os.makedirs(blobs_dir, exist_ok=True)
            base = os.path.basename(relpath).replace(os.sep,'_')
            outp = os.path.join(blobs_dir, f'{base}_{int(time.time())}.bin')
            with open(outp, 'wb') as ob:
                ob.write(data)
            exported['blobs'].append(outp)

        # Export strings if requested
        if self.export_strings:
            sdir = os.path.join(self.out_dir, 'strings')
            os.makedirs(sdir, exist_ok=True)
            sfile = os.path.join(sdir, relpath.replace(os.sep,'_') + '.txt')
            with open(sfile, 'w', encoding='utf-8', errors='replace') as sf:
                sf.write('---ASCII---\n' + '\n'.join(ascii_strings) + '\n---UTF16LE---\n' + '\n'.join(utf16_strings))
            exported['strings'] = sfile

        return {
            'relpath': relpath,
            'size': len(data),
            'entropy': entropy,
            'signatures': sigs,
            'keyword_hits': keyword_hits,
            'iocs': iocs,
            'suspicious': suspicious,
            'exported': exported
        }

    def write_reports(self, fmt: str='json'):
        os.makedirs(self.out_dir, exist_ok=True)
        if fmt.lower() == 'json':
            outp = os.path.join(self.out_dir, 'report.json')
            with open(outp, 'w', encoding='utf-8') as jf:
                json.dump(self.summary, jf, indent=2)
            print('Wrote JSON report to', outp)
        else:
            outp = os.path.join(self.out_dir, 'report.csv')
            keys = ['relpath','size','entropy','suspicious','keyword_hits','iocs_urls','iocs_ips','iocs_domains','signatures','exported_blobs','exported_strings']
            with open(outp, 'w', newline='', encoding='utf-8') as cf:
                w = csv.writer(cf)
                w.writerow(keys)
                for r in self.summary:
                    sigs = ';'.join([f"{s['sig']}@{s['offset']}" for s in (r.get('signatures') or [])])
                    exported_blobs = ';'.join(r.get('exported',{}).get('blobs') or [])
                    exported_strings = r.get('exported',{}).get('strings') or ''
                    iocs = r.get('iocs') or {}
                    w.writerow([
                        r.get('relpath'),
                        r.get('size'),
                        r.get('entropy'),
                        r.get('suspicious'),
                        ';'.join(r.get('keyword_hits') or []),
                        ';'.join(iocs.get('urls') or []),
                        ';'.join(iocs.get('ips') or []),
                        ';'.join(iocs.get('domains') or []),
                        sigs,
                        exported_blobs,
                        exported_strings
                    ])
            print('Wrote CSV report to', outp)

# --- CLI ---
def build_cli():
    p = argparse.ArgumentParser(description='Analyze .accdu/.accdb/.zip packages for hidden blobs and IOCs (safe, static).')
    p.add_argument('input', help='Path to .accdu/.zip file or extracted folder')
    p.add_argument('--out', '-o', help='Output directory', default=None)
    p.add_argument('--no-blobs', action='store_true', help='Do not export raw blob files')
    p.add_argument('--no-strings', action='store_true', help='Do not export raw string dumps')
    p.add_argument('--format', '-f', choices=['json','csv'], default='json', help='Output report format')
    return p

def main():
    parser = build_cli()
    args = parser.parse_args()
    inspector = AccduInspector(
        args.input,
        out_dir=args.out,
        export_blobs=not args.no_blobs,
        export_strings=not args.no_strings
    )
    try:
        print('Preparing...')
        inspector.prepare()
        print(f'Scanning {len(inspector.files_to_scan)} files...')
        inspector.analyze_all()
        inspector.write_reports(fmt=args.format)
        print('Done. Output directory:', inspector.out_dir)
    finally:
        inspector.cleanup()

if __name__ == '__main__':
    main()
