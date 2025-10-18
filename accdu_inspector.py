#!/usr/bin/env python3

from __future__ import annotations
import argparse, os, zipfile, tempfile, shutil, re, json, csv, time, math, subprocess, base64, glob
from datetime import datetime
from io import BytesIO

# Optional dependency: olefile for OLE parsing
try:
    import olefile  # type: ignore
    HAS_OLEFILE = True
except Exception:
    HAS_OLEFILE = False

# Optional dependency: yara-python
try:
    import yara  # type: ignore
    HAS_YARA = True
except Exception:
    HAS_YARA = False

# ---- Signatures / heuristics ----
SIGS = {
    'OLE_CF': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
    'ZIP': b'PK\x03\x04',
    'MZ': b'MZ',  # PE header marker (if seen inside hex or raw)
    'ZIP_EOCD': b'PK\x05\x06',
    '7Z': b'7z\xBC\xAF\x27\x1C',
    'RAR5': b'Rar!\x1A\x07\x00'
}

# Expanded suspicious keywords (case-insensitive search on strings)
KEYWORDS = [
    # VBA/runtime
    'AutoExec','RunCode','Application.Run','DoCmd.RunSQL','DoCmd.TransferText','DoCmd.TransferSpreadsheet',
    'CreateObject(','GetObject(','Eval(','Shell(','Environ$','Open','Close','Kill','FileCopy','MkDir','RmDir',
    # COM/WSH
    'Wscript.Shell','Scripting.FileSystemObject','ADODB.Stream','MSXML2.XMLHTTP','MSXML2.ServerXMLHTTP',
    'WinHttp.WinHttpRequest','UserAgent','SetRequestHeader','ResponseBody','ResponseText','Send',
    # Windows / process
    'URLDownloadToFile','URLMon','WinExec(','CreateProcess','VirtualAlloc','VirtualProtect','RtlMoveMemory',
    'WriteProcessMemory','ReadProcessMemory','CreateRemoteThread','LoadLibrary','GetProcAddress',
    # PowerShell / LOLBins
    'PowerShell','powershell.exe','cmd.exe','rundll32.exe','regsvr32.exe','mshta.exe','wscript.exe','cscript.exe',
    # Encoding / obfuscation
    'Base64','FromBase64String','StrReverse','Chr(','Asc(','Xor','Split(','Join(','Replace(','Mid(','Left(','Right(',
    # Networking
    'http://','https://','ftp://','smb://','file://','\\UNC\\','\\\\',
    # Registry
    'WScript.Shell','RegWrite','RegRead','HKCU','HKLM','Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    # Persistence / Tasks
    'schtasks','TaskScheduler','RunOnce','Startup','StartupFolder','Shell:Startup',
]

MIN_ASCII = 4
MIN_UTF16 = 4

# URL and IP patterns
RE_URL = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
RE_IP = re.compile(r'(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])')

# DLL / file-like names
RE_FILE = re.compile(r'[A-Za-z0-9_\-\.\\/:]{3,}\.(?:dll|exe|vbs|ps1|bat|js|wsf|lnk|dat|bin|cab|zip|tmp|scr)', re.IGNORECASE)

# Hex blob (>= 80 hex chars) allowing whitespace between
RE_HEX_BLOB = re.compile(r'(?:\s*?[0-9A-Fa-f]{2}){80,}')

# Base64 chunks
RE_B64 = re.compile(r'(?:(?:[A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/]))')

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

def find_iocs_and_files(text: str):
    urls = RE_URL.findall(text)
    ips = RE_IP.findall(text)
    files = RE_FILE.findall(text)
    def uniq(seq):
        seen=set(); out=[]
        for s in seq:
            k=s.lower()
            if k not in seen:
                seen.add(k); out.append(s)
        return out
    return {'urls': uniq(urls), 'ips': uniq(ips), 'files': uniq(files)}

def detect_base64_chunks(text: str):
    return RE_B64.findall(text)

def safe_b64_decode(b64s):
    outs = []
    for s in b64s:
        try:
            t = ''.join(s.split())
            pad = (-len(t)) % 4
            if pad: t += '=' * pad
            data = base64.b64decode(t, validate=False)
            outs.append(data)
        except Exception:
            continue
    return outs

def extract_hex_blobs(text: str):
    blobs = []
    for m in RE_HEX_BLOB.finditer(text):
        hexseq = re.sub(r'\s+', '', m.group(0))
        try:
            blobs.append(bytes.fromhex(hexseq))
        except Exception:
            continue
    return blobs

# --- Pure-Python MS-OVBA decompressor ---
def _copy_token_get_length_and_offset(token, bit_count):
    offset_mask = (1 << bit_count) - 1
    offset = (token & offset_mask) + 1  # 1-based offset
    length = (token >> bit_count) + 3    # +3 per spec
    return length, offset

def _decompress_chunk(payload: bytes, outbuf: bytearray) -> None:
    i = 0
    offset_bits = 12  # typical for VBA
    while i < len(payload):
        flags = payload[i]; i += 1
        for bit in range(8):
            if i >= len(payload):
                break
            if (flags >> bit) & 1 == 0:
                outbuf.append(payload[i]); i += 1
            else:
                if i+1 >= len(payload):
                    return
                token = payload[i] | (payload[i+1] << 8); i += 2
                length, back = _copy_token_get_length_and_offset(token, offset_bits)
                for _ in range(length):
                    if back > len(outbuf):
                        return
                    outbuf.append(outbuf[-back])

def decompress_ms_ovba(data: bytes):
    if not data or data[0] != 0x01:
        return None
    i = 1  # skip signature
    result = bytearray()
    while i + 2 <= len(data):
        header = int.from_bytes(data[i:i+2], 'little'); i += 2
        compressed = (header & 0x8000) != 0
        chunk_size = (header & 0x0FFF)
        if chunk_size == 0:
            chunk_size = min(4095, len(data) - i)
        if i + chunk_size > len(data):
            chunk_size = max(0, len(data) - i)
        chunk = data[i:i+chunk_size]; i += chunk_size
        if not chunk:
            break
        if not compressed:
            result.extend(chunk)
        else:
            _decompress_chunk(chunk, result)
    return bytes(result) if result else None

# Suspicion scoring
def score_suspicion(keyword_hits, iocs, sigs, has_hex, has_b64):
    score = 0
    score += min(40, 2 * len(set([k.lower() for k in (keyword_hits or [])])))
    score += 10 * (1 if iocs.get('urls') else 0)
    score += 5 * (1 if iocs.get('ips') else 0)
    score += 5 * (1 if iocs.get('files') else 0)
    sig_names = [s.get('sig') for s in (sigs or [])]
    if 'MZ' in sig_names: score += 15
    if 'OLE_CF' in sig_names: score += 10
    if has_hex: score += 10
    if has_b64: score += 10
    return max(0, min(100, score))

# YARA support
def load_yara_rules(path: str):
    if not HAS_YARA:
        return None
    if not path:
        return None
    path = os.path.abspath(path)
    if os.path.isdir(path):
        # load all rule files in directory
        files = [p for p in glob.glob(os.path.join(path, '**'), recursive=True) if os.path.isfile(p) and os.path.splitext(p)[1].lower() in ('.yar','.yara')]
        if not files:
            return None
        sources = {f'ns_{i}': open(f,'rb').read().decode('utf-8','ignore') for i,f in enumerate(files)}
        return yara.compile(sources=sources)
    else:
        return yara.compile(filepath=path)

def run_yara_on_bytes(yrules, data: bytes, namespace: str):
    results = []
    if not (HAS_YARA and yrules and data):
        return results
    try:
        matches = yrules.match(data=data, timeout=10)
        for m in matches:
            strings = []
            for (off, sid, val) in m.strings[:50]:  # cap strings for size
                try:
                    display = val if isinstance(val, str) else val.decode('latin-1', 'replace')
                except Exception:
                    display = repr(val)[:120]
                strings.append({'offset': off, 'identifier': sid, 'value_preview': display[:120]})
            results.append({
                'namespace': namespace,
                'rule': m.rule,
                'tags': list(m.tags),
                'meta': m.meta,
                'strings': strings
            })
    except Exception as e:
        results.append({'namespace': namespace, 'error': str(e)})
    return results

class AccduInspector:
    def __init__(self, source_path: str, out_dir: str|None=None, export_blobs: bool=True, export_strings: bool=True, try_ole: bool=True, try_msovba: bool=True, modules_only: bool=False, yara_path: str|None=None):
        self.source = os.path.abspath(source_path)
        self.export_blobs = export_blobs
        self.export_strings = export_strings
        self.try_ole = try_ole and HAS_OLEFILE
        self.try_msovba = try_msovba
        self.modules_only = modules_only
        self.yara_path = yara_path
        self.yara_rules = load_yara_rules(yara_path) if yara_path else None

        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        self.out_dir = os.path.abspath(out_dir) if out_dir else os.path.abspath(f'./accdu_report_{ts}')
        os.makedirs(self.out_dir, exist_ok=True)
        self.tmpdir = tempfile.mkdtemp(prefix='accdu_extract_')
        self.files_to_scan = []  # list of (abs_path, rel_path)
        self.summary = []
        self.modules_stdout = []

    def cleanup(self):
        try:
            shutil.rmtree(self.tmpdir)
        except Exception:
            pass

    def prepare(self):
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
                    pass
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
        # modules-only mode: dump and exit
        if self.modules_only:
            print("\n====== Recovered VBA Modules ======\n")
            for item in self.modules_stdout:
                print(f"--- {item['name']} ---")
                print(item['content'])
                print("\n")
            return  # no report files in modules-only

    def analyze_file(self, filepath: str, relpath: str) -> dict:
        with open(filepath, 'rb') as f:
            data = f.read()
        entropy = round(shannon_entropy(data),3)
        ascii_strings = extract_ascii_strings(data)
        utf16_strings = extract_utf16le_strings(data)
        all_text = '\n'.join(ascii_strings + utf16_strings)
        sigs = find_signatures(data)
        iocs = find_iocs_and_files(all_text)
        keyword_hits = [kw for kw in KEYWORDS if re.search(re.escape(kw), all_text, flags=re.IGNORECASE)]

        # Hex blobs from strings text (not from raw)
        hex_blobs = extract_hex_blobs(all_text)
        hex_out_paths = []
        if hex_blobs:
            hex_dir = os.path.join(self.out_dir, 'hex_blobs')
            os.makedirs(hex_dir, exist_ok=True)
            for idx, blob in enumerate(hex_blobs):
                p = os.path.join(hex_dir, f"{relpath.replace(os.sep,'_')}.{idx}.hexbin")
                with open(p, 'wb') as hf:
                    hf.write(blob)
                hex_out_paths.append(p)

        # Base64 detection & decoding
        b64_chunks = detect_base64_chunks(all_text)
        b64_decoded_paths = []
        if b64_chunks:
            b64_dir = os.path.join(self.out_dir, 'b64')
            os.makedirs(b64_dir, exist_ok=True)
            for idx, decoded in enumerate(safe_b64_decode(b64_chunks)):
                p = os.path.join(b64_dir, f"{relpath.replace(os.sep,'_')}.{idx}.b64.bin")
                with open(p, 'wb') as bf:
                    bf.write(decoded)
                with open(p + '.txt', 'w', encoding='utf-8', errors='replace') as tf:
                    tf.write(decoded.decode('latin-1', errors='replace'))
                b64_decoded_paths.append(p)

        # suspicion
        suspicion = score_suspicion(keyword_hits, iocs, sigs, bool(hex_out_paths), bool(b64_decoded_paths))
        exported = {'blobs':[], 'strings': None, 'vba':[], 'vba_decompressed':[], 'b64': b64_decoded_paths, 'hex': hex_out_paths}
        yara_matches = []

        # YARA on raw file bytes
        if self.yara_rules:
            yara_matches += run_yara_on_bytes(self.yara_rules, data, namespace=f'raw:{relpath}')

        # Export raw blob if suspicious and allowed
        if suspicion >= 10 and self.export_blobs:
            blobs_dir = os.path.join(self.out_dir, 'blobs')
            os.makedirs(blobs_dir, exist_ok=True)
            base = os.path.basename(relpath).replace(os.sep,'_')
            outp = os.path.join(blobs_dir, f'{base}_{int(time.time())}.bin')
            with open(outp, 'wb') as ob:
                ob.write(data)
            exported['blobs'].append(outp)
            # YARA on saved blob (mostly redundant with raw, but keeps path context)
            if self.yara_rules:
                try:
                    with open(outp, 'rb') as bf:
                        yara_matches += run_yara_on_bytes(self.yara_rules, bf.read(), namespace=f'blob:{os.path.basename(outp)}')
                except Exception:
                    pass

        # If OLE CF and olefile available, try to extract VBA streams
        for s in sigs:
            if s.get('sig') == 'OLE_CF' and self.try_ole:
                try:
                    vba_paths = self.extract_vba_from_ole(data, relpath)
                    exported['vba'].extend(vba_paths or [])
                except Exception as e:
                    exported['vba'].append({'error': str(e)})

        # Try MS-OVBA decompression on saved VBA .bin streams
        if self.try_msovba:
            vba_out_root = os.path.join(self.out_dir, 'vba', relpath.replace(os.sep,'_'))
            if os.path.isdir(vba_out_root):
                for name in os.listdir(vba_out_root):
                    if not name.lower().endswith('.bin'):
                        continue
                    bin_path = os.path.join(vba_out_root, name)
                    try:
                        with open(bin_path, 'rb') as bf:
                            raw = bf.read()
                        decomp = decompress_ms_ovba(raw)
                        if decomp:
                            txtpath = bin_path + '.msovba.txt'
                            with open(txtpath, 'w', encoding='utf-8', errors='replace') as tf:
                                tf.write(decomp.decode('latin-1', errors='replace'))
                            exported['vba_decompressed'].append(txtpath)
                            # modules-only collection
                            if self.modules_only:
                                self.modules_stdout.append({'name': name + ' (msovba)', 'content': decomp.decode('latin-1', errors='replace')})
                            # YARA on decompressed VBA text bytes
                            if self.yara_rules:
                                yara_matches += run_yara_on_bytes(self.yara_rules, decomp, namespace=f'vba:{name}.msovba.txt')
                    except Exception as e:
                        exported['vba_decompressed'].append({'error':str(e),'bin':bin_path})

        # YARA on decoded b64 and hex artifacts
        if self.yara_rules:
            for p in b64_decoded_paths + hex_out_paths:
                try:
                    with open(p, 'rb') as f:
                        yara_matches += run_yara_on_bytes(self.yara_rules, f.read(), namespace=f'artifact:{os.path.basename(p)}')
                except Exception:
                    pass

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
            'suspicion': suspicion,
            'yara_matches': yara_matches,
            'exported': exported
        }

    def extract_vba_from_ole(self, data: bytes, relpath: str) -> list:
        import olefile  # local import to ensure error shows if missing
        paths = []
        ole = olefile.OleFileIO(BytesIO(data))
        entries = ole.listdir(streams=True, storages=True)
        vba_streams = []
        for e in entries:
            if len(e) >=1 and e[0].upper() in ('VBA','MACROS'):
                vba_streams.append(e)
        for e in entries:
            en = '/'.join(e)
            if en.lower().endswith('dir') or 'vba' in en.lower() or 'project' in en.lower():
                if e not in vba_streams:
                    vba_streams.append(e)

        vba_out_dir = os.path.join(self.out_dir, 'vba', relpath.replace(os.sep,'_'))
        os.makedirs(vba_out_dir, exist_ok=True)

        for entry in vba_streams:
            try:
                stream_name = '/'.join(entry)
                raw = ole.openstream(entry).read()
                fname_safe = stream_name.replace('/','_').replace('\\','_')
                outpath = os.path.join(vba_out_dir, fname_safe + '.bin')
                with open(outpath, 'wb') as f:
                    f.write(raw)
                paths.append(outpath)
                # Raw text dump for quick glance
                txtpath = outpath + '.txt'
                try:
                    txt = raw.decode('utf-8', errors='strict')
                except Exception:
                    txt = raw.decode('latin-1', errors='replace')
                with open(txtpath, 'w', encoding='utf-8', errors='replace') as tf:
                    tf.write(txt)
                paths.append(txtpath)
                # Optional: run olevba if available
                try:
                    res = subprocess.run(['olevba', outpath], capture_output=True, text=True, timeout=30)
                    if res.returncode == 0 or res.stdout or res.stderr:
                        ov_out = os.path.join(vba_out_dir, fname_safe + '.olevba.txt')
                        with open(ov_out, 'w', encoding='utf-8', errors='replace') as ovf:
                            ovf.write('=== STDOUT ===\n')
                            ovf.write(res.stdout or '')
                            ovf.write('\n=== STDERR ===\n')
                            ovf.write(res.stderr or '')
                        paths.append(ov_out)
                        if self.modules_only and res.stdout:
                            self.modules_stdout.append({'name': fname_safe + ' (olevba)', 'content': res.stdout})
                except FileNotFoundError:
                    pass
                except Exception:
                    pass
            except Exception as e:
                paths.append({'stream':entry, 'error':str(e)})
        ole.close()
        return paths

    def write_reports(self, fmt: str='json'):
        os.makedirs(self.out_dir, exist_ok=True)
        if fmt.lower() == 'json':
            outp = os.path.join(self.out_dir, 'report.json')
            with open(outp, 'w', encoding='utf-8') as jf:
                json.dump(self.summary, jf, indent=2)
            print('Wrote JSON report to', outp)
        else:
            outp = os.path.join(self.out_dir, 'report.csv')
            keys = ['relpath','size','entropy','suspicion','keyword_hits','iocs_urls','iocs_ips','iocs_files','signatures','yara_count','exported_blobs','exported_strings','exported_vba','exported_vba_decompressed','exported_b64','exported_hex']
            with open(outp, 'w', newline='', encoding='utf-8') as cf:
                w = csv.writer(cf)
                w.writerow(keys)
                for r in self.summary:
                    sigs = ';'.join([f"{s['sig']}@{s['offset']}" for s in (r.get('signatures') or [])])
                    exported = r.get('exported',{})
                    exported_blobs = ';'.join([str(x) for x in (exported.get('blobs') or [])])
                    exported_strings = exported.get('strings') or ''
                    exported_vba = ';'.join([str(x) for x in (exported.get('vba') or [])])
                    exported_vba_de = ';'.join([str(x) for x in (exported.get('vba_decompressed') or [])])
                    exported_b64 = ';'.join([str(x) for x in (exported.get('b64') or [])])
                    exported_hex = ';'.join([str(x) for x in (exported.get('hex') or [])])
                    iocs = r.get('iocs') or {}
                    yara_count = len(r.get('yara_matches') or [])
                    w.writerow([
                        r.get('relpath'),
                        r.get('size'),
                        r.get('entropy'),
                        r.get('suspicion'),
                        ';'.join(r.get('keyword_hits') or []),
                        ';'.join(iocs.get('urls') or []),
                        ';'.join(iocs.get('ips') or []),
                        ';'.join(iocs.get('files') or []),
                        sigs,
                        yara_count,
                        exported_blobs,
                        exported_strings,
                        exported_vba,
                        exported_vba_de,
                        exported_b64,
                        exported_hex
                    ])
            print('Wrote CSV report to', outp)

# ---- CLI ----
def build_cli():
    p = argparse.ArgumentParser(description='Analyze .accdu/.accdb/.zip packages; YARA-scan blobs, extract VBA, decode Base64, score suspicion, and export IOCs.')
    p.add_argument('input', help='Path to .accdu/.zip file or extracted folder')
    p.add_argument('--out', '-o', help='Output directory', default=None)
    p.add_argument('--no-blobs', action='store_true', help='Do not export raw blob files')
    p.add_argument('--no-strings', action='store_true', help='Do not export raw string dumps')
    p.add_argument('--no-ole', action='store_true', help='Do not attempt OLE/VBA extraction (even if olefile is installed)')
    p.add_argument('--no-msovba', action='store_true', help='Do not attempt pure-Python MS-OVBA decompression')
    p.add_argument('--format', '-f', choices=['json','csv'], default='json', help='Output report format')
    p.add_argument('--modules-only', action='store_true', help='Print recovered VBA (olevba/msovba) to stdout and exit')
    p.add_argument('--yara', help='Path to a YARA rule file or directory of .yar/.yara rules', default=None)
    return p

def main():
    parser = build_cli()
    args = parser.parse_args()
    inspector = AccduInspector(
        args.input,
        out_dir=args.out,
        export_blobs=not args.no_blobs,
        export_strings=not args.no_strings,
        try_ole=not args.no_ole,
        try_msovba=not args.no_msovba,
        modules_only=args.modules_only,
        yara_path=args.yara
    )
    try:
        print('Preparing... (olefile: {}, yara: {})'.format('yes' if HAS_OLEFILE else 'no', 'yes' if HAS_YARA else 'no'))
        if args.yara and not HAS_YARA:
            print('WARNING: --yara specified but yara-python is not installed. Install with: pip install yara-python')
        inspector.prepare()
        print('Scanning {} files...'.format(len(inspector.files_to_scan)))
        inspector.analyze_all()
        if not args.modules_only:
            inspector.write_reports(fmt=args.format)
            print('Done. Output directory:', inspector.out_dir)
        if not HAS_OLEFILE:
            print('\nTip: install olefile for richer OLE parsing:')
            print('  pip install olefile')
        print('Optional: install oletools to enable `olevba` output:')
        print('  pip install oletools')
        print('Optional: install yara-python for YARA scanning:')
        print('  pip install yara-python')
    finally:
        inspector.cleanup()

if __name__ == '__main__':
    main()
