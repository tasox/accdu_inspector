#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import argparse, os, zipfile, tempfile, shutil, re, json, csv, time, math, subprocess, glob, hashlib
from datetime import datetime
from io import BytesIO

# Optional deps
try:
    import olefile  # type: ignore
    HAS_OLEFILE = True
except Exception:
    HAS_OLEFILE = False

try:
    import yara  # type: ignore
    HAS_YARA = True
except Exception:
    HAS_YARA = False

MAGICS = [
    ('OLE_CF', b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'),
    ('MZ', b'MZ'),
    ('ZIP', b'PK\x03\x04'),
    ('PNG', b'\x89PNG\r\n\x1a\n'),
    ('PDF', b'%PDF-'),
    ('RAR', b'Rar!\x1A\x07\x00'),
    ('RAR5', b'Rar!\x1A\x07\x01\x00'),
    ('GZIP', b'\x1F\x8B\x08'),
    ('7Z', b'7z\xBC\xAF\x27\x1C'),
]

KEYWORDS = [
    'AutoExec','RunCode','Application.Run','DoCmd.RunSQL','DoCmd.TransferText','DoCmd.TransferSpreadsheet',
    'CreateObject(','GetObject(','Eval(','Shell(','Environ$','Open','Close','Kill','FileCopy','MkDir','RmDir',
    'Wscript.Shell','Scripting.FileSystemObject','ADODB.Stream','MSXML2.XMLHTTP','MSXML2.ServerXMLHTTP',
    'WinHttp.WinHttpRequest','UserAgent','SetRequestHeader','ResponseBody','ResponseText','Send',
    'URLDownloadToFile','URLMon','WinExec(','CreateProcess','VirtualAlloc','VirtualProtect','RtlMoveMemory',
    'WriteProcessMemory','ReadProcessMemory','CreateRemoteThread','LoadLibrary','GetProcAddress',
    'PowerShell','powershell.exe','cmd.exe','rundll32.exe','regsvr32.exe','mshta.exe','wscript.exe','cscript.exe',
    'Base64','FromBase64String','StrReverse','Chr(','Asc(','Xor','Split(','Join(','Replace(','Mid(','Left(','Right(',
    'http://','https://','ftp://','smb://','file://','\\UNC\\','\\\\',
    'WScript.Shell','RegWrite','RegRead','HKCU','HKLM','Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'schtasks','TaskScheduler','RunOnce','Startup','StartupFolder','Shell:Startup',
]

RE_URL = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
RE_IP = re.compile(r'(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])')
RE_FILE = re.compile(r'[A-Za-z0-9_\-\.\\/:]{3,}\.(?:dll|exe|vbs|ps1|bat|js|wsf|lnk|dat|bin|cab|zip|tmp|scr|pdf|png|rar|7z|gz)', re.IGNORECASE)

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

def extract_ascii_strings(data: bytes, min_len: int=4):
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

def extract_utf16le_strings(data: bytes, min_len: int=4):
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
        else:
            if len(curr) >= min_len:
                res.append(''.join(curr))
            curr = []
            i += 2
    if len(curr) >= min_len:
        res.append(''.join(curr))
    return res

# --- VBA marker detection tolerant to UTF-16/NULL ---
def _nul_tolerant_bytes(word: str) -> bytes:
    return b''.join([c.encode('ascii') + b'\x00?' for c in word])
VB_MARKER_WORDS = [ 'VBAPROJECT', 'VBA', 'PROJECT', 'CMG=', 'DPB=', 'GC=', 'dir' ]
VB_MARKERS_REGEX = [ re.compile(_nul_tolerant_bytes(w), re.IGNORECASE) for w in VB_MARKER_WORDS ]

def find_vba_markers(data: bytes):
    hits = []
    for rx, word in zip(VB_MARKERS_REGEX, VB_MARKER_WORDS):
        for m in rx.finditer(data):
            hits.append({'marker': word, 'offset': m.start()})
    return hits

# --- MS-OVBA pure-Python decompressor ---
def _copy_token_get_length_and_offset(token, bit_count):
    offset_mask = (1 << bit_count) - 1
    offset = (token & offset_mask) + 1
    length = (token >> bit_count) + 3
    return length, offset

def _decompress_chunk(payload: bytes, outbuf: bytearray) -> None:
    i = 0
    offset_bits = 12
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
    i = 1
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

def find_magic_signatures(data: bytes):
    found = []
    for name, sig in MAGICS:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            found.append({'sig': name, 'offset': idx})
            start = idx + 1
    return sorted(found, key=lambda x: x['offset'])

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

def score_suspicion(keyword_hits, iocs, sigs, has_embedded_blobs, has_vba_markers):
    score = 0
    score += min(40, 2 * len(set([k.lower() for k in (keyword_hits or [])])))
    score += 10 * (1 if iocs.get('urls') else 0)
    score += 5 * (1 if iocs.get('ips') else 0)
    score += 5 * (1 if iocs.get('files') else 0)
    sig_names = [s.get('sig') for s in (sigs or [])]
    if 'MZ' in sig_names: score += 15
    if 'OLE_CF' in sig_names: score += 10
    if has_embedded_blobs: score += 15
    if has_vba_markers: score += 15
    return max(0, min(100, score))

# --- HEX (ASCII) run detection with fragmentation fix ---
def carve_ascii_hex_blobs(text: str, min_hex_chars: int = 100, merge_gap_chars: int = 64):
    # Find long hex sequences with optional 0x and separators.
    pat = re.compile(r'(?is)(?:\b(?:0x)?[0-9a-f]{2}(?:[\s,:;\-\r\n]+(?:0x)?[0-9a-f]{2}){'+str(max(1,(min_hex_chars//2)-1)) + r',}\b|[0-9a-f]{'+str(min_hex_chars)+r',})')
    matches = [m.span() for m in pat.finditer(text)]
    if not matches: 
        return []
    # Merge nearby spans to fix fragmentation
    merged = []
    for s,e in matches:
        if not merged:
            merged.append([s,e])
        else:
            ps,pe = merged[-1]
            if s <= pe + merge_gap_chars:
                merged[-1][1] = max(pe, e)
            else:
                merged.append([s,e])

    blobs = []
    for s,e in merged:
        segment = text[s:e]
        cleaned = re.sub(r'(?i)0x', '', segment)
        cleaned = re.sub(r'[^0-9A-Fa-f]', '', cleaned)
        if len(cleaned) % 2 == 1:
            cleaned = cleaned[:-1]
        if len(cleaned) < 2* (min_hex_chars//2):
            continue
        try:
            blobs.append({'source_span': (s,e), 'bytes': bytes.fromhex(cleaned)})
        except Exception:
            continue
    return blobs

# --- HEX (UTF-16 / null-interleaved) run detection with fragmentation fix ---
def carve_utf16_hex_blobs(data: bytes, utf16_min_pairs: int = 60, merge_gap_bytes: int = 64):
    hexset = set(b'0123456789abcdefABCDEF')
    runs = []
    i = 0; n = len(data)
    while i+1 < n:
        j = i; pairs = []
        while j+1 < n and data[j] in hexset and (data[j+1] == 0x00 or data[j+1] in b' \t\r\n,;:'):
            pairs.append(chr(data[j]))
            j += 2
        if len(pairs) >= utf16_min_pairs:
            runs.append([i, j, ''.join(pairs)])
            i = j
        else:
            i += 1
    if not runs:
        return []

    # Merge nearby UTF-16 hex runs separated by small gaps
    merged = []
    for s,e,txt in runs:
        if not merged:
            merged.append([s,e,txt])
        else:
            ps,pe,pt = merged[-1]
            if s <= pe + merge_gap_bytes:
                merged[-1][1] = max(pe, e)
                merged[-1][2] = pt + txt
            else:
                merged.append([s,e,txt])

    blobs = []
    for s,e,txt in merged:
        cleaned = re.sub(r'[^0-9A-Fa-f]', '', txt)
        if len(cleaned) % 2 == 1:
            cleaned = cleaned[:-1]
        if len(cleaned) < 2* (utf16_min_pairs//2):
            continue
        try:
            blobs.append({'source_span': (s,e), 'bytes': bytes.fromhex(cleaned)})
        except Exception:
            continue
    return blobs

# --- General embedded blob carver (magic + high-entropy windows) ---
def carve_by_magic_and_entropy(data: bytes, carve_min_size: int = 256, entropy_window: int = 1024, entropy_threshold: float = 7.2):
    hits = []
    # Signature based: slice between consecutive headers
    positions = []
    for name, sig in MAGICS:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            positions.append((idx, name))
            start = idx + 1
    positions.sort()
    for i, (pos, name) in enumerate(positions):
        end = positions[i+1][0] if i+1 < len(positions) else len(data)
        chunk = data[pos:end]
        if len(chunk) >= carve_min_size:
            hits.append({'offset': pos, 'length': len(chunk), 'sig': name, 'bytes': chunk})

    # Entropy-based
    covered = [(h['offset'], h['offset']+h['length']) for h in hits]
    def is_covered(a,b):
        for x,y in covered:
            if a >= x and b <= y:
                return True
        return False
    i = 0; n = len(data)
    while i + entropy_window <= n:
        win = data[i:i+entropy_window]
        ent = shannon_entropy(win)
        if ent >= entropy_threshold:
            j = i + entropy_window
            while j + entropy_window <= n and shannon_entropy(data[j:j+entropy_window]) >= (entropy_threshold - 0.2):
                j += entropy_window
            a, b = i, min(n, j)
            if not is_covered(a,b) and (b-a) >= carve_min_size:
                hits.append({'offset': a, 'length': b-a, 'sig': 'GENERIC_HIGH_ENTROPY', 'bytes': data[a:b]})
                covered.append((a,b))
            i = j
        else:
            i += entropy_window
    hits.sort(key=lambda h: h['offset'])
    return hits

# --- De-duplication by SHA-256 ---
def dedupe_blobs(blob_dicts: list, already_seen: set|None=None):
    seen = set(already_seen or [])
    out = []
    for b in blob_dicts:
        h = hashlib.sha256(b['bytes']).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        b['sha256'] = h
        out.append(b)
    return out, seen

class AccduInspector:
    def __init__(self, source_path: str, out_dir: str|None=None, export_strings: bool=True, try_ole: bool=True, try_msovba: bool=True, modules_only: bool=False, yara_path: str|None=None, dump_markers: bool=False, dump_markers_json: str|None=None, extract_from_markers: bool=False, min_hex_chars: int=100, utf16_min_pairs: int=60, entropy_threshold: float=7.2, carve_window: int=1024, carve_min_size: int=256, merge_gap_chars: int=64, merge_gap_bytes: int=64, no_dedupe: bool=False):
        self.source = os.path.abspath(source_path)
        self.export_strings = export_strings
        self.try_ole = try_ole and HAS_OLEFILE
        self.try_msovba = try_msovba
        self.modules_only = modules_only
        self.yara_path = yara_path
        self.yara_rules = self.load_yara_rules(yara_path) if yara_path else None
        self.dump_markers = dump_markers
        self.dump_markers_json_path = dump_markers_json
        self.extract_from_markers = extract_from_markers

        self.min_hex_chars = min_hex_chars
        self.utf16_min_pairs = utf16_min_pairs
        self.entropy_threshold = entropy_threshold
        self.carve_window = carve_window
        self.carve_min_size = carve_min_size
        self.merge_gap_chars = merge_gap_chars
        self.merge_gap_bytes = merge_gap_bytes
        self.no_dedupe = no_dedupe

        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        self.out_dir = os.path.abspath(out_dir) if out_dir else os.path.abspath(f'./accdu_report_{ts}')
        os.makedirs(self.out_dir, exist_ok=True)
        self.tmpdir = tempfile.mkdtemp(prefix='accdu_extract_')
        self.files_to_scan = []
        self.summary = []
        self.modules_stdout = []
        self.markers_map = {}

    def load_yara_rules(self, path: str):
        if not HAS_YARA or not path: return None
        path = os.path.abspath(path)
        if os.path.isdir(path):
            files = [p for p in glob.glob(os.path.join(path, '**'), recursive=True) if os.path.isfile(p) and os.path.splitext(p)[1].lower() in ('.yar','.yara')]
            if not files: return None
            import yara
            sources = {f'ns_{i}': open(f,'rb').read().decode('utf-8','ignore') for i,f in enumerate(files)}
            return yara.compile(sources=sources)
        else:
            import yara
            return yara.compile(filepath=path)

    def run_yara_on_bytes(self, data: bytes, namespace: str):
        results = []
        if not (HAS_YARA and self.yara_rules and data):
            return results
        try:
            matches = self.yara_rules.match(data=data, timeout=10)
            for m in matches:
                strings = []
                for (off, sid, val) in m.strings[:50]:
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

            markers = rec.get('vba_markers') or []
            if self.dump_markers and markers:
                print(f"[MARKERS] {rel}")
                for m in markers:
                    print(f"  {m['marker']} @ 0x{m['offset']:X}")
            if markers:
                self.markers_map[rel] = markers

        if self.dump_markers_json_path:
            try:
                outp = self.dump_markers_json_path
                if os.path.isdir(self.out_dir) and not os.path.isabs(outp):
                    outp = os.path.join(self.out_dir, outp)
                with open(outp, 'w', encoding='utf-8') as jf:
                    json.dump(self.markers_map, jf, indent=2)
                print(f"Wrote markers JSON to {outp}")
            except Exception as e:
                print(f"ERROR writing markers JSON: {e}")

        if self.modules_only:
            print("\n====== Recovered VBA Modules ======\n")
            for item in self.modules_stdout:
                print(f"--- {item['name']} ---")
                print(item['content'])
                print("\n")
            return

    def analyze_file(self, filepath: str, relpath: str) -> dict:
        with open(filepath, 'rb') as f:
            data = f.read()
        entropy = round(shannon_entropy(data),3)

        vba_markers = find_vba_markers(data)
        has_vba_markers = bool(vba_markers)

        ascii_strings = extract_ascii_strings(data)
        utf16_strings = extract_utf16le_strings(data)
        all_text = '\n'.join(ascii_strings + utf16_strings)
        sigs = find_magic_signatures(data)
        iocs = find_iocs_and_files(all_text)
        keyword_hits = [kw for kw in KEYWORDS if re.search(re.escape(kw), all_text, flags=re.IGNORECASE)]

        # Embedded carving (signatures + entropy)
        carved = carve_by_magic_and_entropy(data, carve_min_size=self.carve_min_size, entropy_window=self.carve_window, entropy_threshold=self.entropy_threshold)
        carved_sha = set()
        carved, carved_sha = dedupe_blobs(carved, carved_sha) if not self.no_dedupe else (carved, set())

        # HEX ASCII carving (merged)
        ascii_hex_blobs = carve_ascii_hex_blobs(all_text, min_hex_chars=self.min_hex_chars, merge_gap_chars=self.merge_gap_chars)
        ascii_hex_blobs, carved_sha = dedupe_blobs(ascii_hex_blobs, carved_sha) if not self.no_dedupe else (ascii_hex_blobs, carved_sha)

        # HEX UTF-16 carving (merged)
        utf16_hex_blobs = carve_utf16_hex_blobs(data, utf16_min_pairs=self.utf16_min_pairs, merge_gap_bytes=self.merge_gap_bytes)
        utf16_hex_blobs, carved_sha = dedupe_blobs(utf16_hex_blobs, carved_sha) if not self.no_dedupe else (utf16_hex_blobs, carved_sha)

        # Save carved outputs
        embedded_paths = []
        carve_dir = os.path.join(self.out_dir, 'blobs', 'carved', relpath.replace(os.sep,'_'))
        os.makedirs(carve_dir, exist_ok=True)

        def save_blob(prefix, idx, blob):
            sig = blob.get('sig', 'CARVED')
            off = blob.get('offset')
            span = blob.get('source_span')
            name_parts = [prefix, f'{idx:03d}']
            if sig: name_parts.append(str(sig))
            if off is not None: name_parts.append(f'at0x{off:X}')
            if span is not None: name_parts.append(f's{span[0]}-{span[1]}')
            name = '_'.join(name_parts) + '.bin'
            path = os.path.join(carve_dir, name)
            with open(path, 'wb') as bf:
                bf.write(blob['bytes'])
            return path

        for i,b in enumerate(carved):
            embedded_paths.append(save_blob('magic', i, b))
        base_idx = len(embedded_paths)
        for j,b in enumerate(ascii_hex_blobs):
            embedded_paths.append(save_blob('hexascii', base_idx + j, b))
        base_idx = len(embedded_paths)
        for k,b in enumerate(utf16_hex_blobs):
            embedded_paths.append(save_blob('hexutf16', base_idx + k, b))

        # Suspicion score
        suspicion = score_suspicion(keyword_hits, iocs, sigs, bool(embedded_paths), has_vba_markers)

        exported = {'strings': None, 'vba':[], 'vba_decompressed':[], 'vba_from_markers':[], 'embedded_blobs': embedded_paths}
        yara_matches = []

        if self.yara_rules:
            yara_matches += self.run_yara_on_bytes(data, namespace=f'raw:{relpath}')

        # OLE extraction
        for s in sigs:
            if s.get('sig') == 'OLE_CF' and (self.try_ole or has_vba_markers):
                try:
                    vba_paths = self.extract_vba_from_ole(data, relpath)
                    exported['vba'].extend(vba_paths or [])
                except Exception as e:
                    exported['vba'].append({'error': str(e)})

        # MS-OVBA on saved VBA .bin
        if self.try_msovba and (has_vba_markers or any(s.get('sig')=='OLE_CF' for s in sigs)):
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
                            if self.modules_only:
                                self.modules_stdout.append({'name': name + ' (msovba)', 'content': decomp.decode('latin-1', errors='replace')})
                            if self.yara_rules:
                                yara_matches += self.run_yara_on_bytes(decomp, namespace=f'vba:{name}.msovba.txt')
                    except Exception as e:
                        exported['vba_decompressed'].append({'error':str(e),'bin':bin_path})

        # Extract-from-markers fallback
        if self.extract_from_markers and has_vba_markers:
            from_root = os.path.join(self.out_dir, 'vba')
            wrote = self.try_decompress_around_markers(relpath, data, vba_markers, from_root, window=4096, max_candidates=100)
            exported['vba_from_markers'].extend(wrote or [])

        # YARA on carved artifacts & VBA outputs
        if self.yara_rules:
            for p in (embedded_paths + exported.get('vba_decompressed', []) + exported.get('vba_from_markers', [])):
                try:
                    with open(p, 'rb') as f:
                        content = f.read()
                    yara_matches += self.run_yara_on_bytes(content, namespace=f'artifact:{os.path.basename(p)}')
                except Exception:
                    pass

        # Strings export
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
            'vba_markers': vba_markers,
            'keyword_hits': keyword_hits,
            'iocs': iocs,
            'suspicion': suspicion,
            'yara_matches': yara_matches,
            'exported': exported
        }

    def try_decompress_around_markers(self, relpath: str, data: bytes, markers: list, out_root: str, window: int = 4096, max_candidates: int = 100):
        written = []
        if not markers:
            return written
        rel_sanitized = relpath.replace(os.sep, '_').replace('/', '_').replace('\\', '_')
        out_dir = os.path.join(out_root, 'from_markers', rel_sanitized)
        os.makedirs(out_dir, exist_ok=True)
        for mi, m in enumerate(markers):
            off = int(m.get('offset', 0))
            start = max(0, off - window); end = min(len(data), off + window)
            candidates = []
            for i in range(start, end):
                if data[i] == 0x01:
                    candidates.append(i)
                    if len(candidates) >= max_candidates:
                        break
            for ci, pos in enumerate(candidates):
                slice_end = min(len(data), pos + 200000)
                blob = data[pos:slice_end]
                try:
                    decomp = decompress_ms_ovba(blob)
                except Exception:
                    decomp = None
                if not decomp:
                    continue
                txt = decomp.decode('latin-1', errors='replace')
                if any(k in txt.lower() for k in ('sub ', 'function ', 'attribute', 'vb_name', 'createobject(')):
                    outp = os.path.join(out_dir, f'marker{mi}_cand{ci}_at0x{pos:X}.msovba.txt')
                    with open(outp, 'w', encoding='utf-8', errors='replace') as f:
                        f.write(txt)
                    written.append(outp)
        return written

    def extract_vba_from_ole(self, data: bytes, relpath: str) -> list:
        import olefile
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
                txtpath = outpath + '.txt'
                try:
                    txt = raw.decode('utf-8', errors='strict')
                except Exception:
                    txt = raw.decode('latin-1', errors='replace')
                with open(txtpath, 'w', encoding='utf-8', errors='replace') as tf:
                    tf.write(txt)
                paths.append(txtpath)
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
            keys = ['relpath','size','entropy','suspicion','keyword_hits','iocs_urls','iocs_ips','iocs_files','signatures','vba_markers','yara_count','exported_strings','exported_vba','exported_vba_decompressed','exported_vba_from_markers','exported_embedded_blobs']
            with open(outp, 'w', newline='', encoding='utf-8') as cf:
                w = csv.writer(cf)
                w.writerow(keys)
                for r in self.summary:
                    sigs = ';'.join([f"{s['sig']}@{s['offset']}" for s in (r.get('signatures') or [])])
                    markers = ';'.join([f"{m['marker']}@{m['offset']}" for m in (r.get('vba_markers') or [])])
                    exported = r.get('exported',{})
                    exported_strings = exported.get('strings') or ''
                    exported_vba = ';'.join([str(x) for x in (exported.get('vba') or [])])
                    exported_vba_de = ';'.join([str(x) for x in (exported.get('vba_decompressed') or [])])
                    exported_vba_from_markers = ';'.join([str(x) for x in (exported.get('vba_from_markers') or [])])
                    exported_embedded = ';'.join([str(x) for x in (exported.get('embedded_blobs') or [])])
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
                        markers,
                        yara_count,
                        exported_strings,
                        exported_vba,
                        exported_vba_de,
                        exported_vba_from_markers,
                        exported_embedded
                    ])
            print('Wrote CSV report to', outp)

def build_cli():
    p = argparse.ArgumentParser(description='Analyze .accdu/.accdb/.zip; VBA markers, MS-OVBA, YARA, hex (ASCII/UTF-16) carving w/ merging, magic+entropy carving, scoring.')
    p.add_argument('input', help='Path to .accdu/.zip file or extracted folder')
    p.add_argument('--out', '-o', help='Output directory', default=None)
    p.add_argument('--no-strings', action='store_true', help='Do not export raw string dumps')
    p.add_argument('--no-ole', action='store_true', help='Do not attempt OLE/VBA extraction (even if olefile is installed)')
    p.add_argument('--no-msovba', action='store_true', help='Do not attempt pure-Python MS-OVBA decompression')
    p.add_argument('--format', '-f', choices=['json','csv'], default='json', help='Output report format')
    p.add_argument('--modules-only', action='store_true', help='Print recovered VBA (olevba/msovba) to stdout and exit')
    p.add_argument('--yara', help='Path to a YARA rule file or directory of .yar/.yara rules', default=None)
    p.add_argument('--dump-markers', action='store_true', help='Print a marker table with offsets per file during the run')
    p.add_argument('--dump-markers-json', help='Write a compact JSON file with {relpath: [marker,offset]}', default=None)
    p.add_argument('--extract-from-markers', action='store_true', help='Automatically try MS-OVBA decompression around each marker offset and save recovered VBA')
    # Tuning flags
    p.add_argument('--min-hex-chars', type=int, default=100, help='ASCII hex: minimum continuous hex chars to consider (default 100)')
    p.add_argument('--utf16-min-pairs', type=int, default=60, help='UTF-16 hex: minimum hex *pairs* (default 60)')
    p.add_argument('--entropy-threshold', type=float, default=7.2, help='Entropy threshold for generic high-entropy carving (default 7.2)')
    p.add_argument('--carve-window', type=int, default=1024, help='Window size for entropy scanning (default 1024)')
    p.add_argument('--carve-min-size', type=int, default=256, help='Minimum bytes to keep a carved region (default 256)')
    p.add_argument('--merge-gap-chars', type=int, default=64, help='Max gap (chars) to merge fragmented ASCII-hex runs (default 64)')
    p.add_argument('--merge-gap-bytes', type=int, default=64, help='Max gap (bytes) to merge fragmented UTF-16-hex runs (default 64)')
    p.add_argument('--no-dedupe', action='store_true', help='Disable deduplication of carved blobs (by SHA-256)')
    return p

def main():
    parser = build_cli()
    args = parser.parse_args()
    inspector = AccduInspector(
        args.input,
        out_dir=args.out,
        export_strings=not args.no_strings,
        try_ole=not args.no_ole,
        try_msovba=not args.no_msovba,
        modules_only=args.modules_only,
        yara_path=args.yara,
        dump_markers=args.dump_markers,
        dump_markers_json=args.dump_markers_json,
        extract_from_markers=args.extract_from_markers,
        min_hex_chars=args.min_hex_chars,
        utf16_min_pairs=args.utf16_min_pairs,
        entropy_threshold=args.entropy_threshold,
        carve_window=args.carve_window,
        carve_min_size=args.carve_min_size,
        merge_gap_chars=args.merge_gap_chars,
        merge_gap_bytes=args.merge_gap_bytes,
        no_dedupe=args.no_dedupe
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
            print('\\nTip: install olefile for richer OLE parsing:\\n  pip install olefile')
        print('Optional: install oletools to enable `olevba` output:\\n  pip install oletools')
        print('Optional: install yara-python for YARA scanning:\\n  pip install yara-python')
    finally:
        inspector.cleanup()

if __name__ == '__main__':
    main()