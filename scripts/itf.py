#!/usr/bin/env python3
"""itf - invisible text forensics.

Scan, clean, watermark and de-obfuscate text at the code point level.
Pure standard library, Python 3.8+. No network, no telemetry, no dependencies.

  itf.py scan      FILE...     find hidden and risky characters
  itf.py clean     FILE...     remove them, safely
  itf.py extract   FILE        decode payloads hidden in invisible characters
  itf.py watermark FILE        embed an invisible copy identifier
  itf.py identify  FILE        read back an embedded copy identifier
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import unicodedata

# --------------------------------------------------------------------------
# character catalogue
# --------------------------------------------------------------------------
# risk levels: critical > high > medium > cosmetic

ZERO_WIDTH = {
    0x200B: "Zero Width Space (ZWSP)",
    0x200C: "Zero Width Non-Joiner (ZWNJ)",
    0x200D: "Zero Width Joiner (ZWJ)",
    0x2060: "Word Joiner",
    0x2061: "Function Application",
    0x2062: "Invisible Times",
    0x2063: "Invisible Separator",
    0x2064: "Invisible Plus",
    0xFEFF: "Zero Width No-Break Space (BOM)",
    0x00AD: "Soft Hyphen",
    0x034F: "Combining Grapheme Joiner",
    0x061C: "Arabic Letter Mark",
    0x115F: "Hangul Choseong Filler",
    0x1160: "Hangul Jungseong Filler",
    0x17B4: "Khmer Vowel Inherent Aq",
    0x17B5: "Khmer Vowel Inherent Aa",
    0x180E: "Mongolian Vowel Separator",
    0x3164: "Hangul Filler",
    0xFFA0: "Halfwidth Hangul Filler",
}

BIDI_MARKS = {
    0x200E: "Left-to-Right Mark (LRM)",
    0x200F: "Right-to-Left Mark (RLM)",
}

BIDI_OVERRIDES = {
    0x202A: "Left-to-Right Embedding (LRE)",
    0x202B: "Right-to-Left Embedding (RLE)",
    0x202C: "Pop Directional Formatting (PDF)",
    0x202D: "Left-to-Right Override (LRO)",
    0x202E: "Right-to-Left Override (RLO)",
    0x2066: "Left-to-Right Isolate (LRI)",
    0x2067: "Right-to-Left Isolate (RLI)",
    0x2068: "First Strong Isolate (FSI)",
    0x2069: "Pop Directional Isolate (PDI)",
}

EXOTIC_SPACE = {
    0x00A0: "No-Break Space (NBSP)",
    0x1680: "Ogham Space Mark",
    0x2000: "En Quad", 0x2001: "Em Quad", 0x2002: "En Space", 0x2003: "Em Space",
    0x2004: "Three-Per-Em Space", 0x2005: "Four-Per-Em Space",
    0x2006: "Six-Per-Em Space", 0x2007: "Figure Space",
    0x2008: "Punctuation Space", 0x2009: "Thin Space", 0x200A: "Hair Space",
    0x202F: "Narrow No-Break Space", 0x205F: "Medium Mathematical Space",
    0x3000: "Ideographic Space",
    0x2028: "Line Separator", 0x2029: "Paragraph Separator",
}

# AI typography tells: visible, legitimate, but a fingerprint in plain prose
COSMETIC = {
    0x2013: ("En Dash", "-"),
    0x2014: ("Em Dash", "-"),
    0x2018: ("Left Single Quote", "'"),
    0x2019: ("Right Single Quote", "'"),
    0x201C: ("Left Double Quote", '"'),
    0x201D: ("Right Double Quote", '"'),
    0x2026: ("Horizontal Ellipsis", "..."),
    0x2212: ("Minus Sign", "-"),
    0x00A0: ("No-Break Space", " "),
}

# Cyrillic / Greek / fullwidth lookalikes for ASCII letters
HOMOGLYPHS = {
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c",
    0x0443: "y", 0x0445: "x", 0x0455: "s", 0x0456: "i", 0x0458: "j",
    0x04BB: "h", 0x0501: "d", 0x051B: "q", 0x051D: "w",
    0x0410: "A", 0x0412: "B", 0x0415: "E", 0x041A: "K", 0x041C: "M",
    0x041D: "H", 0x041E: "O", 0x0420: "P", 0x0421: "C", 0x0422: "T",
    0x0425: "X", 0x0405: "S", 0x0406: "I", 0x0408: "J",
    0x03BF: "o", 0x03B1: "a", 0x03B5: "e", 0x03B9: "i", 0x03BD: "v",
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H",
    0x0399: "I", 0x039A: "K", 0x039C: "M", 0x039D: "N", 0x039F: "O",
    0x03A1: "P", 0x03A4: "T", 0x03A5: "Y", 0x03A7: "X",
}

def _name(cp):
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        return "U+%04X" % cp

def classify(cp, prev_cp, next_cp):
    """Return (risk, label, reason) or None when the character is unremarkable."""
    if 0xE0000 <= cp <= 0xE007F:
        return ("critical", "Tag Character",
                "carries hidden ASCII; the standard prompt-injection smuggling channel")
    if cp in BIDI_OVERRIDES:
        return ("critical", BIDI_OVERRIDES[cp],
                "reorders rendering; Trojan Source (CVE-2021-42574) in source code")
    if 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0xFFFFD or 0x100000 <= cp <= 0x10FFFD:
        return ("critical", "Private Use Area", "no defined meaning; used as a covert channel")
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        if cp == 0xFE0F and prev_cp is not None and is_pictographic(prev_cp):
            return None  # emoji presentation selector, legitimate
        return ("high", "Variation Selector",
                "encodes arbitrary bytes when chained; the emoji smuggling channel")
    if cp in ZERO_WIDTH:
        if cp in (0x200C, 0x200D) and joiner_is_legitimate(cp, prev_cp, next_cp):
            return None
        return ("high", ZERO_WIDTH[cp], "invisible; carries watermarks and hidden payloads")
    if cp in BIDI_MARKS:
        return ("medium", BIDI_MARKS[cp], "invisible directional hint")
    if cp in EXOTIC_SPACE:
        return ("medium", EXOTIC_SPACE[cp], "looks like a space, is not U+0020")
    if cp in HOMOGLYPHS:
        return ("medium", "Homoglyph of %r" % HOMOGLYPHS[cp],
                "non-Latin letter that renders like ASCII")
    if unicodedata.category(chr(cp)) == "Cc" and cp not in (0x09, 0x0A, 0x0D):
        return ("high", "Control Character %s" % _name(cp), "unprintable control code")
    return None

def is_pictographic(cp):
    return (0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF
            or 0x2B00 <= cp <= 0x2BFF or 0x1F1E6 <= cp <= 0x1F1FF
            or cp in (0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0xFE0F)
            or 0x1F3FB <= cp <= 0x1F3FF)

def in_complex_script(cp):
    """Scripts where ZWJ/ZWNJ carry real orthographic meaning."""
    if cp is None:
        return False
    return (0x0600 <= cp <= 0x06FF or 0x0750 <= cp <= 0x077F   # Arabic
            or 0x0700 <= cp <= 0x074F                          # Syriac
            or 0x0780 <= cp <= 0x07BF                          # Thaana
            or 0x0900 <= cp <= 0x0DFF                          # Indic
            or 0x0E00 <= cp <= 0x0E7F                          # Thai / Lao
            or 0x1000 <= cp <= 0x109F                          # Myanmar
            or 0x1780 <= cp <= 0x17FF                          # Khmer
            or 0xFB50 <= cp <= 0xFDFF or 0xFE70 <= cp <= 0xFEFF)

def joiner_is_legitimate(cp, prev_cp, next_cp):
    """ZWJ inside an emoji sequence, or ZWJ/ZWNJ inside a complex script, must stay.

    Removing these silently corrupts family emoji and Arabic, Hindi, Persian text.
    This is the single most common bug in naive invisible-character strippers.
    """
    if cp == 0x200D and is_pictographic(prev_cp or 0) and is_pictographic(next_cp or 0):
        return True
    return in_complex_script(prev_cp) or in_complex_script(next_cp)

RISK_ORDER = {"cosmetic": 0, "medium": 1, "high": 2, "critical": 3}

# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------

def scan_text(text, include_cosmetic=False):
    findings = []
    line = 1
    col = 0
    for i, ch in enumerate(text):
        cp = ord(ch)
        if ch == "\n":
            line += 1
            col = 0
            continue
        col += 1
        prev_cp = ord(text[i - 1]) if i > 0 else None
        next_cp = ord(text[i + 1]) if i + 1 < len(text) else None
        hit = classify(cp, prev_cp, next_cp)
        if hit is None and include_cosmetic and cp in COSMETIC:
            hit = ("cosmetic", COSMETIC[cp][0], "typography tell, not a hidden character")
        if hit:
            risk, label, reason = hit
            findings.append({
                "offset": i, "line": line, "column": col,
                "codepoint": "U+%04X" % cp, "label": label,
                "risk": risk, "reason": reason,
                "context": context_of(text, i),
            })
    return findings

def context_of(text, i, span=24):
    left = text[max(0, i - span):i].replace("\n", "\\n")
    right = text[i + 1:i + 1 + span].replace("\n", "\\n")
    return "%s[%s]%s" % (left, "U+%04X" % ord(text[i]), right)

# --------------------------------------------------------------------------
# clean
# --------------------------------------------------------------------------

def clean_text(text, level="safe"):
    """safe       remove hidden characters that have no business in prose or code
       aggressive also normalise exotic spaces and drop soft hyphens
       paranoid   also fold homoglyphs and smart typography to ASCII
    """
    out = []
    removed = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        prev_cp = ord(text[i - 1]) if i > 0 else None
        next_cp = ord(text[i + 1]) if i + 1 < len(text) else None
        hit = classify(cp, prev_cp, next_cp)
        if hit:
            risk = hit[0]
            if risk in ("critical", "high"):
                removed.append((i, "U+%04X" % cp, hit[1]))
                continue
            if level in ("aggressive", "paranoid") and risk == "medium":
                if cp in EXOTIC_SPACE:
                    out.append("\n" if cp in (0x2028, 0x2029) else " ")
                    removed.append((i, "U+%04X" % cp, hit[1] + " -> space"))
                    continue
                if cp in BIDI_MARKS:
                    removed.append((i, "U+%04X" % cp, hit[1]))
                    continue
            if level == "paranoid" and cp in HOMOGLYPHS:
                out.append(HOMOGLYPHS[cp])
                removed.append((i, "U+%04X" % cp, hit[1] + " -> ASCII"))
                continue
        if level == "paranoid" and cp in COSMETIC:
            out.append(COSMETIC[cp][1])
            removed.append((i, "U+%04X" % cp, COSMETIC[cp][0] + " -> ASCII"))
            continue
        out.append(ch)
    return "".join(out), removed

# --------------------------------------------------------------------------
# payload extraction
# --------------------------------------------------------------------------

def extract_payloads(text):
    found = {}
    tag = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    if tag:
        found["tag_characters"] = tag
    vs = []
    for c in text:
        cp = ord(c)
        if 0xFE00 <= cp <= 0xFE0F:
            vs.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            vs.append(cp - 0xE0100 + 16)
    if len(vs) >= 2:
        try:
            found["variation_selectors"] = bytes(vs).decode("utf-8", "replace")
        except Exception:
            found["variation_selectors"] = repr(vs)
    bits = "".join("0" if ord(c) == 0x200B else "1"
                   for c in text if ord(c) in (0x200B, 0x200C))
    if len(bits) >= 8:
        chars = [chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8)]
        candidate = "".join(chars)
        if all(32 <= ord(c) < 127 or c in "\n\t" for c in candidate):
            found["zero_width_binary"] = candidate
    return found

# --------------------------------------------------------------------------
# watermark
# --------------------------------------------------------------------------

def watermark_text(text, marker, every=1):
    """Embed marker as zero-width binary: one bit after every `every` words.

    ZWSP encodes 0, ZWNJ encodes 1. The result renders identically to the
    original, so two recipients can receive visually identical copies that
    still say which one leaked.
    """
    bits = "".join(format(b, "08b") for b in marker.encode("utf-8"))
    zero, one = "\u200b", "\u200c"
    words = text.split(" ")
    out = []
    bi = 0
    for n, word in enumerate(words):
        out.append(word)
        if n < len(words) - 1:
            if (n + 1) % every == 0 and bi < len(bits):
                out.append(zero if bits[bi] == "0" else one)
                bi += 1
            out.append(" ")
    if bi < len(bits):
        sys.stderr.write("warning: text too short, embedded %d of %d bits\n"
                         % (bi, len(bits)))
    return "".join(out)


def identify_watermark(text):
    return extract_payloads(text).get("zero_width_binary")

# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

TEXT_EXT = {".txt", ".md", ".markdown", ".py", ".js", ".ts", ".tsx", ".jsx", ".json",
            ".yml", ".yaml", ".html", ".htm", ".css", ".csv", ".sql", ".sh", ".go",
            ".rs", ".java", ".rb", ".php", ".c", ".h", ".cpp", ".toml", ".ini", ".env"}

def iter_files(paths):
    for p in paths:
        if p == "-":
            yield "-"
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in
                           {".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__"}]
                for f in sorted(files):
                    if os.path.splitext(f)[1].lower() in TEXT_EXT:
                        yield os.path.join(root, f)
        else:
            yield p

def read(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()

def cmd_scan(args):
    report = []
    worst = -1
    for path in iter_files(args.paths):
        try:
            findings = scan_text(read(path), args.include_cosmetic)
        except (OSError, UnicodeError) as exc:
            sys.stderr.write("skip %s: %s\n" % (path, exc))
            continue
        if findings:
            report.append({"file": path, "findings": findings})
            worst = max(worst, max(RISK_ORDER[f["risk"]] for f in findings))
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        if not report:
            print("clean: no hidden or risky characters found")
        for entry in report:
            print("\n%s" % entry["file"])
            for f in entry["findings"]:
                print("  %-8s %-9s line %d col %d  %s"
                      % (f["risk"].upper(), f["codepoint"], f["line"], f["column"], f["label"]))
                print("           %s" % f["reason"])
    if args.fail_on and worst >= RISK_ORDER[args.fail_on]:
        return 1
    return 0

def cmd_clean(args):
    for path in iter_files(args.paths):
        text = read(path)
        cleaned, removed = clean_text(text, args.level)
        if args.in_place and path != "-":
            if cleaned != text:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(cleaned)
                sys.stderr.write("%s: %d character(s) removed\n" % (path, len(removed)))
        else:
            sys.stdout.write(cleaned)
        if args.report and removed:
            for off, cp, label in removed:
                sys.stderr.write("  removed %s at %d (%s)\n" % (cp, off, label))
    return 0

def cmd_extract(args):
    payloads = extract_payloads(read(args.path))
    if not payloads:
        print("no hidden payload found")
        return 0
    print(json.dumps(payloads, indent=2, ensure_ascii=False))
    return 0

def cmd_watermark(args):
    sys.stdout.write(watermark_text(read(args.path), args.id, args.every))
    return 0

def cmd_identify(args):
    found = identify_watermark(read(args.path))
    print(found if found else "no watermark found")
    return 0

def main(argv=None):
    p = argparse.ArgumentParser(prog="itf", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="find hidden and risky characters")
    s.add_argument("paths", nargs="+")
    s.add_argument("--json", action="store_true")
    s.add_argument("--include-cosmetic", action="store_true",
                   help="also flag em dashes, curly quotes and other typography tells")
    s.add_argument("--fail-on", choices=list(RISK_ORDER),
                   help="exit 1 when a finding at this level or above is present")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("clean", help="remove hidden characters")
    c.add_argument("paths", nargs="+")
    c.add_argument("--level", choices=["safe", "aggressive", "paranoid"], default="safe")
    c.add_argument("--in-place", action="store_true")
    c.add_argument("--report", action="store_true")
    c.set_defaults(func=cmd_clean)

    e = sub.add_parser("extract", help="decode hidden payloads")
    e.add_argument("path")
    e.set_defaults(func=cmd_extract)

    w = sub.add_parser("watermark", help="embed an invisible copy identifier")
    w.add_argument("path")
    w.add_argument("--id", required=True)
    w.add_argument("--every", type=int, default=1, help="one bit every N words")
    w.set_defaults(func=cmd_watermark)

    i = sub.add_parser("identify", help="read back an embedded identifier")
    i.add_argument("path")
    i.set_defaults(func=cmd_identify)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 2
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
