#!/usr/bin/env python3
"""Zero-dependency test suite. Run: python3 tests/test_itf.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import itf  # noqa: E402

FAILED = []


def check(name, condition, detail=""):
    if condition:
        print("  ok   %s" % name)
    else:
        print("  FAIL %s %s" % (name, detail))
        FAILED.append(name)


print("detection")
check("zero width space is high",
      any(f["risk"] == "high" for f in itf.scan_text("ciao​mondo")))
check("bidi override is critical",
      any(f["risk"] == "critical" for f in itf.scan_text("if(a)‮{}‬")))
check("tag characters are critical",
      any(f["risk"] == "critical" for f in itf.scan_text("hi" + chr(0xE0041))))
check("private use area is critical",
      any(f["risk"] == "critical" for f in itf.scan_text("xy")))
check("cyrillic homoglyph is medium",
      any(f["risk"] == "medium" for f in itf.scan_text("pаypal")))
check("nbsp is medium",
      any(f["risk"] == "medium" for f in itf.scan_text("a b")))
check("plain ascii is clean", itf.scan_text("perfectly normal text") == [])
check("em dash is silent by default", itf.scan_text("a — b") == [])
check("em dash reported with cosmetic flag",
      len(itf.scan_text("a — b", include_cosmetic=True)) == 1)

print("false positives that would corrupt real text")
FAMILY = "\U0001f468‍\U0001f469‍\U0001f467"
check("emoji ZWJ not flagged", itf.scan_text("famiglia " + FAMILY) == [])
check("emoji ZWJ survives clean", "‍" in itf.clean_text(FAMILY)[0])
check("arabic ZWNJ not flagged", itf.scan_text("مرح‌با") == [])
check("arabic ZWNJ survives clean",
      "‌" in itf.clean_text("مرح‌با")[0])
check("emoji presentation selector not flagged", itf.scan_text("✔️ ok") == [])
check("newline and tab not flagged", itf.scan_text("a\nb\tc") == [])

print("cleaning levels")
dirty = "test​ con nbsp e pаypal — fine"
safe, _ = itf.clean_text(dirty, "safe")
check("safe removes zero width", "​" not in safe)
check("safe keeps nbsp", " " in safe)
aggressive, _ = itf.clean_text(dirty, "aggressive")
check("aggressive normalises nbsp", " " not in aggressive and " " in aggressive)
check("aggressive keeps homoglyph", "а" in aggressive)
paranoid, _ = itf.clean_text(dirty, "paranoid")
check("paranoid folds homoglyph", "а" not in paranoid and "paypal" in paranoid)
check("paranoid folds em dash", "—" not in paranoid)
check("clean is idempotent", itf.clean_text(safe, "safe")[0] == safe)

print("payload extraction")
tagged = "hello" + "".join(chr(0xE0000 + ord(c)) for c in "SECRET")
check("tag payload decoded",
      itf.extract_payloads(tagged).get("tag_characters") == "SECRET")
vs = "a" + "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16)
                   for b in "hi".encode("utf-8"))
check("variation selector payload decoded",
      itf.extract_payloads(vs).get("variation_selectors") == "hi")
check("clean text has no payload", itf.extract_payloads("nothing here") == {})

print("watermarking")
doc = " ".join("parola%d" % i for i in range(60))
marked = itf.watermark_text(doc, "AB")
check("watermark is invisible", marked.replace("​", "").replace("‌", "") == doc)
check("watermark reads back", itf.identify_watermark(marked) == "AB")
other = itf.watermark_text(doc, "CD")
check("different ids give different copies", marked != other)
check("second id reads back", itf.identify_watermark(other) == "CD")
check("clean removes the watermark",
      itf.identify_watermark(itf.clean_text(marked, "safe")[0]) is None)

print("")
if FAILED:
    print("%d test(s) failed: %s" % (len(FAILED), ", ".join(FAILED)))
    sys.exit(1)
print("all tests passed")
