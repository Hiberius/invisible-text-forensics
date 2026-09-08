# Character catalogue

Every code point this skill knows about, with the risk level it is reported at.
Generated from `scripts/itf.py`; the script is the source of truth.

## Critical: ranges, not a fixed list

| Range | Name | Why critical |
|---|---|---|
| `U+E0000–E007F` | Tag characters | Each one maps to an ASCII character (`cp - 0xE0000`). A run of them is a readable string that renders as nothing. The standard channel for smuggling instructions into a prompt. |
| `U+202A–U+202E` | Bidi embeddings and overrides | Reorder how the following text renders without changing its bytes. Trojan Source, CVE-2021-42574. |
| `U+2066–U+2069` | Bidi isolates | Same class of attack, isolate variant. |
| `U+E000–F8FF`, `U+F0000–FFFFD`, `U+100000–10FFFD` | Private Use Area | No standard meaning. Anything can be encoded here and no renderer will show it consistently. |

## High: zero-width characters

Invisible with no width. Legitimate uses exist for two of them, see the note below.

| Code point | Name | Unicode name |
|---|---|---|
| `U+00AD` | Soft Hyphen | SOFT HYPHEN |
| `U+034F` | Combining Grapheme Joiner | COMBINING GRAPHEME JOINER |
| `U+061C` | Arabic Letter Mark | ARABIC LETTER MARK |
| `U+115F` | Hangul Choseong Filler | HANGUL CHOSEONG FILLER |
| `U+1160` | Hangul Jungseong Filler | HANGUL JUNGSEONG FILLER |
| `U+17B4` | Khmer Vowel Inherent Aq | KHMER VOWEL INHERENT AQ |
| `U+17B5` | Khmer Vowel Inherent Aa | KHMER VOWEL INHERENT AA |
| `U+180E` | Mongolian Vowel Separator | MONGOLIAN VOWEL SEPARATOR |
| `U+200B` | Zero Width Space (ZWSP) | ZERO WIDTH SPACE |
| `U+200C` | Zero Width Non-Joiner (ZWNJ) | ZERO WIDTH NON-JOINER |
| `U+200D` | Zero Width Joiner (ZWJ) | ZERO WIDTH JOINER |
| `U+2060` | Word Joiner | WORD JOINER |
| `U+2061` | Function Application | FUNCTION APPLICATION |
| `U+2062` | Invisible Times | INVISIBLE TIMES |
| `U+2063` | Invisible Separator | INVISIBLE SEPARATOR |
| `U+2064` | Invisible Plus | INVISIBLE PLUS |
| `U+3164` | Hangul Filler | HANGUL FILLER |
| `U+FEFF` | Zero Width No-Break Space (BOM) | ZERO WIDTH NO-BREAK SPACE |
| `U+FFA0` | Halfwidth Hangul Filler | HALFWIDTH HANGUL FILLER |

> `U+200C` (ZWNJ) and `U+200D` (ZWJ) are removed **only** when they are not inside an
> emoji sequence and not adjacent to Arabic, Syriac, Thaana, Indic, Thai, Myanmar or
> Khmer code points. Stripping them blindly corrupts family emoji and changes the
> spelling of Arabic, Persian and Hindi words.

## High: variation selectors

| Range | Encodes |
|---|---|
| `U+FE00–FE0F` | Selector index 0-15. `U+FE0F` after a pictographic character is the legitimate emoji presentation selector and is left alone. |
| `U+E0100–E01EF` | Selector index 16-255. Chained after any base character they carry one byte each, which is enough for arbitrary payloads. |

## Medium: bidi marks

| Code point | Name |
|---|---|
| `U+200E` | Left-to-Right Mark (LRM) |
| `U+200F` | Right-to-Left Mark (RLM) |

## Medium: spaces that are not U+0020

| Code point | Name | Unicode name |
|---|---|---|
| `U+00A0` | No-Break Space (NBSP) | NO-BREAK SPACE |
| `U+1680` | Ogham Space Mark | OGHAM SPACE MARK |
| `U+2000` | En Quad | EN QUAD |
| `U+2001` | Em Quad | EM QUAD |
| `U+2002` | En Space | EN SPACE |
| `U+2003` | Em Space | EM SPACE |
| `U+2004` | Three-Per-Em Space | THREE-PER-EM SPACE |
| `U+2005` | Four-Per-Em Space | FOUR-PER-EM SPACE |
| `U+2006` | Six-Per-Em Space | SIX-PER-EM SPACE |
| `U+2007` | Figure Space | FIGURE SPACE |
| `U+2008` | Punctuation Space | PUNCTUATION SPACE |
| `U+2009` | Thin Space | THIN SPACE |
| `U+200A` | Hair Space | HAIR SPACE |
| `U+2028` | Line Separator | LINE SEPARATOR |
| `U+2029` | Paragraph Separator | PARAGRAPH SEPARATOR |
| `U+202F` | Narrow No-Break Space | NARROW NO-BREAK SPACE |
| `U+205F` | Medium Mathematical Space | MEDIUM MATHEMATICAL SPACE |
| `U+3000` | Ideographic Space | IDEOGRAPHIC SPACE |

These are the usual reason a `split()`, a `strip()`, a CSV import or a database
lookup fails on text that looks correct. Almost always a paste from Word, a PDF
or a web page.

## Medium: homoglyphs

Non-Latin letters that render like ASCII. Used for domain spoofing, package name
squatting, and slipping past keyword filters.

| Code point | Renders as | Script |
|---|---|---|
| `U+0391` Α | `A` | Greek |
| `U+0392` Β | `B` | Greek |
| `U+0395` Ε | `E` | Greek |
| `U+0396` Ζ | `Z` | Greek |
| `U+0397` Η | `H` | Greek |
| `U+0399` Ι | `I` | Greek |
| `U+039A` Κ | `K` | Greek |
| `U+039C` Μ | `M` | Greek |
| `U+039D` Ν | `N` | Greek |
| `U+039F` Ο | `O` | Greek |
| `U+03A1` Ρ | `P` | Greek |
| `U+03A4` Τ | `T` | Greek |
| `U+03A5` Υ | `Y` | Greek |
| `U+03A7` Χ | `X` | Greek |
| `U+03B1` α | `a` | Greek |
| `U+03B5` ε | `e` | Greek |
| `U+03B9` ι | `i` | Greek |
| `U+03BD` ν | `v` | Greek |
| `U+03BF` ο | `o` | Greek |
| `U+0405` Ѕ | `S` | Cyrillic |
| `U+0406` І | `I` | Cyrillic |
| `U+0408` Ј | `J` | Cyrillic |
| `U+0410` А | `A` | Cyrillic |
| `U+0412` В | `B` | Cyrillic |
| `U+0415` Е | `E` | Cyrillic |
| `U+041A` К | `K` | Cyrillic |
| `U+041C` М | `M` | Cyrillic |
| `U+041D` Н | `H` | Cyrillic |
| `U+041E` О | `O` | Cyrillic |
| `U+0420` Р | `P` | Cyrillic |
| `U+0421` С | `C` | Cyrillic |
| `U+0422` Т | `T` | Cyrillic |
| `U+0425` Х | `X` | Cyrillic |
| `U+0430` а | `a` | Cyrillic |
| `U+0435` е | `e` | Cyrillic |
| `U+043E` о | `o` | Cyrillic |
| `U+0440` р | `p` | Cyrillic |
| `U+0441` с | `c` | Cyrillic |
| `U+0443` у | `y` | Cyrillic |
| `U+0445` х | `x` | Cyrillic |
| `U+0455` ѕ | `s` | Cyrillic |
| `U+0456` і | `i` | Cyrillic |
| `U+0458` ј | `j` | Cyrillic |
| `U+04BB` һ | `h` | Cyrillic |
| `U+0501` ԁ | `d` | Cyrillic |
| `U+051B` ԛ | `q` | Cyrillic |
| `U+051D` ԝ | `w` | Cyrillic |

## Cosmetic: typography tells

Visible and perfectly legitimate. Reported only with `--include-cosmetic`, replaced
only at `--level paranoid`. They are a stylistic fingerprint, not a hidden channel.

| Code point | Name | ASCII replacement |
|---|---|---|
| `U+00A0` | No-Break Space | ` ` |
| `U+2013` | En Dash | `-` |
| `U+2014` | Em Dash | `-` |
| `U+2018` | Left Single Quote | `'` |
| `U+2019` | Right Single Quote | `'` |
| `U+201C` | Left Double Quote | `"` |
| `U+201D` | Right Double Quote | `"` |
| `U+2026` | Horizontal Ellipsis | `...` |
| `U+2212` | Minus Sign | `-` |

