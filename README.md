# Invisible Text Forensics

**An Agent Skill that reads text at the code point level: finds and removes zero-width
characters, bidirectional overrides, tag characters, variation-selector payloads and
homoglyphs. Also watermarks documents so you can tell which copy leaked.**

[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-6E56CF)
![Offline](https://img.shields.io/badge/network-never-8f9bb8)

```bash
npx skills add Hiberius/invisible-text-forensics
```

Works with Claude Code, Claude Desktop, Codex, Cursor, Windsurf, OpenClaw and anything
else that reads a `SKILL.md`.

---

## Why this exists

Humanizer and de-AI skills rewrite **style**: em dashes, "delve", tricolons. There are
dozens of them and some have tens of thousands of stars. Not one of them reads the
**bytes**.

Text carries characters that render as nothing and survive copy, paste, email, PDF
extraction and git:

- a zero-width watermark that says which copy of your contract this is
- a run of tag characters spelling `IGNORE PREVIOUS INSTRUCTIONS` inside a prompt
- a bidirectional override making source code render differently from how it compiles
- a no-break space in a CSV header that quietly breaks a column lookup

This skill is the layer underneath the humanizers. Run a humanizer for the prose, run
this for everything the prose is made of.

## Try it in ten seconds

```bash
python3 scripts/itf.py scan document.md
```

```
document.md
  CRITICAL U+202E     line 12 col 18  Right-to-Left Override (RLO)
           reorders rendering; Trojan Source (CVE-2021-42574) in source code
  HIGH     U+200B     line 3 col 41   Zero Width Space (ZWSP)
           invisible; carries watermarks and hidden payloads
  MEDIUM   U+0443     line 3 col 58   Homoglyph of 'y'
           non-Latin letter that renders like ASCII
```

## What it does

| Command | What you get |
|---|---|
| `scan` | Every hidden or risky character with code point, line, column, risk level and why it matters. `--json` for pipelines, `--fail-on high` as a CI gate. |
| `clean` | Removal at three levels: `safe` (hidden characters only), `aggressive` (+ exotic spaces), `paranoid` (+ homoglyphs and smart typography folded to ASCII). |
| `extract` | Decodes what the invisible characters actually spell: tag characters, variation-selector bytes, zero-width binary. |
| `watermark` | Embeds an invisible copy identifier. Two recipients get visually identical files. |
| `identify` | Reads the identifier back out of a leaked copy. |

## The detail that matters

`U+200D` (ZWJ) and `U+200C` (ZWNJ) are **not** always removable:

- inside an emoji sequence, ZWJ is what makes 👨‍👩‍👧 one family instead of three people
- in Arabic, Persian, Hindi and other complex scripts they change which letters join, and
  removing them changes the word

Every naive `re.sub` stripper corrupts both. This one checks the neighbouring code points
first and leaves legitimate joiners alone. Verified in `tests/`.

## Use it as a CI gate

```yaml
- name: invisible character gate
  run: python3 scripts/itf.py scan . --fail-on critical
```

Blocks pull requests that carry Trojan Source overrides or tag-character payloads.

## Documentation

- [`SKILL.md`](SKILL.md) — the skill itself, what the agent reads
- [`references/character-catalog.md`](references/character-catalog.md) — every code point, by risk level
- [`references/attack-patterns.md`](references/attack-patterns.md) — six attack mechanics with reproducible payloads

## Related

- [hiberius-unicode-toolkit](https://github.com/Hiberius/hiberius-unicode-toolkit) — the same engine as a single offline HTML page, no install
- Pair it with any humanizer skill: they handle the writing, this handles the bytes

## License

MIT. No network calls, no telemetry, no dependencies. Nothing leaves your machine.
