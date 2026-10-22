# re-ai

I write the same triage notes every time I open an unknown binary, so I automated the boring part. `re-ai` reads a file and produces one markdown report: headers, sections, imports, strings, entropy, and the packer heuristics I check by hand.

Nothing is executed. It is static inspection only.

## What it does

1. Extracts printable ASCII and UTF-16LE strings with file offsets.
2. Parses the DOS header, COFF header, optional header, section table and import directory with a reader written against `struct`. No `pefile`, no binary parser dependency.
3. Resolves imports per DLL, including ordinal imports, for both PE32 and PE32+.
4. Computes Shannon entropy for the whole file, for 1 KiB chunks and for every section, plus any overlay after the last section.
5. Runs heuristics: known packer section names, high entropy sections, writable and executable sections, empty or tiny import tables, sections that expand in memory, entry point outside a section or in a high entropy last section, TLS directory, signature presence.
6. Optionally drafts the narrative analysis through any OpenAI compatible API. Off unless you pass `--llm`.

## Install

```console
git clone https://github.com/StefanYasin/re-ai.git
cd re-ai
python -m pip install -e ".[dev]"
```

Python 3.10 or newer. No runtime dependencies.

## Usage

```console
$ re-ai --file app.exe
re-ai: app.exe | entropy 6.42 (elevated) | score 3 | several indicators worth a closer look | report: app.exe.re-ai.md
```

The report is written next to the input as `<file>.re-ai.md`. Use `--out` to put it somewhere else, or `--out -` to print it.

```console
re-ai --file app.exe --out reports/app.md
re-ai --file app.exe --out - --quiet > report.md
re-ai --file app.exe --json findings.json
re-ai --file app.exe --llm
```

| Flag | Meaning |
| --- | --- |
| `--file PATH` | Binary to analyze. Required. |
| `--out PATH` | Report path. `-` writes to stdout. Defaults to `<file>.re-ai.md`. |
| `--llm` | Draft the analysis section through an OpenAI compatible API. |
| `--model NAME` | Override `RE_AI_MODEL`. |
| `--min-string-length N` | Minimum printable run. Default scales with file size (4, 6 or 8). |
| `--strings N` | How many interesting and longest strings to list. Default 25. |
| `--json [PATH]` | Also write the findings as JSON. `-` writes to stdout. |
| `--quiet` | Skip the summary line. |

Exit codes: `0` report written, `1` report written but the LLM step failed, `2` bad input or output path.

## LLM section

The API call is a plain `POST` to `<base URL>/chat/completions` using `urllib`, so there is still nothing to install. Configure it with environment variables:

```console
export RE_AI_BASE_URL="https://api.openai.com/v1"
export RE_AI_API_KEY="sk-..."
export RE_AI_MODEL="gpt-4o-mini"      # optional, this is the default
re-ai --file app.exe --llm
```

`OPENAI_BASE_URL`, `OPENAI_API_KEY` and `OPENAI_MODEL` work as fallbacks. A local server that ignores the key still needs a non empty `RE_AI_API_KEY`, for example `local`. If the call fails the report is still written, the failure is noted in the Analysis section, and the exit code is `1`.

The prompt only contains facts the tool extracted: hashes, header fields, sections, imports, interesting strings, entropy values and findings. Nothing from the file is uploaded beyond that summary.

## Report layout

`# Static analysis: <name>`, then `## Assessment`, `## File`, `## PE headers`, `## Sections`, `## Imports`, `## Strings`, `## Entropy`, `## Analysis`, `## Method and limits`. The layout is fixed so two reports diff cleanly.

## Tests

```console
python -m pytest -q
```

The PE parser is tested against a synthetic PE image built byte by byte in `tests/pe_builder.py`, so the suite runs without a compiler and without network access. When a mingw capable `gcc` is on `PATH`, the tests also compile a tiny C program and parse that, which covers a real linker output. The LLM tests start a local HTTP server and never touch a real API.

## Limits

- PE only. An ELF or Mach-O file gets strings and entropy, and the report says it is not a PE.
- Strings are raw printable runs. They are not attributed to sections yet.
- Entropy and heuristics are indicators. A clean report does not mean a clean sample.
- No disassembly, no unpacking, no emulation. Those belong in a real RE workflow, not in this tool.

## License

MIT.

Built by Stefan Yasin (https://stefanyasin.github.io/)
