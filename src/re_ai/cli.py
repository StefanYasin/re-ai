"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze_file
from .entropy import describe_entropy
from .llm import LLMError, draft_analysis, resolve_config
from .report import render_report

EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_BAD_INPUT = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="re-ai",
        description="Static triage of a binary into a single markdown report.",
        epilog=(
            "LLM drafting is off by default. Set RE_AI_BASE_URL, RE_AI_API_KEY and "
            "optionally RE_AI_MODEL, then pass --llm."
        ),
    )
    parser.add_argument("--file", required=True, metavar="PATH", help="binary to analyze")
    parser.add_argument(
        "--out",
        metavar="PATH",
        default=None,
        help="report path, or - for stdout (default: <file>.re-ai.md next to the input)",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="draft the analysis section with an OpenAI compatible API",
    )
    parser.add_argument("--model", metavar="NAME", default=None, help="override RE_AI_MODEL")
    parser.add_argument(
        "--min-string-length",
        type=int,
        default=None,
        metavar="N",
        help="minimum printable run length (default scales with file size)",
    )
    parser.add_argument(
        "--strings",
        type=int,
        default=25,
        metavar="N",
        help="how many interesting and longest strings to print (default 25)",
    )
    parser.add_argument(
        "--json",
        nargs="?",
        const="-",
        default=None,
        metavar="PATH",
        help="also write machine readable findings, - for stdout",
    )
    parser.add_argument("--quiet", action="store_true", help="do not print the summary line")
    parser.add_argument("--version", action="version", version=f"re-ai {__version__}")
    return parser


def _default_out(file_path: Path) -> Path:
    return file_path.with_name(file_path.name + ".re-ai.md")


def _write(path: str, text: str) -> None:
    if path == "-":
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    file_path = Path(args.file).expanduser()
    if not file_path.exists():
        print(f"re-ai: no such file: {file_path}", file=sys.stderr)
        return EXIT_BAD_INPUT
    if not file_path.is_file():
        print(f"re-ai: not a regular file: {file_path}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if args.min_string_length is not None and args.min_string_length < 1:
        print("re-ai: --min-string-length must be 1 or more", file=sys.stderr)
        return EXIT_BAD_INPUT
    if args.strings < 0:
        print("re-ai: --strings must be 0 or more", file=sys.stderr)
        return EXIT_BAD_INPUT

    try:
        analysis = analyze_file(file_path, strings_min=args.min_string_length)
    except OSError as exc:
        print(f"re-ai: could not read {file_path}: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT

    llm_text: str | None = None
    llm_model: str | None = None
    llm_error: str | None = None
    exit_code = EXIT_OK

    if args.llm:
        try:
            config = resolve_config(model=args.model)
            llm_text, llm_model = draft_analysis(analysis, config=config)
        except LLMError as exc:
            llm_error = str(exc)
            exit_code = EXIT_PARTIAL
            print(f"re-ai: LLM drafting failed: {exc}", file=sys.stderr)

    report = render_report(
        analysis,
        llm_text=llm_text,
        llm_model=llm_model,
        llm_error=llm_error,
        strings_limit=args.strings,
    )

    out_path = args.out if args.out is not None else str(_default_out(file_path))
    try:
        _write(out_path, report)
        if args.json is not None:
            _write(args.json, json.dumps(analysis.to_dict(), indent=2) + "\n")
    except OSError as exc:
        print(f"re-ai: could not write output: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if not args.quiet:
        target = "stdout" if out_path == "-" else out_path
        print(
            f"re-ai: {analysis.name} | entropy {analysis.overall_entropy:.2f} "
            f"({describe_entropy(analysis.overall_entropy)}) | score {analysis.risk_score} "
            f"| {analysis.verdict} | report: {target}"
        )
    return exit_code
