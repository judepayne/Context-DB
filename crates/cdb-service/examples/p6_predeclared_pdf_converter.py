#!/usr/bin/env python3
"""Bounded stdin/stdout PDF conversion for the real-document acceptance example."""
import argparse
import pathlib
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--pdftotext", required=True)
parser.add_argument("--pages", required=True)
parser.add_argument("input", nargs="?", default="-")
parser.add_argument("output", nargs="?", default="-")
args = parser.parse_args()
pages = [int(value) for value in args.pages.split(",")]
if not pages or pages != sorted(set(pages)) or pages[0] < 1:
    raise SystemExit("pages must be unique, positive, and ascending")
if args.input != "-" or args.output != "-":
    raise SystemExit("converter accepts stdin/stdout only")
with tempfile.TemporaryDirectory(prefix="ctxql-pdf-") as directory:
    source = pathlib.Path(directory) / "source.pdf"
    source.write_bytes(sys.stdin.buffer.read())
    for page in pages:
        result = subprocess.run(
            [args.pdftotext, "-f", str(page), "-l", str(page), "-layout", "-enc", "UTF-8", str(source), "-"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        sys.stdout.buffer.write(result.stdout)
sys.stdout.buffer.flush()
