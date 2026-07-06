#!/usr/bin/env python3
"""Convert the spec PDFs in docs/ to markdown for easier grepping.

Uses pdftotext (poppler) in layout mode so tables and figures keep
their alignment, and emits one fenced block per PDF page with a
"## Page N" heading, so text found by grep is easy to locate in the
original PDF.

Usage: python3 docs/pdf2md.py [file.pdf ...]
With no arguments, converts every PDF in the script's directory.
Output goes to docs/md/<name>.md.
"""

import pathlib
import re
import subprocess
import sys

DOCS = pathlib.Path(__file__).resolve().parent
OUT = DOCS / "md"


def convert(pdf: pathlib.Path) -> pathlib.Path:
    text = subprocess.run(
        ["pdftotext", "-layout", "-enc", "UTF-8", str(pdf), "-"],
        check=True, capture_output=True, text=True).stdout

    out = OUT / (pdf.stem + ".md")
    with out.open("w") as f:
        f.write(f"# {pdf.name}\n\n")
        f.write("Converted by docs/pdf2md.py; page numbers are PDF pages,\n"
                "not the document's printed page numbers.\n")
        # pdftotext separates pages with form feeds
        for i, page in enumerate(text.split("\f"), start=1):
            page = re.sub(r"[ \t]+$", "", page, flags=re.M).strip("\n")
            if not page:
                continue
            f.write(f"\n## Page {i}\n\n```\n{page}\n```\n")
    return out


def main() -> int:
    OUT.mkdir(exist_ok=True)
    pdfs = [pathlib.Path(a) for a in sys.argv[1:]] or sorted(DOCS.glob("*.pdf"))
    if not pdfs:
        print("no PDFs found", file=sys.stderr)
        return 1
    for pdf in pdfs:
        out = convert(pdf)
        print(f"{pdf.name} -> {out.relative_to(DOCS.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
