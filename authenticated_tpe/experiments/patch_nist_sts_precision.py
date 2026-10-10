#!/usr/bin/env python3
"""Make a reporting-only precision patch to an extracted NIST STS 2.1.2 tree.

The original source tree is never modified. Statistical algorithms and settings
are unchanged; p-value serialization and the second-level parser are upgraded
from six-decimal float I/O to round-trip double I/O.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import shutil
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_hash(root: Path, source_only: bool = False) -> str:
    rows = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if source_only and path.relative_to(root).parts[0] not in {"src", "include", "templates"} and path.name not in {"makefile", "Makefile", "config.h"}:
            continue
        rows.append(f"{digest(path.read_bytes())}  {path.relative_to(root).as_posix()}")
    return digest("\n".join(rows).encode())


def patch(source: Path, destination: Path, diff_path: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    changes: list[str] = []
    for path in sorted((destination / "src").glob("*.c")):
        before = path.read_text(errors="strict")
        after = before
        # All C floating-point report fields use 17 significant digits. This
        # includes per-stream p-values and provides round-trip double output.
        after = after.replace("%f", "%.17g")
        after = after.replace("%8.6f", "%.17g")
        after = after.replace("%9.6f", "%.17g")
        # Linear-complexity stats contain two adjacent floating values.
        after = after.replace("%.17g%.17g", "%.17g %.17g")
        if path.name == "assess.c":
            after = after.replace("float\tc;", "double\tc;")
            after = after.replace('fscanf(fp[numOfFiles], "%.17g", &c);', 'fscanf(fp[numOfFiles], "%lf", &c);')
            after = after.replace('fscanf(fp, "%.17g", &c);', 'fscanf(fp, "%lf", &c);')
            # The histogram and final report now consume full parsed doubles.
        if after != before:
            original_rel = path.relative_to(destination)
            changes.extend(difflib.unified_diff(
                before.splitlines(keepends=True), after.splitlines(keepends=True),
                fromfile=f"a/{original_rel.as_posix()}", tofile=f"b/{original_rel.as_posix()}",
            ))
            path.write_text(after)
    diff_path.write_text("".join(changes), encoding="utf-8")
    if not changes:
        raise RuntimeError("No precision patch was applied")
    assess = (destination / "src" / "assess.c").read_text()
    if "float\tc;" in assess or 'fscanf(fp, "%f", &c)' in assess:
        raise RuntimeError("assess.c double parser patch did not apply")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--destination", type=Path, required=True)
    ap.add_argument("--diff", type=Path, required=True)
    ap.add_argument("--metadata", type=Path, required=True)
    args = ap.parse_args()
    patch(args.source.resolve(), args.destination.resolve(), args.diff.resolve())
    values = [
        f"official_extracted_tree_sha256={tree_hash(args.source.resolve())}",
        f"official_source_tree_sha256={tree_hash(args.source.resolve(), source_only=True)}",
        f"precision_patched_source_tree_sha256={tree_hash(args.destination.resolve(), source_only=True)}",
        f"precision_patch_sha256={digest(args.diff.read_bytes())}",
        f"precision_patch_script_sha256={digest(Path(__file__).read_bytes())}",
    ]
    args.metadata.write_text("\n".join(values) + "\n", encoding="utf-8")
    print("\n".join(values))


if __name__ == "__main__":
    main()
