#!/usr/bin/env python3
"""CLI: python3 resolve.py --ref BIN_CON_SIMBOLOS --target BIN_STRIPPEADO [--json]"""
import argparse, json, sys
from rpo.match import resolve

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ref", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = resolve(a.ref, a.target)
    if a.json:
        json.dump(res, sys.stdout, indent=2); print()
    else:
        for k, r in res.items():
            if r["status"] == "ok":
                print(f"{k}\tvaddr={r['vaddr']:#x}\tfile_offset={r['file_offset']:#x}")
            else:
                print(f"{k}\t{r['status']} (candidatos={r['candidates']})")
    return 0 if all(r["status"] == "ok" for r in res.values()) else 2

if __name__ == "__main__":
    sys.exit(main())
