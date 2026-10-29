#!/usr/bin/env python3
"""Mide recall y falsos positivos de los escenarios pre-registrados sobre corpus-out/.
Uso: python3 scripts/measure.py [corpus-out] [salida.json]
Escribe el JSON con cada caso y un resumen. No decide nada por sí solo: el
resumen trae recall y FP de cada escenario y si cumple el umbral pre-registrado."""
import json, os, sys, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rpo.match import resolve
from rpo.sig import find_targets

THRESH = {"S1": 0.90, "S2": 0.90}

def configs(root):
    out = []
    for d in sorted(os.listdir(root)):
        p = os.path.join(root, d)
        if os.path.isdir(p) and "-O" in d and not d.startswith("work-"):
            v, o = d.rsplit("-O", 1)
            out.append((v, o, p))
    return out

def case(scn, ref, tgt_stripped, truth_bin):
    truth = find_targets(truth_bin)
    res = resolve(ref, tgt_stripped)
    rows = []
    for key, (addr, _sz) in sorted(truth.items()):
        r = res.get(key, {"status": "no_ref"})
        ok = r.get("status") == "ok"
        rows.append({"scenario": scn, "ref": ref, "target": tgt_stripped, "target_fn": key,
                     "truth": addr, "status": r.get("status"), "method": r.get("method"),
                     "reported": r.get("vaddr"), "correct": ok and r["vaddr"] == addr,
                     "false_positive": ok and r["vaddr"] != addr,
                     "candidates": r.get("candidates")})
    return rows

def summarize(rows):
    s = {}
    for scn in sorted({r["scenario"] for r in rows}):
        rs = [r for r in rows if r["scenario"] == scn]
        n = len(rs); c = sum(r["correct"] for r in rs); fp = sum(r["false_positive"] for r in rs)
        d = {"targets": n, "correct": c, "false_positives": fp,
             "anchored_correct": sum(1 for r in rs if r["correct"] and r["method"] == "anchored"),
             "ambiguous": sum(1 for r in rs if r["status"] == "ambiguous"),
             "notfound": sum(1 for r in rs if r["status"] == "notfound"),
             "recall": round(c / n, 4) if n else None}
        if scn in THRESH:
            d["threshold_recall"] = THRESH[scn]
            d["cumple"] = bool(n) and c / n >= THRESH[scn] and fp == 0
        s[scn] = d
    return s

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "corpus-out"
    out = sys.argv[2] if len(sys.argv) > 2 else None
    cfgs = configs(root)
    if not cfgs:
        sys.exit(f"sin configuraciones en {root}")
    rows = []
    for v, o, p in cfgs:
        for app in ("app-a", "app-b"):
            rows += case("S1", f"{p}/{app}", f"{p}/{app}.stripped", f"{p}/{app}")
        rows += case("S2", f"{p}/app-a", f"{p}/app-b.stripped", f"{p}/app-b")
        rows += case("S2", f"{p}/app-b", f"{p}/app-a.stripped", f"{p}/app-a")
        for v2, o2, p2 in cfgs:
            if o2 == o and v2 != v:
                rows += case("S3", f"{p2}/app-a", f"{p}/app-a.stripped", f"{p}/app-a")
    # objetivos que no aparecen en el gemelo (inlineados)
    missing = []
    for v, o, p in cfgs:
        for app in ("app-a", "app-b"):
            t = find_targets(f"{p}/{app}")
            for k in ("Reader::read", "Writer::write"):
                if k not in t:
                    missing.append(f"{v}-O{o}/{app}:{k}")
    toolchain = open(os.path.join(root, "toolchain.txt")).read().strip() if os.path.exists(os.path.join(root, "toolchain.txt")) else None
    doc = {"toolchain": toolchain, "configs": [f"{v}-O{o}" for v, o, _ in cfgs],
           "targets_absent_in_twin": missing, "summary": summarize(rows), "cases": rows}
    js = json.dumps(doc, indent=1)
    if out:
        open(out, "w").write(js + "\n")
    print(json.dumps({"toolchain": toolchain, "configs": len(cfgs), "absent": missing,
                      "summary": doc["summary"]}, indent=1))
    fp_total = sum(r["false_positive"] for r in rows if r["scenario"] in ("S1", "S2"))
    return 1 if fp_total else 0

if __name__ == "__main__":
    sys.exit(main())
