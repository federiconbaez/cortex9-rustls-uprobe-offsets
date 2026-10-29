"""Búsqueda de firmas en el .text de un binario strippeado."""
from .elf import Elf
from .sig import find_targets, nm_functions, signature, to_regex

ALIGN = 16

def search(text_addr, text, sig, align=ALIGN):
    """Direcciones (vaddr) alineadas donde la firma coincide."""
    rx = to_regex(sig)
    hits = []
    start = (-text_addr) % align
    for pos in range(start, len(text) - len(sig) + 1, align):
        if rx.match(text, pos):
            hits.append(text_addr + pos)
    return hits

ANCHOR_WINDOW = 0x10000
ANCHOR_MAX = 8
ANCHOR_MIN_SIZE = 32

def anchors_for(ref_path, addr, funcs=None):
    """Funciones rustls del gemelo más cercanas a `addr` (misma unidad de código, en general)."""
    funcs = funcs if funcs is not None else nm_functions(ref_path)
    near = []
    for name, vals in funcs.items():
        if "rustls" not in name:
            continue
        for (a, sz) in vals:
            if a != addr and sz >= ANCHOR_MIN_SIZE and abs(a - addr) <= ANCHOR_WINDOW:
                near.append((abs(a - addr), a, sz, name))
    near.sort()
    return near[:ANCHOR_MAX]

def disambiguate(ref_path, addr, hits, text_addr, text, align, funcs):
    """Elige entre varias coincidencias usando anclas: funciones rustls vecinas que coinciden
    de forma única en el objetivo. Un candidato se acepta sólo si su distancia al ancla es la
    misma que en el gemelo para al menos 2 anclas y ningún otro candidato tiene apoyo."""
    support = {h: 0 for h in hits}
    used = 0
    for _d, a, sz, _name in anchors_for(ref_path, addr, funcs):
        try:
            sig = signature(ref_path, a, sz)
        except ValueError:
            continue
        ah = search(text_addr, text, sig, align)
        if len(ah) != 1:
            continue
        used += 1
        cand = ah[0] + (addr - a)
        if cand in support:
            support[cand] += 1
    best = sorted(support.items(), key=lambda kv: -kv[1])
    if best and best[0][1] >= 2 and (len(best) == 1 or best[1][1] == 0):
        return best[0][0], best[0][1], used
    return None, (best[0][1] if best else 0), used

def resolve(ref_path, target_path, align=ALIGN):
    """Resuelve las funciones objetivo de `ref_path` (con símbolos) en `target_path` (strippeado).
    Devuelve {clave: {status, vaddr?, file_offset?, candidates}}; status ∈ {ok, ambiguous, notfound}."""
    targets = find_targets(ref_path)
    elf = Elf(target_path)
    text_addr, text = elf.section(".text")
    out = {}
    funcs = None
    for key, (addr, size) in sorted(targets.items()):
        sig = signature(ref_path, addr, size)
        hits = search(text_addr, text, sig, align)
        r = {"candidates": len(hits), "sig_len": len(sig),
             "masked": sum(1 for b in sig if b is None)}
        if len(hits) == 1:
            r.update(status="ok", method="unique", vaddr=hits[0],
                     file_offset=elf.vaddr_to_offset(hits[0]))
        elif hits:
            funcs = funcs if funcs is not None else nm_functions(ref_path)
            pick, sup, used = disambiguate(ref_path, addr, hits, text_addr, text, align, funcs)
            r.update(anchors_used=used, anchor_support=sup)
            if pick is not None:
                r.update(status="ok", method="anchored", vaddr=pick,
                         file_offset=elf.vaddr_to_offset(pick))
            else:
                r["status"] = "ambiguous"
        else:
            r["status"] = "notfound"
        out[key] = r
    return out
