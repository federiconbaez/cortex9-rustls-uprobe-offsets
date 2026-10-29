"""Firmas de bytes de funciones, con desplazamientos dependientes de posición enmascarados."""
import re
import subprocess

TARGETS = {
    "Reader::read": re.compile(r"^<rustls::conn::connection::Reader as [\w:]*Read>::read$"),
    "Writer::write": re.compile(r"^<rustls::conn::connection::Writer as [\w:]*Write>::write$"),
}

_OBJDUMP_LINE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )*[0-9a-f]{2})\s*\t?(.*)$")
_REL32_BRANCH = re.compile(r"^(call|jmp|j[a-z]{1,3})\b")

def nm_functions(path):
    """Devuelve {nombre_demanglado: [(addr, size), ...]} de símbolos de texto con tamaño."""
    out = subprocess.run(["nm", "-C", "-S", "--defined-only", path],
                         check=True, capture_output=True, text=True).stdout
    funcs = {}
    for line in out.splitlines():
        parts = line.split(" ", 3)
        if len(parts) != 4 or parts[2] not in ("T", "t"):
            continue
        funcs.setdefault(parts[3], []).append((int(parts[0], 16), int(parts[1], 16)))
    return funcs

def find_targets(path):
    """{clave_objetivo: (addr, size)} para las funciones objetivo presentes en un build con símbolos.
    Si un nombre aparece más de una vez con direcciones distintas se lanza error: no se adivina."""
    funcs = nm_functions(path)
    found = {}
    for key, rx in TARGETS.items():
        hits = sorted({v for name, vals in funcs.items() if rx.match(name) for v in vals})
        if len(hits) > 1:
            raise ValueError(f"{path}: {key} tiene {len(hits)} definiciones: {hits}")
        if hits:
            found[key] = hits[0]
    return found

def parse_objdump(text):
    """Parsea `objdump -d -w` en [(addr, bytes, mnemonic_y_operandos)]. Las líneas de
    continuación (instrucciones largas partidas) se pegan a la anterior."""
    insns = []
    for line in text.splitlines():
        m = _OBJDUMP_LINE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        asm = m.group(3).strip()
        if insns and not asm and insns[-1][0] + len(insns[-1][1]) == addr:
            a, b, s = insns[-1]
            insns[-1] = (a, b + raw, s)
        else:
            insns.append((addr, raw, asm))
    return insns

def mask_instruction(raw, asm):
    """Lista de bytes o None (comodín) para una instrucción."""
    out = list(raw)
    if "(%rip)" in asm:
        # desplazamiento rip-relativo: enmascarar todo salvo el primer byte de opcode
        return [out[0]] + [None] * (len(out) - 1)
    if _REL32_BRANCH.match(asm) and len(raw) >= 5 and not asm.startswith(("jmp *", "call *")):
        if "*" not in asm.split(None, 1)[-1]:
            return out[:-4] + [None] * 4
    return out

def signature(path, addr, size):
    """Firma enmascarada de la función [addr, addr+size) de `path`."""
    txt = subprocess.run(["objdump", "-d", "-w",
                          f"--start-address={addr:#x}", f"--stop-address={addr + size:#x}", path],
                         check=True, capture_output=True, text=True).stdout
    sig = []
    expect = addr
    for a, raw, asm in parse_objdump(txt):
        if a != expect:
            raise ValueError(f"hueco en el desensamblado en {a:#x} (esperaba {expect:#x})")
        sig.extend(mask_instruction(raw, asm))
        expect = a + len(raw)
    if expect != addr + size:
        raise ValueError(f"desensamblado incompleto: {expect:#x} != {addr + size:#x}")
    return sig

def to_regex(sig):
    return re.compile(b"".join(b"." if b is None else re.escape(bytes([b])) for b in sig), re.S)
