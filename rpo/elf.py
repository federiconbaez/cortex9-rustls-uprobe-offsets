"""Lector mínimo de ELF64 little-endian: secciones y segmentos PT_LOAD."""
import struct

class ElfError(Exception):
    pass

class Elf:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ElfError(f"{path}: no es ELF")
        if d[4] != 2 or d[5] != 1:
            raise ElfError(f"{path}: sólo ELF64 little-endian")
        (self.e_type, self.e_machine, _ver, self.entry, phoff, shoff, _flags, _ehsize,
         phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
        self.segments = []
        for i in range(phnum):
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = struct.unpack_from(
                "<IIQQQQQQ", d, phoff + i * phentsize)
            if p_type == 1:  # PT_LOAD
                self.segments.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
        raw = []
        for i in range(shnum):
            raw.append(struct.unpack_from("<IIQQQQIIQQ", d, shoff + i * shentsize))
        self.sections = {}
        if raw and shstrndx < len(raw):
            stroff = raw[shstrndx][4]
            for (name, _t, _fl, addr, off, size, *_r) in raw:
                end = d.index(b"\0", stroff + name)
                self.sections[d[stroff + name:end].decode()] = (addr, off, size)

    def section(self, name):
        if name not in self.sections:
            raise ElfError(f"sin sección {name}")
        addr, off, size = self.sections[name]
        return addr, self.data[off:off + size]

    def vaddr_to_offset(self, vaddr):
        for (va, off, filesz, _m, _f) in self.segments:
            if va <= vaddr < va + filesz:
                return off + (vaddr - va)
        raise ElfError(f"vaddr {vaddr:#x} fuera de los PT_LOAD")

    def read_vaddr(self, vaddr, size):
        off = self.vaddr_to_offset(vaddr)
        return self.data[off:off + size]
