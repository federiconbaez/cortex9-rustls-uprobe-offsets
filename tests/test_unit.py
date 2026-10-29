import os, re, subprocess, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rpo.elf import Elf, ElfError
from rpo.sig import parse_objdump, mask_instruction, to_regex, TARGETS
from rpo.match import search, infer_align

SAMPLE = """
0000000000149150 <x>:
  149150:\t55                   \tpush   %rbp
  149151:\t48 8b 05 10 20 30 00 \tmov    0x302010(%rip),%rax        # 44b168
  149158:\te8 13 00 00 00       \tcall   149170 <y>
  14915d:\t74 03                \tje     149162 <x+0x12>
  14915f:\tff 61 18             \tjmp    *0x18(%rcx)
  149162:\t0f 84 aa bb cc dd    \tje     ddd02c12 <z>
"""

class TestObjdump(unittest.TestCase):
    def test_parse(self):
        ins = parse_objdump(SAMPLE)
        self.assertEqual([a for a, _, _ in ins], [0x149150, 0x149151, 0x149158, 0x14915d, 0x14915f, 0x149162])
        self.assertEqual(ins[1][1], bytes.fromhex("488b0510203000"))

    def test_masks(self):
        ins = parse_objdump(SAMPLE)
        m = [mask_instruction(r, s) for _, r, s in ins]
        self.assertEqual(m[0], [0x55])
        self.assertEqual(m[1], [0x48] + [None] * 6)          # rip-relativo
        self.assertEqual(m[2], [0xE8, None, None, None, None])  # call rel32
        self.assertEqual(m[3], [0x74, 0x03])                  # rel8 corto: se conserva
        self.assertEqual(m[4], [0xFF, 0x61, 0x18])            # indirecto: se conserva
        self.assertEqual(m[5], [0x0F, 0x84, None, None, None, None])  # jcc rel32

class TestTargets(unittest.TestCase):
    def test_regex_both_std_layouts(self):
        r, w = TARGETS["Reader::read"], TARGETS["Writer::write"]
        self.assertTrue(r.match("<rustls::conn::connection::Reader as std::io::Read>::read"))
        self.assertTrue(r.match("<rustls::conn::connection::Reader as alloc::io::read::Read>::read"))
        self.assertFalse(r.match("<rustls::conn::connection::Reader as std::io::Read>::read_exact"))
        self.assertTrue(w.match("<rustls::conn::connection::Writer as core::io::write::Write>::write"))
        self.assertFalse(w.match("<rustls::conn::connection::Writer as std::io::Write>::write_all"))
        self.assertFalse(w.match("<ring::io::writer::Writer as ring::io::writer::Accumulator>::write_bytes"))

class TestSearch(unittest.TestCase):
    def test_aligned_unique_and_ambiguous(self):
        sig = [0x55, None, 0xC3]
        text = bytearray(b"\xcc" * 64)
        text[16:19] = b"\x55\x99\xc3"
        text[33:36] = b"\x55\x98\xc3"   # no alineado: se ignora
        self.assertEqual(search(0x1000, bytes(text), sig), [0x1010])
        text[48:51] = b"\x55\x00\xc3"
        self.assertEqual(search(0x1000, bytes(text), sig), [0x1010, 0x1030])

    def test_regex_escapes_metachars(self):
        rx = to_regex([ord("."), None, ord("*")])
        self.assertTrue(rx.match(b".x*"))
        self.assertFalse(rx.match(b"ax*"))
        self.assertTrue(rx.match(b".\n*"))  # comodín incluye \n

class TestAlign(unittest.TestCase):
    def test_infer_align(self):
        self.assertEqual(infer_align({"f": [(0x1000, 4)], "g": [(0x1010, 4)]}), 16)
        self.assertEqual(infer_align({"f": [(0x1003, 4)], "g": [(0x1010, 4)]}), 1)
        self.assertEqual(search(0x1000, b"\xcc\x55\xc3", [0x55, 0xC3], align=1), [0x1001])

class TestElf(unittest.TestCase):
    def test_text_section_matches_readelf(self):
        path = "/bin/true"
        e = Elf(path)
        out = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True, check=True).stdout
        m = re.search(r"\]\s+\.text\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", out)
        addr, off, size = (int(x, 16) for x in m.groups())
        self.assertEqual(e.sections[".text"], (addr, off, size))
        self.assertEqual(e.vaddr_to_offset(addr), off)

    def test_rejects_non_elf(self):
        with self.assertRaises(ElfError):
            Elf(__file__)

if __name__ == "__main__":
    unittest.main()
