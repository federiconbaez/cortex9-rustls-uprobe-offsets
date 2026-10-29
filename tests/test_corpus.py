"""Integración sobre el corpus construido. Falla (no se saltea) si no hay corpus:
correr antes scripts/build_corpus.sh."""
import os, sys, unittest
ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
from rpo.match import resolve
from rpo.sig import find_targets
CORPUS = os.environ.get("RPO_CORPUS", os.path.join(ROOT, "corpus-out"))

def cfgs():
    if not os.path.isdir(CORPUS):
        raise AssertionError(f"no hay corpus en {CORPUS}: correr scripts/build_corpus.sh")
    c = [os.path.join(CORPUS, d) for d in sorted(os.listdir(CORPUS)) if "-O" in d and not d.startswith("work-")]
    if not c:
        raise AssertionError(f"corpus vacío en {CORPUS}")
    return c

class TestCorpus(unittest.TestCase):
    def test_stripped_has_no_symbols_and_twin_has_targets(self):
        for p in cfgs():
            for app in ("app-a", "app-b"):
                self.assertEqual(find_targets(f"{p}/{app}.stripped"), {}, p)
                self.assertTrue(find_targets(f"{p}/{app}"), f"{p}/{app} sin funciones objetivo")

    def test_twin_resolution_never_wrong(self):
        for p in cfgs():
            for app in ("app-a", "app-b"):
                truth = find_targets(f"{p}/{app}")
                for k, r in resolve(f"{p}/{app}", f"{p}/{app}.stripped").items():
                    if r["status"] == "ok":
                        self.assertEqual(r["vaddr"], truth[k][0], f"{p}/{app} {k}")

    def test_cross_app_resolution_never_wrong(self):
        for p in cfgs():
            for ref, tgt in (("app-a", "app-b"), ("app-b", "app-a")):
                truth = find_targets(f"{p}/{tgt}")
                for k, r in resolve(f"{p}/{ref}", f"{p}/{tgt}.stripped").items():
                    if r["status"] == "ok":
                        self.assertEqual(r["vaddr"], truth[k][0], f"{p} {ref}->{tgt} {k}")

if __name__ == "__main__":
    unittest.main()
