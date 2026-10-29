#!/usr/bin/env bash
# Construye la matriz del corpus: apps {a,b} x versiones de rustls x opt-level.
# Salida: corpus-out/<version>-O<opt>/<app>{,.stripped}
# Uso: scripts/build_corpus.sh [versiones...]  (por defecto la lista pre-registrada)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/corpus-out"
VERSIONS=("${@:-}")
if [ -z "${VERSIONS[0]}" ]; then VERSIONS=(0.23.46 0.23.27 0.23.10); fi
OPTS=(${OPTS:-1 2 3 s})
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
mkdir -p "$OUT"
rustc --version > "$OUT/toolchain.txt"
for v in "${VERSIONS[@]}"; do
  W="$OUT/work-$v"
  rm -rf "$W"; mkdir -p "$W"
  cp -r "$ROOT/corpus/app-a" "$ROOT/corpus/app-b" "$ROOT/corpus/fixtures" "$W/"
  for app in app-a app-b; do
    (cd "$W/$app" && cargo generate-lockfile -q && cargo update -q -p rustls --precise "$v")
  done
  for o in "${OPTS[@]}"; do
    D="$OUT/$v-O$o"; mkdir -p "$D"
    for app in app-a app-b; do
      (cd "$W/$app" && CARGO_TARGET_DIR="$W/target-O$o" CARGO_PROFILE_RELEASE_OPT_LEVEL="$o" \
        cargo build -q --release)
      cp "$W/target-O$o/release/$app" "$D/$app"
      strip --strip-all -o "$D/$app.stripped" "$D/$app"
      # el binario strippeado debe ejecutar igual que el gemelo
      "$D/$app.stripped" 2 >/dev/null
    done
    echo "built $D"
  done
done
