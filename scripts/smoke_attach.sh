#!/usr/bin/env bash
# Smoke attach REAL (requiere root): para cada offset resuelto en S2 (app-a <-> app-b,
# misma versión y opt) registra un uprobe por tracefs en el binario STRIPPEADO,
# lo ejecuta y exige: salida 0 (no crashea) y >= 1 hit por probe.
# Falla fuerte si tracefs no está, si no se puede registrar o si algo no se cumple.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="${1:-$ROOT/corpus-out}"
TR=/sys/kernel/tracing
[ -w "$TR/uprobe_events" ] || mount -t tracefs nodev "$TR" 2>/dev/null || true
[ -w "$TR/uprobe_events" ] || { echo "FALLA: $TR/uprobe_events no escribible (¿root? ¿CONFIG_UPROBE_EVENTS?)" >&2; exit 1; }
uname -r
probes=0; hits_ok=0; fails=0
cleanup() { echo 0 > "$TR/events/rpo/enable" 2>/dev/null || true; echo > "$TR/uprobe_events" 2>/dev/null || true; }
trap cleanup EXIT
for cfg in "$CORPUS"/*-O*; do
  case "$(basename "$cfg")" in work-*) continue;; esac
  for pair in "app-a app-b" "app-b app-a"; do
    set -- $pair; ref="$cfg/$1"; tgt="$cfg/$2.stripped"
    json="$(cd "$ROOT" && python3 resolve.py --ref "$ref" --target "$tgt" --json || true)"
    mapfile -t offs < <(python3 -c 'import json,sys
d=json.loads(sys.argv[1])
for k,r in sorted(d.items()):
    if r["status"]=="ok": print(k.replace("::","_"), hex(r["file_offset"]))' "$json")
    [ "${#offs[@]}" -gt 0 ] || { echo "sin offsets resueltos para $ref -> $tgt"; continue; }
    cleanup
    names=()
    for line in "${offs[@]}"; do
      set -- $line; n="p$(( probes ))_$1"; names+=("$n")
      echo "p:rpo/$n $tgt:$2" >> "$TR/uprobe_events" || { echo "FALLA: no se pudo registrar $n en $tgt:$2" >&2; exit 1; }
      probes=$((probes+1))
    done
    echo 1 > "$TR/events/rpo/enable"
    if ! "$tgt" 8 >/dev/null; then echo "FALLA: $tgt terminó con error con probes puestos" >&2; fails=$((fails+1)); fi
    echo 0 > "$TR/events/rpo/enable"
    for n in "${names[@]}"; do
      h="$(awk -v n="$n" '$2==n {print $3}' "$TR/uprobe_profile")"
      echo "$(basename "$cfg") $(basename "$tgt") $n hits=${h:-?}"
      if [ -n "$h" ] && [ "$h" -ge 1 ]; then hits_ok=$((hits_ok+1)); else echo "FALLA: $n sin hits" >&2; fails=$((fails+1)); fi
    done
  done
done
echo "probes=$probes con_hits=$hits_ok fallas=$fails"
[ "$probes" -gt 0 ] || { echo "FALLA: ningún probe registrado" >&2; exit 1; }
[ "$fails" -eq 0 ]
