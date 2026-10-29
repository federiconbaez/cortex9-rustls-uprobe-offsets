# cortex9-rustls-uprobe-offsets

Resolvedor **offline** de offsets de uprobe para rustls en binarios Rust
**strippeados**. Le das un binario sin símbolos y un build gemelo con símbolos.
Te devuelve la dirección virtual y el offset de archivo de
`<rustls::conn::connection::Reader as Read>::read` y
`<rustls::conn::connection::Writer as Write>::write`, que es donde un uprobe ve el
texto plano de una conexión rustls. El matching no carga BPF ni necesita root: es
`nm` + `objdump` + Python estándar.

```
$ python3 resolve.py --ref build-con-simbolos/app --target app.stripped
Reader::read   vaddr=0x150bf0  file_offset=0x14fbf0
Writer::write  vaddr=0x150c90  file_offset=0x14fc90
# uprobe:  echo 'p:tls/rd /ruta/app.stripped:0x14fbf0' >> /sys/kernel/tracing/uprobe_events
```

## Cómo funciona

1. En el gemelo con símbolos ubica cada función objetivo con `nm -C -S`.
2. La desensambla con `objdump` y arma una firma de bytes. Enmascara las
   instrucciones `(%rip)` y el rel32 de call/jmp/jcc, que cambian con el layout.
3. Busca la firma en el `.text` del strippeado, con la alineación de funciones
   que infiere del gemelo (16, o 1 en `opt-level=s`).
4. Si hay **una** coincidencia, la reporta.
5. Si hay varias, desambigua con **anclas**: funciones rustls vecinas que
   coinciden de forma única. Acepta un candidato sólo si tiene ≥ 2 anclas de
   acuerdo y ningún rival tiene apoyo. Si no, no reporta nada: nunca adivina.

`Writer::write` es un trampolín de 10 bytes (`jmp *0x18(%rcx)`) que aparece
varias veces en cada binario. Por eso hacen falta las anclas: la mitad de los
aciertos son `anchored`.

## Resultados (box, rustc 1.99.1, 29/10/2026)

El corpus y los umbrales están en [PREREGISTRO.md](PREREGISTRO.md), commiteados
antes de medir. Son 24 binarios: 3 versiones de rustls (0.23.10, 0.23.27 y
0.23.46), 4 `opt-level` (1, 2, 3 y s) y 2 apps distintas. Los strippeados salen
de `strip --strip-all`. La verdad de terreno es `nm` del gemelo.

| Escenario | Corrida 1 (pre-registrada) | Corrida 2 (tras arreglo post-hoc) | Umbral |
|---|---|---|---|
| S1 gemelo: misma app con símbolos → strippeada | 36/48 (75 %), 0 FP: **no cumplido** | 48/48 (100 %), 0 FP | ≥ 90 %, 0 FP |
| S2 cruzado entre apps (misma versión y opt) | 36/48 (75 %), 0 FP: **no cumplido** | 48/48 (100 %), 0 FP | ≥ 90 %, 0 FP |
| S3 cruzado entre versiones de rustls (exploratorio) | 6/48 (12,5 %), 0 FP | 9/48 (18,75 %), 0 FP | sin umbral |

- La **corrida 1** es el resultado ciego y **no cumple**. Los 12 misses de S1 y
  S2 son todos de `opt-level=s`: ahí rustc no alinea funciones a 16 y la
  búsqueda estaba fija en 16.
- La **corrida 2** usa la alineación inferida del gemelo. Ese cambio se hizo
  después de ver la corrida 1, así que **no es ciego** (ver Enmienda 2).
- **Por construcción:** el 100 % de S1 es casi por construcción, porque el
  strippeado tiene el mismo código que su gemelo. En S2 el código de rustls
  también es casi idéntico entre las dos apps, porque se compila igual como
  crate aparte y sólo cambian las direcciones. Es un 100 % sobre mi propio
  corpus, no una garantía en binarios ajenos.
- S3 muestra el límite real: con otra versión de rustls la firma casi nunca
  coincide. **Hace falta un gemelo con la misma versión de rustls y el mismo
  opt-level.**
- Datos crudos: [`results/box-2026-10-29-run1.json`](results/box-2026-10-29-run1.json)
  y [`results/box-2026-10-29-run2.json`](results/box-2026-10-29-run2.json).

## Smoke attach (CI, sudo)

El job `corpus` reconstruye el corpus en GitHub Actions y vuelve a medir. El
paso falla si hay cualquier falso positivo en S1 o S2. Después corre
`scripts/smoke_attach.sh` con sudo, que para cada offset resuelto en S2 hace
esto:

1. Registra un uprobe real por tracefs (`p:rpo/… binario.stripped:0xOFFSET`).
2. Ejecuta el binario strippeado.
3. Exige que salga con código 0, o sea sin crash, y que cada probe tenga al
   menos 1 hit.

Si tracefs no está o el registro falla, el job falla. No hay salteos.

Resultado en CI ([run 40929672808](https://github.com/federiconbaez/cortex9-rustls-uprobe-offsets/actions/runs/40929672808),
kernel `7.0.0-1017-azure`, rustc 1.99.1, mismo código que la corrida 2): la
re-medición en el runner dio igual que en la box (S1 48/48, S2 48/48, S3 9/48,
0 FP). El smoke registró **48 uprobes**, los 48 con hits (16 o 18 por probe según
la app), con **0 crashes** y 0 fallas.

## Alcance y lo que NO está verificado

- Sólo x86-64 ELF, rustls 0.23.x con proveedor `ring` y el toolchain del
  momento: rustc 1.99.1 en la box y `stable` en CI.
- Sólo dos funciones objetivo. No cubre `read_tls`/`write_tls` ni rustls 0.21/0.22.
- No probé binarios de terceros: ni builds con LTO, ni PGO, ni `panic=abort`, ni
  otros linkers.
- El gemelo tiene que ser el **mismo build** sin strip, o un build con la misma
  versión de rustls y el mismo opt-level. Sin eso, S3 muestra que no sirve.
- El smoke attach usa uprobes de tracefs, el mismo mecanismo de kernel que usan
  los uprobes BPF, pero **no** carga un programa BPF ni lee el buffer plano.
- La clave privada en `corpus/fixtures/` es sólo de prueba.

## Uso

```
scripts/build_corpus.sh                      # corpus-out/ (RUSTUP_TOOLCHAIN=stable)
python3 -m unittest tests.test_unit tests.test_corpus -v
python3 scripts/measure.py corpus-out out.json
sudo scripts/smoke_attach.sh corpus-out      # necesita tracefs con uprobes
```

Licencia: Apache-2.0.
