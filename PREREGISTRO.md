# Pre-registro (antes de medir)

Este archivo se commitea y se publica **antes** de correr la primera medición.
Nada de lo de abajo se cambia después de ver resultados; si algo cambia, va en
un commit nuevo que lo diga.

## Pregunta

Dado un binario Rust **strippeado** que enlaza rustls y un **build gemelo con
símbolos**, ¿se pueden recuperar las direcciones de las funciones donde un
uprobe ve el texto plano de rustls, sin símbolos en el binario objetivo y sin
cargar BPF en la máquina que hace el matching?

## Funciones objetivo (2 por binario)

Se busca por nombre demanglado en `nm -C` del build con símbolos:

- `<rustls::conn::connection::Reader as …Read>::read`
- `<rustls::conn::connection::Writer as …Write>::write`

(el path del trait varía entre toolchains: `std::io::Read` o `alloc::io::read::Read`;
la regex es `^<rustls::conn::connection::Reader as [\w:]*Read>::read$` y su
equivalente para `Writer`/`write`). Si una función no aparece en el gemelo
(p. ej. porque se inlineó), no cuenta como objetivo de ese binario y se
reporta cuántas quedaron afuera.

## Corpus

- Apps: `corpus/app-a` (TLS en memoria, Reader/Writer directo) y
  `corpus/app-b` (StreamOwned sobre socketpair Unix, en hilos). Son programas
  distintos: el layout del `.text` difiere entre ellos.
- Versiones de rustls: 0.23.46, 0.23.27, 0.23.10 (proveedor `ring`).
- `opt-level`: 1, 2, 3, s. Toolchain: `stable` (se registra `rustc --version`).
- 3 × 4 × 2 = 24 binarios. El strippeado es `strip --strip-all` del gemelo.

## Método

1. Del gemelo con símbolos se toma el rango de cada función objetivo
   (`nm -S`), se desensambla con `objdump` y se construye una firma de bytes
   donde se enmascaran los desplazamientos dependientes de posición
   (instrucciones con `(%rip)`, y el rel32 de call/jmp/jcc).
2. Se busca la firma en el `.text` del strippeado, sólo en direcciones
   alineadas a 16. Si hay **una** coincidencia se reporta; si hay **cero o más
   de una** no se reporta nada (ambigua = miss, nunca adivinar).
3. Verdad de terreno: `nm` del build con símbolos del binario objetivo.
   Un reporte es **falso positivo** si su dirección no es exactamente el
   inicio de la función objetivo correspondiente.

## Escenarios y umbrales

| Escenario | Firma desde | Objetivo strippeado | Umbral |
|---|---|---|---|
| S1 gemelo (criterio de aceptación) | app X con símbolos | strip de la misma app X | recall ≥ 90 %, FP = 0 |
| S2 cruzado entre apps | app-a con símbolos (y viceversa) | app-b strippeada, misma versión y opt | recall ≥ 90 %, FP = 0 |
| S3 cruzado entre versiones (exploratorio) | app X, otra versión de rustls, mismo opt | app X strippeada | sin umbral, sólo se reporta |

S1 es casi **por construcción**: el strippeado tiene exactamente el mismo
código que su gemelo, así que un 100 % ahí sólo prueba que el matcher no se
rompe y que no hay ambigüedad. S2 es la medición que importa.

## Smoke attach (CI, con sudo)

Para cada offset resuelto en S2 sobre los strippeados se registra un uprobe
por tracefs (`/sys/kernel/tracing/uprobe_events`, offset de archivo), se
ejecuta el binario strippeado y se exige: código de salida 0 (no crashea) y
≥ 1 hit por probe. Si tracefs no está o el registro falla, el job **falla**.

## Enmienda 1 (antes de la medición completa)

En una prueba de desarrollo con un solo par (0.23.46, opt-level 1, app-a → app-b)
se vio que `Writer::write` compila a un trampolín de 10 bytes
(`mov …; jmp *0x18(%rcx)`, despacho dinámico al `PlaintextSink`) que coincide
en 5 lugares del `.text`. Con la regla original eso es siempre un miss.

Se agrega un paso, fijado acá antes de medir el corpus completo: si una firma
tiene **varias** coincidencias, se toman hasta 8 funciones rustls vecinas del
gemelo (±64 KiB, tamaño ≥ 32 bytes) como **anclas**; las que coinciden de forma
única en el objetivo proponen `ancla + (objetivo − ancla en el gemelo)`. Se
acepta un candidato sólo si tiene apoyo de **≥ 2 anclas** y ningún otro
candidato tiene apoyo. Si no, sigue siendo ambiguo (miss). Los resultados
distinguen `unique` de `anchored`.

Umbrales, corpus y funciones objetivo **no cambian**. Ese par de desarrollo
queda incluido en la medición y se reporta igual que los demás.
