# Uso (Español)

## Comandos

| Comando | Qué hace |
|---------|----------|
| `vouch search <query>` | Busca en el AUR por nombre y descripción (más votados primero). Alias: `s`. |
| `vouch audit <pkg>` | Baja los metadatos + recipe del AUR y muestra un veredicto. **Solo lectura** — no compila. |
| `vouch build <pkg\|dir>` | Veta, aplica el gate y compila en el sandbox sin red. Acepta un nombre AUR o un directorio local con `PKGBUILD`. No instala. |
| `vouch install <pkg…>` | Resuelve el grafo de dependencias, veta cada paquete AUR, compila en orden e instala con pacman. Alias: `i`. |
| `vouch upgrade` | Recompila los paquetes AUR instalados cuya versión en el AUR es más nueva (un `-Syu` de la capa AUR). Alias: `u`. |
| `vouch ioc [--import FILE]` | Muestra los indicadores de compromiso cargados, o mergea un feed JSON. |
| `vouch forget <pkg>` | Borra la aprobación guardada de un paquete y re-arma el trust-on-first-use. |

## Flags

- `--dry-run` — resuelve y veta todo, muestra el plan, no compila ni instala nada.
- `--yes` — continúa pese a un veredicto **REVIEW**, o acepta un recipe que
  **cambió** desde la última vez que lo avalaste.
- `--force` — compila aunque el veredicto sea **REFUSED**. Muy desaconsejado;
  imprime una advertencia clara.
- `--allow-build-network` — permite que el `build()` de ese paquete use red (para
  recipes que sí necesitan descargar al compilar, p.ej. electron/npm). Es
  **por-paquete**, el paquete se sigue vetando, se **recuerda** para el recipe sin
  cambios, y reduce el aislamiento (se imprime un aviso claro).
- `--rmdeps` — tras instalar, quita las dependencias solo-de-build (make/check que
  no se necesitan en runtime) que nada más requiere (`pacman -Rns`).
- `--no-sandbox` — compila **sin** el sandbox de aislamiento. Algunos recipes no
  compilan aislados (p.ej. los que necesitan FUSE/unionfs, como el wrapper de
  flutter-bin que usan ciertas apps Flutter — verás `unionfs failed` en el sandbox).
  Con `--no-sandbox` el build corre sin confinar; el paquete **se sigue vetando**
  (trust + scan + IoC + TOFU), solo se quita el aislamiento del build.
- `--no-devel` (solo `upgrade`) — **los paquetes VCS se revisan por defecto**:
  `vouch upgrade` y `vouch -Syu` también recompilan los `-git`/`-svn`/… instalados
  cuyo upstream tiene commits nuevos (compara el `HEAD` upstream con el commit
  incrustado en la versión instalada, un `git ls-remote` por paquete). Usa
  `--no-devel` para saltar ese chequeo y ganar velocidad. (Los paquetes con fuente
  VCS pero versión tipo release no se autodetectan — recompílalos con `vouch -S <pkg>`.)

## Veredictos y códigos de salida

| Veredicto | Significado | Código |
|-----------|-------------|--------|
| VOUCHED | Suficientemente limpio para continuar | `0` |
| REVIEW REQUIRED | Un humano debe revisar primero (`--yes` para seguir) | `1` |
| REFUSED | Demasiado riesgoso; no compila (`--force` para forzar) | `2` |
| (error) | Fallo de red/parseo/etc. | `3` |

## Flujos típicos

**Vetar antes de confiar en nada**
```console
$ vouch audit firefox-patch-bin
```

**Instalar con vista previa**
```console
$ vouch install pamac-aur --dry-run     # ver el plan y veredictos por paquete
$ vouch install pamac-aur               # build (en sandbox) + instalar
```

**Un paquete que de verdad necesita red al compilar**
```console
$ vouch build alguna-electron-app --allow-build-network
# recordado: una recompilación posterior sin cambios ya no necesita el flag
```

**Mantener al día los paquetes AUR**
```console
$ vouch upgrade --dry-run    # lista lo que tiene versión más nueva en el AUR
$ vouch upgrade              # veta + recompila + instala las actualizaciones
```

**Feeds de threat intel**
```console
$ vouch ioc                           # muestra contadores de indicadores y la ruta del feed
$ vouch ioc --import aur-malware.json # mergea una lista comunitaria (p.ej. aur-malware-check)
```

## Sintaxis estilo pacman

`vouch` también acepta flags estilo pacman (como `yay`/`paru`), así no tienes que
aprender sintaxis nueva — ambas funcionan:

| estilo pacman | equivalente |
|---------------|-------------|
| `vouch -Syu` | actualización completa: `pacman -Syu` (repos) **y luego** `vouch upgrade` (AUR) |
| `vouch -S <pkg…>` | instalar — los targets de repos van a `pacman -S`, los del AUR por `vouch install` |
| `vouch -Ss <query>` | busca en repos (`pacman -Ss`) **y** en el AUR (`vouch search`) |
| `vouch -Sy` | refresca las bases de datos de sincronización |
| `vouch -R…`, `-Q…`, `-U…`, `-F…`, `-T…`, `-D…` | se pasan directo a `pacman` |

`-h`/`--help` y `-V`/`--version` siempre muestran la ayuda/versión de vouch.

## Dónde se guarda el estado

- Aprobaciones de revisión (TOFU): `$XDG_DATA_HOME/vouch/reviews/` (por defecto `~/.local/share/vouch/reviews/`).
- Feed de IoC del usuario: `$XDG_DATA_HOME/vouch/ioc.json`.
