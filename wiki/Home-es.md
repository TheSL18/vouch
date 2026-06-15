# vouch — Wiki (Español)

**Un AUR helper con la seguridad primero: avala cada paquete antes de instalarlo.**

`vouch` es un helper del [AUR](https://aur.archlinux.org/) para Arch Linux con una
idea central: **nunca ejecutar un recipe que no hayas revisado.** Los helpers
clásicos compilan e instalan lo que el AUR les entregue; `vouch` veta primero y
rechaza lo que no puede avalar.

Nació como respuesta al ataque de cadena de suministro **"Atomic Arch"** de junio
de 2026, donde paquetes AUR secuestrados descargaban un payload npm malicioso
(`atomic-lockfile`, `js-digest`) que soltaba un infostealer y un rootkit eBPF.

## Páginas

- **[Uso](Usage-es)** — comandos, flags y flujos de trabajo.
- **[Modelo de seguridad](Security-Model-es)** — qué revisa cada capa y por qué.
- **[Preguntas frecuentes](FAQ-es)** — dudas comunes.

## Inicio rápido

```sh
git clone https://github.com/TheSL18/vouch
cd vouch
cargo build --release
./target/release/vouch audit <paquete>
```

```console
$ vouch audit alguna-app-aur        # solo lectura: fetch + vetado + veredicto
$ vouch install alguna-app-aur      # resuelve + veta el árbol + build en sandbox + instala
$ vouch upgrade                     # -Syu de la capa AUR
```

## Requisitos

`vouch` es una herramienta de Arch Linux. Al compilar enlaza **libalpm**; en
ejecución usa **bubblewrap** (sandbox), **makepkg** y **pacman**. Para el sandbox
de build hacen falta user namespaces sin privilegios habilitados.

## Estado

Temprano pero funcional: audit, build (en sandbox), install (con vetado de todo el
árbol), upgrade, feeds de IoC y trust-on-first-use están implementados. Mira el
[roadmap](https://github.com/TheSL18/vouch#roadmap) para lo que sigue.
