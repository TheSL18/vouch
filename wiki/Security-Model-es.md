# Modelo de seguridad (Español)

`vouch` asume que el AUR es **no confiable por defecto**. El mantenedor de un
paquete puede cambiar, una cuenta puede ser comprometida, y un recipe ejecuta
código arbitrario en tu máquina tanto al compilar *como* al instalar. `vouch`
encadena capas independientes para que ningún bypass aislado baste, y elimina el
peor default: la ejecución silenciosa.

## Las capas

### 1. Señales de confianza
Derivadas de los metadatos del AUR: paquetes huérfanos (la puerta de entrada de
"Atomic Arch"), recién adoptados, con pocos votos, actualizados hace muy poco,
marcados out-of-date. Ninguna es prueba de malicia; juntas elevan la necesidad de
revisión.

### 2. Análisis conductual
Análisis de patrones en `PKGBUILD` y `.install` buscando técnicas vistas en
ataques de cadena de suministro: `npm`/`bun`/`pip install` al compilar,
`curl | bash`, hooks eBPF / `getdents64` (rootkits), blobs ofuscados en base64,
bits setuid, persistencia (cron, units de systemd, archivos rc de shell,
autostart), descargas desde hosts efímeros o IPs crudas, borrado del historial.

### 3. Análisis estructural
Entiende los cuerpos de las funciones de shell, así que el contexto importa: una
llamada de red dentro de `build()`/`package()` (las fuentes van en el array
`source=()` con checksum) se marca, y cada hook `.install` se expone porque pacman
lo ejecuta **como root**.

### 4. Inteligencia de amenazas (IoC)
Compara los recipes contra indicadores *conocidos como maliciosos* en vez de
comportamiento: los nombres npm del payload de Atomic Arch, más cuentas de
mantenedor baneadas, nombres de paquete secuestrados, strings/dominios maliciosos
y hashes de archivos. Los indicadores vienen con una base compilada y se pueden
ampliar con feeds comunitarios (`vouch ioc --import`). Cualquier match es
`Critical`. Esto caza un payload conocido aunque se referencie de forma indirecta
y las reglas conductuales no se disparen.

### 5. Sandbox de build (enforcement en ejecución)
El scanner es informativo y se puede engañar con ofuscación; el sandbox no. Las
compilaciones corren dentro de **bubblewrap** con sistema de solo lectura, un único
directorio de build escribible, todos los namespaces aislados y —lo clave— la
**red aislada durante `build()`/`package()`**. Las fuentes se descargan y se
verifican por checksum en una fase aparte con red. Un recipe que intente
`npm install` o `curl | bash` un payload durante el build simplemente **no tiene
ruta de salida**. Si no se puede establecer un sandbox, `vouch` se niega a
compilar en lugar de caer a un build sin aislar.

### 6. Trust-on-first-use (TOFU)
El momento más peligroso de Atomic Arch no fue la primera instalación, sino la
*actualización* maliciosa a un paquete que ya confiabas. `vouch` guarda el
contenido exacto del recipe que avalaste. Un recipe sin cambios se recompila con
baja fricción; uno que **cambió** te detiene y muestra un diff de exactamente qué
cambió antes de re-aprobar. Un recipe legítimo y personalizado es así una revisión
de una sola vez, no un fastidio constante.

## Scoring y decisiones

Los hallazgos se ponderan por severidad en un score 0–100; **cada regla cuenta una
vez**, así que un paquete legítimo que (por ejemplo) symlinkea seis timers de
systemd no se va a REFUSED por repetición. Un solo hallazgo `Critical` rechaza de
inmediato. Si no: `< 25` → vouched, `25–59` → review requerido, `≥ 60` → refused.

## Vetado de todo el árbol

En una instalación se veta **cada** paquete AUR del grafo de dependencias, no solo
el que escribiste. Una dependencia transitiva es igual de capaz de cargar un
payload.

## Repo-vs-AUR preciso (libalpm)

`vouch` le pregunta a `libalpm` si algún repositorio configurado puede satisfacer
una dependencia (manejando provides, restricciones de versión y sonames, a través
de repos de terceros como `chaotic-aur`/`cachyos`). Si existe un binario firmado,
se prefiere sobre recompilar desde el AUR — acorde a tu configuración real de
confianza.

## Limitaciones honestas

- Las compilaciones usan `--nodeps`; las make-dependencies deben estar ya presentes.
- `--force` y `--allow-build-network` son válvulas de escape: explícitas, logueadas
  y por-paquete, pero relajan garantías por elección tuya.
- El scanner estático es una heurística. Es una capa; el sandbox y el TOFU son las
  que aguantan aun cuando el scanner sea engañado.
