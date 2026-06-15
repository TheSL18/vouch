# Preguntas frecuentes (Español)

**¿`vouch` reemplaza a `yay` / `paru`?**
Todavía no. Cubre audit, build, install y un upgrade de la capa AUR, pero no es un
front-end completo de pacman. Convive con tu helper actual.

**¿Modifica mi sistema?**
Solo `vouch install` / `vouch upgrade` llaman a `pacman` (con `sudo`), y piden
confirmación antes. `audit` y `--dry-run` no tocan nada.

**Un paquete legítimo que confío sale marcado. ¿Es un falso positivo?**
`vouch` *expone* patrones riesgosos; no afirma que sean maliciosos. Un hook
`.install` personalizado, por ejemplo, se muestra como nota MEDIUM pero suele
quedar VOUCHED. Lo revisas una vez — el trust-on-first-use se queda callado hasta
que el recipe cambie.

**Mi paquete sí necesita red durante `build()` (electron/npm).**
Usa `--allow-build-network`. Es por-paquete, el paquete se sigue vetando, la
decisión se recuerda para el recipe sin cambios, y se imprime un aviso de
aislamiento reducido. El default sigue cerrado.

**¿Por qué un paquete se compiló en vez de tomarse de un repo (o viceversa)?**
`vouch` le pregunta a `libalpm` si algún repositorio configurado puede satisfacer
la dependencia. Si tienes un repo binario como `chaotic-aur`, los paquetes que
provee se usan desde ahí (firmados) en vez de recompilarse desde el AUR.

**El sandbox de build no arranca.**
Necesita user namespaces sin privilegios y `bubblewrap`. Si no se puede establecer
un sandbox, `vouch` se niega a compilar en lugar de hacerlo sin aislar — por diseño.

**¿Cómo actualizo los indicadores de threat intel?**
`vouch ioc --import <file.json>` mergea un feed JSON (p.ej. una lista comunitaria
como `aur-malware-check`) en tus indicadores locales en `$XDG_DATA_HOME/vouch/ioc.json`.

**Cambié de opinión sobre un paquete que avalé.**
`vouch forget <pkg>` borra la aprobación guardada y re-arma el trust-on-first-use.

**¿Puedo forzar un veredicto REFUSED?**
`--force`, si entiendes del todo los hallazgos. Imprime una advertencia clara.
Existe para casos expertos raros, no para uso rutinario.

**¿Qué significan los códigos de salida?**
`0` vouched · `1` review requerido · `2` refused · `3` error. Útiles para scripts.
