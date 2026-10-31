---
name: subagent-watchdog
description: >
  Controles para detectar y recuperar subagentes T3 trabados (git stash colgado,
  comando eterno, hilo sin actividad). Usar al orquestar, delegar fases, o si el
  usuario pide watchdog, stuck agent, subagente colgado, /watchdog.
---

# Subagent watchdog

## Al delegar

- Preferí `isolation: "worktree"` para implementación. El checkout compartido permite que un `git stash` del niño pise o trabe al orquestador.
- En el brief del niño: prohibido `git stash -u` del árbol entero. WIP = commit en su rama.
- Guardá `taskId` y el `link` del hilo.
- Tras `delegate_task`, si `next` dice que el completion despierta este hilo, no hagas `task_status` en el mismo turno.

## Detección automática

Hay un `schedule_task` T3 en este proyecto, cada 3 min, bound al hilo orquestador.
Prompt canónico: `E:\projects\vulnRadar\.grok\watchdog-prompt.md`.
Estado: `E:\projects\vulnRadar\.grok\watchdog-state.json` (gitignored).

Si el schedule no existe, crealo:

- `title`: Watchdog subagentes
- `bindToCurrentThread`: true
- `schedule`: `{ type: "interval", everyMs: 180000 }`
- `prompt`: leer y ejecutar `watchdog-prompt.md`

## Si el watchdog cancela a un niño

1. `git stash list` y `git status` en el repo.
2. Recuperá stash de la fase si el árbol está limpio o el stash no pisa trabajo ajeno.
3. Pytest. Commit en la rama de la fase. No mergees sin revisión.
4. No relances el mismo `delegate_task` salvo que el trabajo no esté en el disco.

## Señales de trabado (resumen)

- `git stash` / `stash pop` running > 2 min → cancel
- `command_execution` running > 12 min → strike, luego cancel
- `updatedAt` viejo > 8 min en `running` → nudge, luego cancel
- `waiting` / pendingApproval → no cancelar
