# Watchdog de subagentes (vulnRadar)

Sos un turno automático del orquestador. NO implementes features del producto.
NO arranques un `delegate_task` nuevo. NO hagas git stash. NO merges a master.

## Objetivo

Detectar subagentes trabados y actuar. El caso que ya nos pasó: Pi hizo `git stash -u` en el checkout compartido y se quedó colgado; el trabajo quedó en el stash.

## Alcance

1. `t3_thread_list` con `includeSubagents=true`, statuses `running`, `waiting`, `queued`, `starting`.
2. Ignorá el hilo padre `07b70fd3-14bd-4631-8053-f4927d3d8ff0` (este orquestador).
3. Sólo hilos con `relationshipToParent = subagent` (o cuyo `threadId` empiece con `thread:delegated-task:`).

## Estado persistente

Archivo: `E:\projects\vulnRadar\.grok\watchdog-state.json` (gitignored).
Forma:

```json
{
  "checkedAt": "ISO-8601",
  "agents": {
    "<threadId>": {
      "strikes": 0,
      "lastSeenUpdatedAt": "...",
      "lastAction": "ok|nudge|cancel",
      "reason": ""
    }
  }
}
```

Leelo si existe. Borra entradas de hilos que ya no estén running/waiting.

## Umbrales (ahora UTC)

| Señal | Umbral | Acción |
|---|---|---|
| `pendingApproval` o pregunta pendiente | — | no tocar, reportar |
| `command_execution` running cuyo texto/title contiene `git stash`, `stash pop`, `stash -u` | > 2 min | **cancel inmediato** |
| cualquier `command_execution` status=running | > 12 min | strike; al 2º **cancel** |
| hilo `running` y `updatedAt` sin cambio | > 8 min | strike + nudge; al 2º **cancel** |
| hilo `waiting` (aprobación humana) | — | no cancelar |

`taskId` del delegate MCP = el `threadId` cambiando el prefijo `thread:` → `node:`.

## Cómo inspeccionar

Para cada subagente sospechoso (`now - updatedAt` > 4 min, o status waiting):

1. `t3_thread_read` view=`activity`, `limit=8`, `maxCharsPerItem=800`. Si `hasMore`, pedí `afterPosition` cerca del final (itemCount-8).
2. Mirà el último item: `updatedAt`, `type`, `status`, `title`, `text`.
3. Clasificá: `ok` | `hung_stash` | `hung_command` | `stale` | `waiting_human`.

## Acciones

**ok:** strikes=0, no molestes al niño.

**hung_stash:** `task_cancel` con reason clara. Después `git stash list` en `E:\projects\vulnRadar`. Si hay stash de la rama de la fase, **no lo apliques** si el working tree tiene cambios ajenos; reportá `git stash list` y `git status --short`.

**nudge (primer strike stale/hung_command):**
`t3_thread_send` al child, `mode: "steer"`, mensaje:
"Watchdog: tu hilo no avanza. NO hagas git stash del árbol. Commiteá WIP en tu rama, o terminá y reportá. Si estás esperando red/API, escribí una línea de estado y seguí."

**cancel (segundo strike o hung_stash):**
`task_cancel` taskId, reason: "watchdog: subagente trabado (<clase>)".
Reportá el `link` verbatim del hilo.

## Informe (siempre, corto)

En este hilo orquestador, una lista:

- hilo `link` verbatim | status | edad de `updatedAt` | veredicto | acción
- Si todos ok: una línea `watchdog: N subagentes vivos, ninguno trabado`.

No inventes PRs. No toques código de Fase 3 salvo git status diagnóstico.
