---
name: todo-tracking-reconciliation
description: Use when reviewing or updating SBOM Manager TODO scope across progress files, session logs, and stale domain checklists.
version: 1.0.0
author: SBOM Manager Team
license: MIT
metadata:
  hermes:
    tags: [todo, progress, tracking, project-management]
    related_skills: [sbom-manager-analysis]
---

# TODO Tracking Reconciliation

## Overview
The repo contains multiple historical task lists. The authoritative active scope is root `tasks/progress.json.active_todo`, mirrored for humans in `tasks/todo/TODO_TRACKING.md`.

## Procedure
1. Read root `tasks/progress.json` and `tasks/done/SESSION_LOG.md` first.
2. Search for unchecked `- [ ]`, `TODO`, `future_todo`, and `pending` entries.
3. Classify each item as active, completed, deferred, or stale.
4. Update `tasks/progress.json.active_todo` with structured fields: `id`, `title`, `status`, `priority`, `area`, `source`, `current_state`, `next_step`.
5. Mirror active/deferred status into `tasks/todo/TODO_TRACKING.md`.
6. Append a dated reconciliation entry to `tasks/done/SESSION_LOG.md`.

## Pitfalls
- Domain `CLAUDE.md` files may be stale after implementation milestones.
- Early `.plan.md` files may show all-pending even when the repo is already implemented.
- Never merge stale and active scope without labeling the evidence.

## Verification Checklist
- [ ] `python -m json.tool tasks/progress.json` passes.
- [ ] `tasks/todo/TODO_TRACKING.md` matches `tasks/progress.json.active_todo`.
- [ ] Deferred items are preserved but not treated as active scope.
