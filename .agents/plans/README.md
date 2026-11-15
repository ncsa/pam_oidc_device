# `.agents/plans/` — Feature Plans & Cross-Tool Handoffs

Active, multi-step implementation plans and handoff documents for in-flight work.

- **Naming:** `YYYY-MM-<short-feature>.md` (e.g. `2026-11-device-flow-refresh.md`).
- **Purpose:** replace one tool's private chat history with a shareable, tool-agnostic
  artifact so a planning agent and an implementation agent (possibly different tools) can
  hand off cleanly. A good plan states: the concrete interfaces / struct layouts, the
  config/schema changes, the test criteria (unit + e2e), and the verification gate set that
  must pass.
- **Lifecycle:** commit the plan while a feature branch is active; delete (or archive) it
  once the work is merged.
- **Read:** an implementation agent should read the plan first, then
  `AGENTS.md` → `.agents/context.md` → `.agents/memory.md`.
