# CLAUDE.md

Guidance for Claude Code in this repository.

The operating contract lives in [AGENTS.md](AGENTS.md) - the build/test
contract, the module boundaries the architecture tests enforce, the "add a
module" recipe, and the invariants to preserve. Read it first. Anything that
applies to every agent belongs in AGENTS.md, not here.

Claude-Code-specific notes:

- Run the build and tests exactly as AGENTS.md specifies (`export
  PATH="$HOME/.dotnet:$PATH"` first; the integration suite needs Docker).
- Warnings are errors and restore is locked, so a warning or a stale
  `packages.lock.json` fails the build - not a nag you can defer.
- This repo carries no `.claude/` commands or review-gate kit; that workflow
  lives in the companion `project-starter` template.
