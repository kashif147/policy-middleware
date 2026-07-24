# Build and deploy model

Every consuming service installs this package as
`"@membership/policy-middleware": "git+https://github.com/kashif147/policy-middleware.git#gateway"`
in its `package.json` — the `#gateway` branch is what's actually deployed from. `package.json`'s own
`publishConfig` points at GitHub Packages, but there is no `.github/workflows/` here and nothing
publishes there — **the git-dependency-on-a-branch model is the real deployment mechanism, not the
npm registry.**

```bash
npm run build       # build:cjs + build:esm — regenerates dist/ and dist/esm/ from src/
npm run build:cjs   # scripts/build-cjs.js — copies src/*.js -> dist/*.js verbatim
npm run build:esm   # scripts/build-esm.js — regex-converts src/*.js (CJS) -> dist/esm/*.js (ESM)
```

`npm test` and `npm run lint` are no-op stubs (`echo "..."`) — there is no test suite; don't invent
a single-test command for either.

**`src/` is the only thing you ever edit.** `dist/` and `dist/esm/` are fully generated but are
committed to git (not gitignored) — because consuming services install this package straight from
the `#gateway` branch via git URL, editing `src/` without running `npm run build` and committing the
result means every consuming service keeps pulling the *old* compiled behavior on its next
`npm install`, silently. `BUILD_PROCESS_EXPLANATION.md` covers this same point in more detail — read
it before touching anything under `dist/`.

**The ESM build is a regex transform, not a real transpiler**: `scripts/build-esm.js` pattern-matches
`const X = require("...")` and `module.exports = {...}` via regex and rewrites them to
`import`/`export` syntax — it does not parse JavaScript beyond those two shapes. If you add a
`require()` or `module.exports` statement to `src/*.js` that doesn't match those exact patterns
(e.g. multiple `module.exports` assignments, `require()` inside a function body, destructured or
computed requires), the ESM build silently produces broken or unconverted output. Always inspect the
generated `dist/esm/*.js` after `npm run build` — don't assume it compiled correctly just because
the script exited without an error.

## Not hook-enforced — attempted, and why it was skipped

The "commit `src/` and `dist/` together" rule above is **not** mechanically enforced by
`.claude/hooks/enforce-hard-rules.mjs`, unlike the platform's other hard rules. This was
deliberately attempted and abandoned in the same session that built the other hooks, not simply
overlooked:

- Every other check in that hook fires on a single `Write`/`Edit` call and inspects that one file's
  new content — a self-contained, easily pipe-testable mechanism (see the hook script's own
  comments and the git history for how each check was verified against real files before being
  wired in).
- This rule instead needs to know whether `src/*.js` and `dist/*.js` changed *together in the same
  git commit*, which means hooking `git commit` itself (a `Bash` matcher) rather than a file edit —
  a genuinely different mechanism.
- Building that safely required confirming what working directory the hook subprocess actually sees
  when a `Bash` command runs from a different `cd`'d location than the project root (needed to
  know which repo's `git commit` is actually being run). A temporary probe hook to verify this
  empirically was blocked by Claude Code's auto-mode safety classifier — reasonably so, since "log
  every subsequent Bash command's cwd to a file" is exactly the shape of a self-surveillance
  mechanism a classifier should be cautious about, independent of the actual (benign) intent.
- Without that verification, a commit-blocking hook couldn't be held to the same "pipe-tested, zero
  false positives against real files" bar as the other checks, so it wasn't built rather than
  shipping something unverified.

If this is revisited: get explicit user sign-off on adding a `Bash`-matcher hook first (the
classifier block is a signal to ask, not a hard wall), verify the cwd behavior with something less
persistent-looking than a standing log (e.g. a single one-shot echo tied to a specific, narrow `if`
permission-rule match rather than every `Bash` call), then implement the check as: for a `git
commit` command whose resolved repo is `policy-middleware` or `rabbitmq-middleware`, run `git diff
--cached --name-only` and deny if it contains a `src/*.js` path with no corresponding `dist/`
change.
