# AGENTS.md

Instructions for AI coding agents working in this repo. The project conventions,
data model and safety rules live in [CLAUDE.md](CLAUDE.md); read it first.

## Commits

- **Always use signed commits.** Create every commit with `git commit -S`
  (or make sure `commit.gpgsign=true` is set), and never use `--no-gpg-sign`.
- Check with `git log --show-signature -1` that the commit shows a good signature.
- If signing fails (no key, agent locked, pinentry unavailable), stop and tell
  the author. Do not fall back to an unsigned commit.
- Don't rewrite or force-push history to add signatures unless asked.
- Only commit or push when the author asks.

## Changelog and release notes

- Write `CHANGELOG.md` entries in the Toy Dolls voice: silly but competent, in
  the spirit of "Nellie the Elephant" (see Tone in [CLAUDE.md](CLAUDE.md)).
  Lead with what a user can now do, and keep every bullet accurate.
- Puns belong only in human-facing text such as the changelog, help text and
  success messages. Never put them in error messages, flag names, `--json`
  output or anything a script might parse.
- Versions live in `VERSION` (`MAJOR.MINOR.PATCH.MICRO`). Tag releases as
  `vMAJOR.MINOR.PATCH` with a signed tag (`git tag -s`).
