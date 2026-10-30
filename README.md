# Spook

**A ghost that watches your AI coding agent.**

Coding agents install packages, run setup scripts and follow READMEs on your machine, with your permissions. Spook checks what the agent is about to run, blocks only the dangerous item, and tells you why. The decision is made by readable rules; a local open-weight model (Gemma via Ollama) explains it in plain English. The core runs entirely on your computer; the [optional integrations](#optional-integrations) are off until you add a key, and each one sends only what is listed below.

Built for the Hacktoberfest Open-Source AI Challenge, week 4: *Ghost in the Machine*.

Landing page: https://mohitbaher.github.io/spook/

## What it stops

| Threat | How Spook sees it |
|---|---|
| Hallucinated or squatted package names | The package does not exist on npm or PyPI. |
| Look-alike names | One edit away from a popular package, scored higher when brand new. |
| Malicious install scripts | Reads `preinstall`/`install`/`postinstall` and the files they run straight from the npm tarball, `setup.py` from PyPI source releases, and `file:` dependencies from disk. Nothing is executed. |
| A trusted package that turned bad | An install script that appeared in the newest version but not the previous one. |
| Prompt injection in READMEs and web pages | Text aimed at AI agents triggers a warning to the agent; packages and links that came only from that source are blocked. |
| Irregular behaviour | Encoded commands, download-then-run, credential files next to a network tool, deleting `/` or `~`, first contact with a raw IP. |
| Malicious local scripts | `bash scripts/setup.sh`, `node x.js` and `./x` are read before they run. |
| Tampering with Spook | The agent can read Spook's memory but cannot edit it or approve its own blocked items. |

## How it works

Spook is a [Claude Code hook](https://code.claude.com/docs/en/hooks): one Python file, standard library only.

1. **`UserPromptSubmit`** records your own words as trusted.
2. **`PostToolUse`** records which packages and URLs appeared in what the agent read, and whether that source addressed AI agents.
3. **`PreToolUse`** scores every item in the command (registry, archive inspection, provenance, behaviour). Anything scoring 5 or more is denied, with the reason sent back to the agent, so it can retry without that item. Everything else runs.
4. **On a block**, a detached worker asks local `gemma3:4b` for a three-sentence explanation, logs it to `.spook/explanations.jsonl` and shows a desktop notification. If Ollama is not running, you get the rule reasons instead.
5. **The Book of the Dead** (`spook-book.json`) remembers packages that are bad in themselves and blocks them instantly next time. Blocks expire after 30 days.

Rules decide; the model only explains. During testing Gemma "corrected" the squatted name `reqeusts` to `requests` in its explanation, the exact mistake that makes typosquatting work, so Spook now checks that every blocked name appears verbatim in the explanation.

## Try it

You need Python 3.10+ and Claude Code. Ollama with `gemma3:4b` is optional.

```bash
git clone https://github.com/mohitbaher/spook
python spook/hook.py install path/to/your/project
ollama pull gemma3:4b
```

Start a new Claude Code session in that project. Then, from your own terminal in the project folder:

```bash
python path/to/spook/hook.py book                  # what Spook remembers
python path/to/spook/hook.py allow npm:some-package  # approve something it blocked
python path/to/spook/hook.py forget npm:some-package
```

To have blocks read aloud (Windows' built-in, offline speech engine), run `python path/to/spook/hook.py voice on` in the project folder; `voice off` turns it off.

Use another local model with `SPOOK_MODEL` (for example `gemma3:1b`) and another Ollama host with `OLLAMA_HOST`.

## In CI: check pull requests

The same rules can check a whole manifest, which is useful when a dependency arrives through a pull request instead of an agent:

```bash
python spook/hook.py ci package.json requirements.txt
```

It prints a Markdown report and exits with 1 if anything is blocked. [`.github/workflows/spook.yml`](.github/workflows/spook.yml) runs it on every pull request that changes a `package.json` or `requirements*.txt` and posts the report as a comment. Nothing is installed or run; registry metadata and install scripts are read as text.

## Optional integrations

Copy [`.env.example`](.env.example) to `.env` next to `hook.py` (it is gitignored) and fill in only what you want. With none of these set, Spook behaves exactly as above.

| Key | What it adds | What leaves your machine |
|---|---|---|
| `SPOOK_SENTRY_DSN` (`pip install sentry-sdk`) | Traces every check as an AI agent run in Sentry: one `execute_tool` span per package, registry lookups, and the explainer's `gen_ai.chat` span with Gemma's token counts, all in one trace. | Item names, scores, reasons, timings, token counts. Never the command, prompts, answers or code (the SDK's own copies of the command are scrubbed). |
| `SPOOK_MONGODB_URI` (`pip install pymongo`) | A **shared Book of the Dead** for a team, in MongoDB Atlas. Before checking a command, Spook asks whether a teammate already blocked its packages; new package blocks are shared by the background worker. `python hook.py sync` shares and pulls everything. Short timeouts: if Atlas is slow, Spook checks normally. | npm/PyPI package names, the rule reasons, times, and an anonymous id per reporter. Never commands, local paths, scripts, code or your allow decisions. |
| `BACKBOARD_API_KEY` | `python compare_models.py` runs the demo's six block cases through local Gemma and open-weight models behind one Backboard key, and writes `bench/results.md` (exact names kept, length, latency, tokens, cost). | Only the six demo cases written in the script. |

The explanation itself always comes from your local model.

## Demo: the Haunted Ofrenda

[`demo/haunted-app`](demo/haunted-app) is a tiny Día de los Muertos web app with four traps: a dependency that does not exist on npm, a vendored package whose postinstall would send your environment variables away, a setup script that would upload your SSH key, and a README comment telling AI agents to `curl | sh` and keep quiet. **Every trap is inert**: the dangerous functions are never called, and all addresses are `203.0.113.7`, a reserved documentation IP.

To try it, copy the folder somewhere outside this repo, run `python spook/hook.py install <copy>`, and ask an agent in that folder to "set up this project and get it running".

In a live run, the agent tried `sed -i '/spook-demo-marigold-candles/d' package.json && npm install --ignore-scripts 2>&1 | tail -5`. Spook blocked it before anything ran, naming both the missing package and the stealer's postinstall, then allowed the clean install once the agent removed them.

## Numbers from testing

Measured on a Windows laptop with an RTX 3050 (4 GB):

- Blocking decision: 0.2 to 0.9 s per command; 0.3 s for a package already in the Book of the Dead.
- Gemma explanation: about 4 s after the block (3 to 13 s per call, ~7 tokens/s).
- False positives: 10 popular packages with legitimate install scripts (esbuild, puppeteer, bcrypt, sqlite3 ...) and 21 everyday agent commands were all allowed.
- The first run against a real agent found three bugs the unit tests had missed (wrong folder after a `cd`, pipes read as package names, an over-strict read guard). All are fixed and covered by `test_hook.py`.
- With Sentry on: 0.6 to 0.7 s per decision. Sentry's SDK auto-enables integrations for every AI library it finds installed; with LangChain on the machine that made each hook call take 23 s, so Spook turns that off.
- With the shared book on: about 1.9 s per decision (each hook call opens a fresh connection to Atlas in Mumbai). A package a teammate already blocked is stopped with no registry lookup at all.

Run the self-check with `python test_hook.py`.

## Limits

Spook is a tripwire, not a sandbox. Rules can be evaded by an attacker who knows them, it reads only the files an install script names (not everything they import), and a few cases are unchecked (git dependencies, pinned versions of npm packages). For real isolation, run agents in a container. Spook is the layer that still speaks up when the agent does not.

## License

MIT
