<div align="center">

# Node Coroner

**Turn a dead Node.js process into a short, evidence-backed incident report.**

[![License: MIT](https://img.shields.io/badge/license-MIT-2f6f4e?style=flat-square)](LICENSE)
![Node 22+](https://img.shields.io/badge/node-%3E%3D22-43853d?style=flat-square&logo=node.js&logoColor=white)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-555?style=flat-square)

</div>

When a Node.js process dies you're left with an exit code, some stderr and a hunch. Node Coroner reads what the process left behind and writes a short incident report: a timeline, the likely causes ranked cautiously, and a link from every claim back to the evidence behind it.

## What it does

- Reads a saved bundle of exit status, stderr and diagnostic reports
- Builds a timeline of the evidence
- Ranks likely causes, from heap exhaustion and unhandled rejections to native crashes and external kills, and links each one to its evidence
- Redacts secrets and environment values it finds in the text
- Writes text, Markdown or JSON

## Quick start

Requires Node.js 22 or newer. No `npm install` needed.

```sh
git clone https://github.com/REllwood/Node-Coroner.git
cd Node-Coroner
npm start -- analyse fixtures/oom.json
```

For a report you can paste into an incident ticket:

```sh
npm start -- analyse fixtures/external-termination.json --format markdown
```

The `fixtures` folder has a bundle for each kind of death: out of memory, uncaught exception, unhandled rejection, native crash, external termination and a clean exit. Run `npm start -- --help` for all options.

## Status

v0.1 analyses saved evidence. It doesn't watch a live process, read system logs or symbolicate native dumps. Next up are importers for container and process-manager logs, and comparing repeated crashes.

## Development

```sh
npm test        # analysis tests
npm run check   # tests plus syntax checks
```

## License

[MIT](LICENSE)
