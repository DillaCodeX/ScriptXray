# ScriptXray — JavaScript deobfuscator

Fast, AST-based JavaScript deobfuscator with two front ends that share one engine:

- **Web app** (`index.html`): static single page, runs entirely in the browser.
- **CLI** (`src/deobfuscate.js`): Node.js, built on Babel.

## What it does

- Decodes hex/unicode escapes and hex numbers
- Constant folding (`!![]`, `0x1 + 0x2`, `'a' + 'b'`)
- Resolves string arrays, decoder functions and rotation IIFEs (obfuscator.io style)
- Inlines proxy objects and helper functions (`o.add(a, b)` becomes `a + b`)
- Restores flattened control flow (`'3|1|0'.split('|')` plus `switch` loops)
- Removes dead code: constant branches, `debugger`, empty statements, unreachable code after `return`/`throw`/`break`/`continue`, unused helpers
- Turns `a['b']` into `a.b`, splits sequence statements
- Renames `_0x1a2b` identifiers to `v1`, `fn1`, `p1`

## Limits

- Original names removed by minifiers can't be recovered, only structure.
- VM-based obfuscators (JScrambler, JSVMP, jsfuck-style) are not supported.
- Opaque predicates (always-true conditions that aren't constant) are left in.
- The decoder must be a top-level function.

## CLI

```bash
npm install
node src/deobfuscate.js input.js -o output.js --stats
# options: --no-rename  --keep-unused
```

## Web app

Open `index.html` directly, or serve the folder:

```bash
npm run serve
```

Babel is loaded from jsDelivr (`@babel/standalone@7.26.4`) and fonts from Google Fonts. To work fully offline, download `babel.min.js` and point the `<script src>` at the local copy.

## Deploy on GitHub Pages

1. Push this repo to GitHub.
2. Settings → Pages → Source: **GitHub Actions**.
3. The included workflow (`.github/workflows/pages.yml`) publishes the site on every push to `main`.

## Security

String decoders are executed to recover strings: in the browser inside a sandboxed, network-less iframe with a timeout; in the CLI with Node's `vm`, which is **not** a security boundary. Analyse untrusted samples inside a container or disposable VM.

## License

MIT
