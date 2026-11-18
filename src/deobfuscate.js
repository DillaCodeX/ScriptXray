#!/usr/bin/env node
'use strict';
/**
 * Fast AST-based JavaScript deobfuscator.
 *
 * Usage:  node deobfuscate.js input.js -o output.js [--no-rename] [--keep-unused] [--stats]
 *
 * Handles (obfuscator.io-style and most generic obfuscators):
 *   - hex / unicode escapes, hex numbers
 *   - constant folding  (!![] , 0x1+0x2 , 'a'+'b' ...)
 *   - string-array + decoder + rotation IIFE  (run in a vm sandbox, calls replaced by literals)
 *   - proxy objects / proxy functions  (o.add(a,b) -> a+b , o.str -> 'str')
 *   - control-flow flattening  ('3|1|0'.split('|') + switch loop)
 *   - dead branches, sequence expressions, a['b'] -> a.b
 *   - unused helper cleanup, readable renaming of _0x1234 identifiers
 *
 * Variable/function names that were minified away cannot be recovered; only structure can.
 *
 * SECURITY: the string-array prelude is executed in node:vm. vm is NOT a hard security
 * boundary. Run this tool inside a container/VM when analysing untrusted samples.
 */
const fs = require('fs');
const vm = require('vm');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types');

const IDENT = /^[A-Za-z_$][\w$]*$/;
const fresh = () => traverse.cache.clear();

const isPure = (n) =>
  !n ||
  (t.isLiteral(n) && !t.isTemplateLiteral(n)) ||
  t.isFunction(n) ||
  (t.isIdentifier(n) && n.name === 'undefined') ||
  (t.isArrayExpression(n) && n.elements.every((e) => e && isPure(e))) ||
  (t.isObjectExpression(n) &&
    n.properties.every((p) => t.isObjectProperty(p) && !p.computed && isPure(p.value))) ||
  (t.isCallExpression(n) &&
    t.isMemberExpression(n.callee) &&
    t.isStringLiteral(n.callee.object) &&
    t.isIdentifier(n.callee.property, { name: 'split' }) &&
    n.arguments.every((a) => t.isStringLiteral(a)));

/* ---------- pass: normalise literals (drop raw so \x61 / 0x1f print plainly) ---------- */
function normalizeLiterals(ast) {
  t.traverseFast(ast, (n) => {
    if ((n.type === 'StringLiteral' || n.type === 'NumericLiteral') && n.extra) {
      delete n.extra.raw;
      delete n.extra.rawValue;
    }
  });
}

/* ---------- pass: constant folding + dead branches ---------- */
function toNode(v) {
  if (typeof v === 'string') return v.length < 100000 ? t.stringLiteral(v) : null;
  if (typeof v === 'boolean') return t.booleanLiteral(v);
  if (v === null) return t.nullLiteral();
  if (typeof v === 'number' && Number.isFinite(v)) {
    return v < 0 || Object.is(v, -0) ? t.unaryExpression('-', t.numericLiteral(-v)) : t.numericLiteral(v);
  }
  return null;
}

function fold(ast) {
  fresh();
  let changed = 0;
  traverse(ast, {
    'BinaryExpression|UnaryExpression': {
      exit(path) {
        const n = path.node;
        if (t.isUnaryExpression(n)) {
          if (n.operator === 'void') return;
          if (n.operator === '-' && t.isNumericLiteral(n.argument)) return;
        }
        const r = path.evaluate();
        if (!r.confident) return;
        const node = toNode(r.value);
        if (node) {
          path.replaceWith(node);
          changed++;
        }
      },
    },
    LogicalExpression: {
      exit(path) {
        const { operator } = path.node;
        if (operator === '??') return;
        const l = path.get('left').evaluate();
        if (!l.confident) return;
        const keepRight = operator === '&&' ? !!l.value : !l.value;
        path.replaceWith(keepRight ? path.node.right : path.node.left);
        changed++;
      },
    },
    ConditionalExpression: {
      exit(path) {
        const r = path.get('test').evaluate();
        if (!r.confident) return;
        path.replaceWith(r.value ? path.node.consequent : path.node.alternate);
        changed++;
      },
    },
    IfStatement(path) {
      const r = path.get('test').evaluate();
      if (!r.confident) return;
      if (r.value) path.replaceWith(path.node.consequent);
      else if (path.node.alternate) path.replaceWith(path.node.alternate);
      else path.remove();
      changed++;
    },
    DebuggerStatement(path) {
      path.remove();
      changed++;
    },
  });
  return changed;
}

/* ---------- pass: a['b'] -> a.b, split sequence statements ---------- */
function cosmetic(ast) {
  fresh();
  let changed = 0;
  traverse(ast, {
    MemberExpression(path) {
      const { node } = path;
      if (node.computed && t.isStringLiteral(node.property) && IDENT.test(node.property.value)) {
        node.computed = false;
        node.property = t.identifier(node.property.value);
        changed++;
      }
    },
    ExpressionStatement(path) {
      const e = path.node.expression;
      if (t.isSequenceExpression(e) && (path.parentPath.isBlockStatement() || path.parentPath.isProgram())) {
        path.replaceWithMultiple(e.expressions.map((x) => t.expressionStatement(x)));
        changed++;
      }
    },
    EmptyStatement(path) {
      if (path.parentPath.isBlockStatement() || path.parentPath.isProgram()) {
        path.remove();
        changed++;
      }
    },
    'ReturnStatement|ThrowStatement|BreakStatement|ContinueStatement'(path) {
      if (!Array.isArray(path.container)) return;
      for (const s of [...path.getAllNextSiblings()].reverse()) {
        if (s.isFunctionDeclaration() || s.isVariableDeclaration({ kind: 'var' })) continue;
        s.remove();
        changed++;
      }
    },
  });
  return changed;
}

/* ---------- pass: string array + decoder + rotation ---------- */
const litArg = (a) =>
  t.isStringLiteral(a) || t.isNumericLiteral(a)
    ? a.value
    : t.isUnaryExpression(a) && a.operator === '-' && t.isNumericLiteral(a.argument)
    ? -a.argument.value
    : undefined;

const idsIn = (node) => {
  const s = new Set();
  t.traverseFast(node, (n) => {
    if (n.type === 'Identifier') s.add(n.name);
  });
  return s;
};

function resolveStringArray(ast, done) {
  fresh();
  let changed = 0;
  traverse(ast, {
    Program(programPath) {
      programPath.stop();
      const program = programPath.node;

      // 1. find decoder: top-level function called most often with literal args
      let best = null;
      for (const [name, b] of Object.entries(programPath.scope.bindings)) {
        if (done.has(name)) continue;
        const ok =
          b.path.isFunctionDeclaration() ||
          (b.path.isVariableDeclarator() && b.path.get('init').isFunction());
        if (!ok) continue;
        let n = 0;
        for (const ref of b.referencePaths) {
          const p = ref.parentPath;
          if (
            p.isCallExpression() &&
            p.node.callee === ref.node &&
            p.node.arguments.length >= 1 &&
            p.node.arguments.length <= 3 &&
            p.node.arguments.every((a) => litArg(a) !== undefined)
          )
            n++;
        }
        if (n >= 3 && (!best || n > best.n)) best = { name, n, binding: b };
      }
      if (!best) return;
      done.add(best.name);

      // 2. gather prelude statements the decoder depends on (+ rotation IIFEs)
      const top = program.body;
      const declIdx = new Map();
      top.forEach((s, i) => {
        for (const nm of Object.keys(t.getBindingIdentifiers(s))) declIdx.set(nm, i);
      });
      if (!declIdx.has(best.name)) return;
      const needed = new Set([declIdx.get(best.name)]);
      let grew = true;
      while (grew) {
        grew = false;
        top.forEach((s, i) => {
          if (needed.has(i)) {
            for (const nm of idsIn(s)) {
              const j = declIdx.get(nm);
              if (j !== undefined && !needed.has(j)) {
                needed.add(j);
                grew = true;
              }
            }
          } else if (t.isExpressionStatement(s)) {
            let e = s.expression;
            if (t.isUnaryExpression(e)) e = e.argument;
            if (!t.isCallExpression(e) || !t.isFunction(e.callee)) return;
            if (!e.arguments.some((a) => t.isNumericLiteral(a))) return;
            const refsNeeded = e.arguments.some((a) =>
              [...idsIn(a)].some((nm) => declIdx.has(nm) && needed.has(declIdx.get(nm)))
            );
            if (refsNeeded) {
              needed.add(i);
              grew = true;
            }
          }
        });
      }
      const idxs = [...needed].sort((a, b) => a - b);
      const prelude = idxs.map((i) => top[i]);
      const code = generate(t.file(t.program(prelude.map((n) => t.cloneNode(n, true))))).code;

      // 3. run it in a sandbox
      let fn;
      try {
        const ctx = vm.createContext({});
        vm.runInContext(code, ctx, { timeout: 5000 });
        fn = vm.runInContext(best.name, ctx);
        if (typeof fn !== 'function') return;
      } catch (e) {
        process.stderr.write(`[warn] decoder ${best.name} could not be evaluated: ${e.message}\n`);
        return;
      }

      // 4. replace decoder calls with their literal results
      const replaced = new Set();
      programPath.traverse({
        CallExpression(p) {
          const { callee, arguments: args } = p.node;
          if (!t.isIdentifier(callee, { name: best.name })) return;
          if (p.scope.getBinding(best.name) !== best.binding) return;
          const vals = args.map(litArg);
          if (vals.some((v) => v === undefined)) return;
          let v;
          try {
            v = fn(...vals);
          } catch {
            return;
          }
          if (typeof v !== 'string') return;
          replaced.add(callee);
          p.replaceWith(t.stringLiteral(v));
          changed++;
        },
      });

      // 5. drop the prelude if nothing else uses it
      const neededNodes = new Set(prelude);
      let safe = true;
      for (const nm of idxs.flatMap((i) => Object.keys(t.getBindingIdentifiers(top[i])))) {
        const b = programPath.scope.getBinding(nm);
        if (!b) continue;
        for (const ref of b.referencePaths) {
          if (replaced.has(ref.node)) continue;
          const stmt = ref.find((p) => p.parentPath && p.parentPath.isProgram());
          if (!stmt || !neededNodes.has(stmt.node)) safe = false;
        }
      }
      if (safe) {
        for (const sp of programPath.get('body')) if (neededNodes.has(sp.node)) sp.remove();
      }
    },
  });
  return changed;
}

/* ---------- pass: proxy objects  var o = {a:'x', f:function(a,b){return a+b}} ---------- */
function inlineProxyObjects(ast) {
  fresh();
  let changed = 0;
  traverse(ast, {
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (!t.isIdentifier(id) || !t.isObjectExpression(init) || !init.properties.length) return;
      const binding = path.scope.getBinding(id.name);
      if (!binding || binding.constantViolations.length) return;

      const props = new Map();
      for (const p of init.properties) {
        if (!t.isObjectProperty(p) || p.computed) return;
        const key = t.isIdentifier(p.key) ? p.key.name : t.isStringLiteral(p.key) ? p.key.value : null;
        if (key === null) return;
        const v = p.value;
        if (t.isStringLiteral(v) || t.isNumericLiteral(v)) props.set(key, { fn: false, node: v });
        else if (
          t.isFunctionExpression(v) &&
          v.params.every((x) => t.isIdentifier(x)) &&
          v.body.body.length === 1 &&
          t.isReturnStatement(v.body.body[0]) &&
          v.body.body[0].argument
        )
          props.set(key, { fn: true, node: v });
        else return;
      }

      const keyOf = (m) =>
        !m.computed && t.isIdentifier(m.property)
          ? m.property.name
          : m.computed && t.isStringLiteral(m.property)
          ? m.property.value
          : null;

      // every reference must be a read of a known key
      for (const ref of binding.referencePaths) {
        const m = ref.parentPath;
        if (!m.isMemberExpression() || m.node.object !== ref.node) return;
        const k = keyOf(m.node);
        if (k === null || !props.has(k)) return;
        const gp = m.parentPath;
        if (gp.isAssignmentExpression({ left: m.node }) || gp.isUpdateExpression() || gp.isUnaryExpression({ operator: 'delete' }))
          return;
        const entry = props.get(k);
        if (entry.fn && !(gp.isCallExpression() && gp.node.callee === m.node)) return;
        if (entry.fn) {
          const ps = entry.node.params.map((p) => p.name);
          const args = gp.node.arguments;
          if (args.length < ps.length || args.some((a) => t.isSpreadElement(a))) return;
          const expr = entry.node.body.body[0].argument;
          const uses = Object.fromEntries(ps.map((p) => [p, 0]));
          t.traverseFast(expr, (n) => {
            if (n.type === 'Identifier' && n.name in uses) uses[n.name]++;
          });
          for (let i = 0; i < ps.length; i++) {
            const simple = t.isLiteral(args[i]) || t.isIdentifier(args[i]);
            if (uses[ps[i]] > 1 && !simple) return;
          }
        }
      }

      // rewrite (scope-limited traversal, inner-first)
      const same = (p, name) => p.scope.getBinding(name) === binding;
      binding.scope.path.traverse({
        CallExpression: {
          exit(p) {
            const c = p.node.callee;
            if (!t.isMemberExpression(c) || !t.isIdentifier(c.object, { name: id.name }) || !same(p, id.name)) return;
            const entry = props.get(keyOf(c));
            if (!entry || !entry.fn) return;
            const ps = entry.node.params.map((x) => x.name);
            const map = new Map(ps.map((nm, i) => [nm, p.node.arguments[i]]));
            const body = t.cloneNode(entry.node.body.body[0].argument, true);
            const wrapper = t.expressionStatement(body);
            t.traverseFast(wrapper, () => {});
            const out = substitute(body, map);
            p.replaceWith(out);
            changed++;
          },
        },
        MemberExpression: {
          exit(p) {
            const n = p.node;
            if (!t.isIdentifier(n.object, { name: id.name }) || !same(p, id.name)) return;
            const entry = props.get(keyOf(n));
            if (!entry || entry.fn) return;
            p.replaceWith(t.cloneNode(entry.node));
            changed++;
          },
        },
      });
      path.remove();
    },
  });
  return changed;
}

function substitute(expr, map) {
  const clone = (n) => t.cloneNode(n, true);
  const walk = (node) => {
    if (t.isIdentifier(node) && map.has(node.name)) return clone(map.get(node.name));
    for (const key of t.VISITOR_KEYS[node.type] || []) {
      const v = node[key];
      if (Array.isArray(v)) node[key] = v.map((c) => (c && c.type ? walkChild(node, key, c) : c));
      else if (v && v.type) node[key] = walkChild(node, key, v);
    }
    return node;
  };
  const walkChild = (parent, key, child) => {
    // do not rewrite non-computed property names / non-computed keys
    if (t.isMemberExpression(parent) && key === 'property' && !parent.computed) return child;
    if (t.isObjectProperty(parent) && key === 'key' && !parent.computed) return child;
    return walk(child);
  };
  return walk(expr);
}

/* ---------- pass: control-flow unflattening ---------- */
function unflatten(ast, force) {
  fresh();
  let changed = 0;
  traverse(ast, {
    'WhileStatement|ForStatement'(path) {
      const { node } = path;
      if (node.test) {
        const r = path.get('test').evaluate();
        if (!(r.confident && r.value)) return;
      }
      if (!t.isBlockStatement(node.body)) return;
      const stmts = node.body.body;
      const sw = stmts[0];
      if (!t.isSwitchStatement(sw)) return;
      if (stmts.length > 2 || (stmts.length === 2 && !t.isBreakStatement(stmts[1]))) return;
      const d = sw.discriminant;
      if (
        !(
          t.isMemberExpression(d) &&
          d.computed &&
          t.isIdentifier(d.object) &&
          t.isUpdateExpression(d.property, { operator: '++', prefix: false }) &&
          t.isIdentifier(d.property.argument)
        )
      )
        return;
      const orderName = d.object.name;
      const idxName = d.property.argument.name;
      const ob = path.scope.getBinding(orderName);
      if (!ob || !ob.path.isVariableDeclarator()) return;
      const oi = ob.path.node.init;
      let order;
      if (
        t.isCallExpression(oi) &&
        t.isMemberExpression(oi.callee) &&
        t.isStringLiteral(oi.callee.object) &&
        t.isIdentifier(oi.callee.property, { name: 'split' }) &&
        t.isStringLiteral(oi.arguments[0])
      )
        order = oi.callee.object.value.split(oi.arguments[0].value);
      else if (t.isArrayExpression(oi) && oi.elements.every((e) => t.isStringLiteral(e) || t.isNumericLiteral(e)))
        order = oi.elements.map((e) => String(e.value));
      else return;

      const map = new Map();
      for (const c of sw.cases) {
        if (!c.test || !(t.isStringLiteral(c.test) || t.isNumericLiteral(c.test))) return;
        const body = [...c.consequent];
        const last = body[body.length - 1];
        if (t.isContinueStatement(last) && !last.label) body.pop();
        else if (!(t.isReturnStatement(last) || t.isThrowStatement(last))) return;
        map.set(String(c.test.value), body);
      }
      const out = [];
      for (const k of order) {
        const b = map.get(k);
        if (!b) return;
        out.push(...b);
      }
      if (out.length) path.replaceWithMultiple(out);
      else path.remove();
      force.add(orderName);
      force.add(idxName);
      changed++;
    },
  });
  return changed;
}

/* ---------- pass: remove unused pure declarations ---------- */
function removeUnused(ast, force, keepTopLevel) {
  fresh();
  let changed = 0;
  traverse(ast, {
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (!t.isIdentifier(id) || !isPure(init)) return;
      const b = path.scope.getBinding(id.name);
      if (!b || b.referenced || b.constantViolations.length) return;
      const isTop = path.scope.path.isProgram();
      if (isTop && keepTopLevel && !force.has(id.name)) return;
      path.remove();
      changed++;
    },
    FunctionDeclaration(path) {
      if (!path.node.id) return;
      const b = path.scope.parent && path.scope.parent.getBinding(path.node.id.name);
      if (!b || b.referenced || b.constantViolations.length) return;
      if (path.parentPath.isProgram() && keepTopLevel) return;
      path.remove();
      changed++;
    },
  });
  return changed;
}

/* ---------- pass: readable renaming of _0x1234 style identifiers ---------- */
function renameMangled(ast) {
  fresh();
  const counters = { p: 0, fn: 0, v: 0 };
  const mangled = /^_0x[0-9a-fA-F]+$/;
  traverse(ast, {
    Scope(path) {
      for (const [name, b] of Object.entries(path.scope.bindings)) {
        if (!mangled.test(name)) continue;
        const kind = b.kind === 'param' ? 'p' : b.path.isFunctionDeclaration() ? 'fn' : 'v';
        let nn;
        do nn = kind + ++counters[kind];
        while (path.scope.hasBinding(nn) || path.scope.hasGlobal(nn));
        path.scope.rename(name, nn);
      }
    },
  });
}

/* ---------- driver ---------- */
function deobfuscate(code, opts = {}) {
  const ast = parser.parse(code, {
    sourceType: 'unambiguous',
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowSuperOutsideMethod: true,
    errorRecovery: true,
  });
  const stats = {};
  const force = new Set();
  const decoded = new Set();
  const add = (k, v) => (stats[k] = (stats[k] || 0) + v);

  normalizeLiterals(ast);
  for (let i = 0; i < 10; i++) {
    let c = 0;
    let n;
    c += n = fold(ast); add('folded', n);
    c += n = resolveStringArray(ast, decoded); add('decodedStrings', n);
    c += n = inlineProxyObjects(ast); add('proxiesInlined', n);
    c += n = cosmetic(ast); add('cosmetic', n);
    c += n = unflatten(ast, force); add('unflattened', n);
    c += n = removeUnused(ast, force, !!opts.keepUnused); add('removedUnused', n);
    if (!c) break;
  }
  if (!opts.noRename) renameMangled(ast);
  const out = generate(ast, { comments: true, compact: false, jsescOption: { minimal: true } }).code;
  return { code: out, stats };
}

module.exports = { deobfuscate };

if (require.main === module) {
  const args = process.argv.slice(2);
  const input = args.find((a) => !a.startsWith('-') && args[args.indexOf(a) - 1] !== '-o');
  if (!input) {
    console.error('usage: node deobfuscate.js input.js [-o output.js] [--no-rename] [--keep-unused] [--stats]');
    process.exit(1);
  }
  const oi = args.indexOf('-o');
  const outFile = oi >= 0 ? args[oi + 1] : input.replace(/\.js$/, '') + '.deobf.js';
  const t0 = process.hrtime.bigint();
  const { code, stats } = deobfuscate(fs.readFileSync(input, 'utf8'), {
    noRename: args.includes('--no-rename'),
    keepUnused: args.includes('--keep-unused'),
  });
  fs.writeFileSync(outFile, code);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.error(`done in ${ms.toFixed(0)} ms -> ${outFile}`);
  if (args.includes('--stats')) console.error(stats);
}
