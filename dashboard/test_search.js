#!/usr/bin/env node
/* Regression tests for the dashboard's tolerant search helpers. */
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

const html = fs.readFileSync(__dirname + '/index.html', 'utf8');
function extract(name) {
  const start = html.indexOf('function ' + name + '(');
  assert(start >= 0, 'missing function ' + name);
  let depth = 0, seenBrace = false;
  for (let i = start; i < html.length; i++) {
    if (html[i] === '{') { depth++; seenBrace = true; }
    else if (html[i] === '}') {
      depth--;
      if (seenBrace && depth === 0) return html.slice(start, i + 1);
    }
  }
  throw new Error('unterminated function ' + name);
}

const code = extract('normalizeSearchText') + '\n' + extract('itemMatchesSearch');
const ctx = {};
vm.createContext(ctx);
vm.runInContext(code, ctx);

assert.strictEqual(ctx.normalizeSearchText('Gemini 3.8 Flash'), 'gemini38flash');
assert.strictEqual(ctx.normalizeSearchText('gemini-3_8'), 'gemini38');
assert(ctx.itemMatchesSearch({title: 'Gemini 3.8 Flash 发布'}, 'gemini3.8'));
assert(ctx.itemMatchesSearch({title: '其他', summary: '谷歌上新 Gemini-3.8 Flash'}, 'gemini 3 8'));
assert(ctx.itemMatchesSearch({title: '其他', platform_name: 'The Verge AI'}, 'vergeai'));
assert(!ctx.itemMatchesSearch({title: 'Gemini 3.7 Flash'}, 'gemini3.8'));
console.log('search normalization tests OK');
