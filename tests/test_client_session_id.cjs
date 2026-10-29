// Browser ID regression: crypto.randomUUID is unavailable on HTTP LAN origins.
// Evaluate the exact shipped function, without duplicating its implementation.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8');
const match = source.match(/function clientSessionId\(\)\s*\{[\s\S]*?\n\}/);
assert(match, 'Client session ID function must be present');
assert(!/(?:^|\W)crypto\.randomUUID\s*\(/m.test(source.replace(/\/\*[\s\S]*?\*\//g,'')), 'No session workflow may call randomUUID directly');
const runtime = {
  crypto: {getRandomValues: webcrypto.getRandomValues.bind(webcrypto)},
  Uint8Array, Array, Error,
};
const newId = vm.runInNewContext(match[0]+'\nclientSessionId',runtime);
const seen = new Set();
for (let n=0; n<10000; n++) {
  const id = newId();
  assert.match(id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert(!seen.has(id),'CSPRNG collision');
  seen.add(id);
}
assert.equal(seen.size,10000);
assert.throws(() => vm.runInNewContext(match[0]+'\nclientSessionId()', {crypto:{},Uint8Array,Array,Error}),/cryptographically secure/);
console.log('PASS: LAN HTTP-compatible, CSPRNG-backed session IDs (10,000 unique, RFC4122 v4)');
