import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const read = name => fs.readFileSync(new URL('../vps/fanout/' + name, import.meta.url), 'utf8');
const section = (text, a, b) => text.slice(text.indexOf(a), text.indexOf(b, text.indexOf(a)));
const html = read('console.html');

// The candidate filter bar offers the three iptest usage classes.
assert.match(html, /<select id="typeFilter" aria-label="筛选网络类型">/);
for (const v of ['优质网络', 'VPN', '代理'])
  assert.match(html, new RegExp('<option value="' + v + '">' + v + '</option>'), 'missing type option ' + v);
assert.match(html, /\["search", "countryFilter", "statusFilter", "typeFilter"\]/, 'typeFilter has no change listener');

// Exit cards only reveal the iptest line through the helpers.
assert.match(section(html, '      function exitCards(', '      function orderedThirdParties('), /exitIPTestLine\(e, checkState\)/, 'exit cards do not render the iptest line');
assert.match(section(html, '      function renderManagedExits()', '      function poolRefreshFeedback('), /thirdIPTestLine\(p, r\)/, 'managed third-party cards do not render the iptest line');

// Reveal gating: nothing shows before the exit's own check is clicked
// in this session, nothing shows while a check is running, and the
// line appears once a finished result carries iptest data.
const lineContext = vm.createContext({ esc: x => String(x ?? '') });
vm.runInContext(section(html, '      function iptestBand', '      const types = {'), lineContext);
const exitInfo = { kind: '家庭宽带', usage: '优质网络', composite: 5 };
assert.equal(lineContext.exitIPTestLine({ slot: 3 }, { status: 'passed', iptest: exitInfo }), '', 'exit iptest shown before its check was clicked');
vm.runInContext('revealedExitIPTest.add(3)', lineContext);
assert.equal(lineContext.exitIPTestLine({ slot: 3 }, { status: 'running' }), '', 'exit iptest shown while running');
assert.equal(lineContext.exitIPTestLine({ slot: 3 }, { status: 'failed' }), '', 'exit iptest shown without data');
assert.equal(
  lineContext.exitIPTestLine({ slot: 3 }, { status: 'passed', iptest: exitInfo }),
  '<small class="iptest-line">iptest 家庭宽带 · 优质网络 · 综合 5 极度纯净</small>',
);
assert.equal(lineContext.exitIPTestLine({ slot: 4 }, { status: 'passed', iptest: exitInfo }), '', 'unrelated exit revealed');

const thirdInfo = { kind: 'IDC 机房', usage: 'VPN', composite: 60 };
assert.equal(lineContext.thirdIPTestLine({ id: 7 }, { status: 'passed', iptest: thirdInfo }), '', 'third-party iptest shown before its check was clicked');
vm.runInContext('revealedThirdIPTest.add(7)', lineContext);
assert.equal(lineContext.thirdIPTestLine({ id: 7 }, { status: 'running', iptest: thirdInfo }), '', 'third-party iptest shown while running');
assert.equal(
  lineContext.thirdIPTestLine({ id: 7 }, { status: 'passed', iptest: thirdInfo }),
  '<small class="iptest-line">iptest IDC 机房 · VPN · 综合 60 中等风险</small>',
);

// Network-type filtering on the candidates page, combined with the
// existing search / country / status filters.
const fields = {
  search: { value: '' },
  countryFilter: { value: '' },
  statusFilter: { value: '' },
  typeFilter: { value: '' },
};
const results = {
  'a.example': { status: 'passed', iptest: { kind: '家庭宽带', usage: '优质网络', composite: 5 } },
  'b.example': { status: 'passed', iptest: { kind: 'IDC 机房', usage: 'VPN', composite: 60 } },
  'c.example': { status: 'passed', iptest: { kind: 'IDC 机房', usage: '代理', composite: 70 } },
  'd.example': { status: 'not_tested' },
  'e.example': { status: 'passed', iptest: { kind: 'IDC 机房', usage: 'Tor', composite: 90 } },
};
const filterContext = vm.createContext({
  $: id => fields[id],
  nodes: [
    { hostname: 'a.example', ip: '1.1.1.1', country_code: 'JP' },
    { hostname: 'b.example', ip: '2.2.2.2', country_code: 'US' },
    { hostname: 'c.example', ip: '3.3.3.3', country_code: 'US' },
    { hostname: 'd.example', ip: '4.4.4.4', country_code: 'KR' },
    { hostname: 'e.example', ip: '5.5.5.5', country_code: 'JP' },
  ],
  nodeResult: n => results[n.hostname] || { status: 'not_tested' },
  country: code => code || '',
});
vm.runInContext(section(html, '      function filteredNodes()', '      function renderNodes()'), filterContext);
const hosts = () => filterContext.filteredNodes().map(n => n.hostname);
assert.deepEqual(hosts(), ['a.example', 'b.example', 'c.example', 'd.example', 'e.example']);
fields.typeFilter.value = '优质网络';
assert.deepEqual(hosts(), ['a.example']);
fields.typeFilter.value = 'VPN';
assert.deepEqual(hosts(), ['b.example']);
fields.typeFilter.value = '代理';
assert.deepEqual(hosts(), ['c.example']);
fields.countryFilter.value = 'JP';
assert.deepEqual(hosts(), [], 'type and country filters must intersect');
fields.countryFilter.value = '';
fields.search.value = 'b.ex';
assert.deepEqual(hosts(), [], 'search must still apply on top of the type filter');
fields.typeFilter.value = 'VPN';
assert.deepEqual(hosts(), ['b.example']);
console.log('console iptest reveal + network-type filter regressions passed');
