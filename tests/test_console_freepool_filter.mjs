import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const read = name => fs.readFileSync(new URL('../vps/fanout/' + name, import.meta.url), 'utf8');
const section = (text, a, b) => text.slice(text.indexOf(a), text.indexOf(b, text.indexOf(a)));
const html = read('console.html');

// The candidate filter bar offers the source dropdown with both sources.
assert.match(html, /<select id="sourceFilter" aria-label="筛选来源">/);
assert.match(html, /<option value="vpngate">VPN Gate<\/option>/);
assert.match(html, /<option value="freepool">免费池<\/option>/);
assert.match(html, /\$\("sourceFilter"\)\.addEventListener\("change", renderNodes\)/, 'sourceFilter has no change listener');

// Candidate rows badge freepool nodes and give passed freepool rows a
// direct promote action, separate from the VPN Gate replace dialog.
assert.match(html, /来源 · 免费池/, 'freepool badge missing from candidate rows');
assert.match(html, /data-action="promoteFreePool"/, 'freepool promote action missing');
assert.match(html, /api\("api\/freepool\/promote"/, 'promote action does not call the freepool API');

// FreePool rows are excluded from the manual third-party list but stay
// visible (labelled) on the exit management cards.
const thirdSection = section(html, '      function renderThirdParties()', '      async function refreshThirdParties()');
assert.match(thirdSection, /p\.source !== "freepool"/, 'manual third-party list does not exclude freepool rows');
const managedSection = section(html, '      function renderManagedExits()', '      function poolRefreshFeedback(');
assert.match(managedSection, /免费池 · SOCKS5/, 'managed exit cards do not label freepool entries');

// Source filtering on the candidates page, combined with the existing
// search / country / status / type filters.
const fields = {
  search: { value: '' },
  countryFilter: { value: '' },
  statusFilter: { value: '' },
  typeFilter: { value: '' },
  sourceFilter: { value: '' },
};
const results = {
  'a.example': { status: 'passed' },
  'fp-1.2.3.4-1080': { status: 'passed' },
  'fp-5.6.7.8-1080': { status: 'not_tested' },
};
const filterContext = vm.createContext({
  $: id => fields[id],
  nodes: [
    { hostname: 'a.example', ip: '9.9.9.9', country_code: 'JP' },
    { hostname: 'fp-1.2.3.4-1080', ip: '1.2.3.4', country_code: 'JP', source: 'freepool' },
    { hostname: 'fp-5.6.7.8-1080', ip: '5.6.7.8', country_code: 'US', source: 'freepool' },
  ],
  nodeResult: n => results[n.hostname] || { status: 'not_tested' },
  country: code => code || '',
});
vm.runInContext(section(html, '      function filteredNodes()', '      function renderNodes()'), filterContext);
const hosts = () => filterContext.filteredNodes().map(n => n.hostname);
assert.deepEqual(hosts(), ['a.example', 'fp-1.2.3.4-1080', 'fp-5.6.7.8-1080']);
fields.sourceFilter.value = 'freepool';
assert.deepEqual(hosts(), ['fp-1.2.3.4-1080', 'fp-5.6.7.8-1080']);
fields.sourceFilter.value = 'vpngate';
assert.deepEqual(hosts(), ['a.example'], 'vpngate filter must keep nodes without a source');
fields.sourceFilter.value = 'freepool';
fields.countryFilter.value = 'US';
assert.deepEqual(hosts(), ['fp-5.6.7.8-1080'], 'source and country filters must intersect');
fields.countryFilter.value = '';
fields.statusFilter.value = 'passed';
assert.deepEqual(hosts(), ['fp-1.2.3.4-1080'], 'source and status filters must intersect');
console.log('console freepool source filter regressions passed');
