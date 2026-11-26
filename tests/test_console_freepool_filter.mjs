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

// Candidate rows badge freepool nodes. Since v0.16.0 freepool rows use
// the same replace-dialog action as VPN Gate rows (promoteNode), gated
// on a passed check; the v0.15.0 direct promote special case is gone.
assert.match(html, /来源 · 免费池/, 'freepool badge missing from candidate rows');
assert.match(html, /data-action="promoteNode"/, 'shared promote dialog action missing');
assert.match(html, /n\.source === "freepool" && r\.status !== "passed"/, 'freepool promote must require a passed check');
assert.doesNotMatch(html, /promoteFreePool/, 'v0.15.0 freepool promote action still present');
assert.doesNotMatch(html, /api\/freepool\/promote/, 'v0.15.0 freepool promote API still called');

// Third-party rendering no longer special-cases freepool rows: the
// manual list shows every entry and managed exit cards use the plain
// custom-proxy label with an edit button for all entries.
const thirdSection = section(html, '      function renderThirdParties()', '      async function refreshThirdParties()');
assert.doesNotMatch(thirdSection, /source !== "freepool"/, 'manual third-party list still excludes freepool rows');
const managedSection = section(html, '      function renderManagedExits()', '      function poolRefreshFeedback(');
assert.doesNotMatch(managedSection, /免费池 · SOCKS5/, 'managed exit cards still special-label freepool entries');
assert.match(managedSection, /自定义 · SOCKS5/, 'managed exit cards lost the custom proxy label');

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
