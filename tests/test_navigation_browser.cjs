'use strict';
// Exercise the shipped navigate function under a minimal DOM, not a copy.
// Regressions that call forEach on querySelector fail here.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8');
const start = source.indexOf('function navigate(page) {');
const end = source.indexOf('\nfunction renderQuick()', start);
assert(start >= 0 && end > start, 'navigate function must be present');
const selectors = source.split('\n').slice(0,3).join('\n');
function element(id,page='') {
  const classes=new Set();
  return {id,dataset:{page},textContent:'',value:'',
    classList:{
      toggle:(name,on)=>{if(on)classes.add(name);else classes.delete(name);},
      contains:name=>classes.has(name),
    }};
}
const pages=['machine','files','runbooks','settings'].map(p=>element('page-'+p));
const nav=['machines','activity','settings'].map(p=>element('nav-'+p,p));
const fields=new Map([['#bread',element('bread')],['#fileAsset',element('fileAsset')]]);
const document={
  querySelector:s=>s==='.nav-item'?nav[0]:s==='.page'?pages[0]:(fields.get(s)||null),
  querySelectorAll:s=>s==='.nav-item'?nav:s==='.page'?pages:[],
};
const calls=[];let connected=true;
const context=vm.createContext({
  document,
  state:{page:'machine',machineHost:'192.168.0.6',currentTab:null},
  updateMachineHeader:()=>calls.push('machine-header'),
  syncWorkspaceChrome:()=>calls.push('chrome'),
  renderWorkbenchSessions:()=>calls.push('sessions'),
  machineTitle:()=> 'Test',
  machineAsset:()=>({id:17}),
  MACHINE_TOOL_PAGES:new Set(['files','docker','services','health','runbooks']),
  authenticatedSSHForHost:()=>connected?{authenticated:true}:null,
  toast:msg=>calls.push('warning: '+msg),
  refreshRunbooks:async()=>calls.push('runbooks'),
  browseFiles:async()=>calls.push('files'),
  showError:e=>{throw e;},
});
vm.runInContext(selectors+'\n'+source.slice(start,end),context);
const navigate=vm.runInContext('navigate',context);
for(const [route,navRoute] of [['machine','machines'],['runbooks','runbooks'],['files','files']]) {
  assert.doesNotThrow(()=>navigate(route),'No uncaught navigation exception: '+route);
  assert.equal(pages.filter(p=>!p.classList.contains('hidden')).length,1);
  assert.equal(pages.find(p=>!p.classList.contains('hidden')).id,'page-'+route);
  assert.deepEqual(nav.filter(b=>b.classList.contains('active')).map(b=>b.dataset.page),
    navRoute==='machines'?['machines']:[]);
}
assert.equal(fields.get('#fileAsset').value,17);
navigate('machine');connected=false;
navigate('files');
assert.equal(pages.find(p=>!p.classList.contains('hidden')).id,'page-machine',
  'Disconnected machines must not enter the Files tool');
assert(calls.some(x=>x.startsWith('warning: ')));
assert(calls.includes('machine-header') && calls.includes('sessions'));
console.log('PASS: machine/runbook/files navigation updates nav states without exceptions');
