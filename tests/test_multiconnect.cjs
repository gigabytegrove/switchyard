'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const source=fs.readFileSync(path.join(root,'static/app.js'),'utf8');
const html=fs.readFileSync(path.join(root,'static/index.html'),'utf8');
const css=fs.readFileSync(path.join(root,'static/style.css'),'utf8');
const start=source.indexOf('function terminalLayoutSelection() {');
const end=source.indexOf('function applyTerminalLayout() {',start);
assert(start>=0&&end>start,'Actual multi-host terminal layout selection must be present');
assert(html.includes('<option value="1">Single</option>'));
assert(html.includes('<option value="2">Split 2</option>'));
assert(html.includes('<option value="4">Grid 4</option>'));
assert(css.includes('.terminal-panels.multiconnect'));
assert(css.includes('.terminal-host.multi-visible'));
assert(source.includes("connect(a.id,{newSession:true})"),'New SSH must open another session');
assert(source.includes("if(state.tabs.size===2&&!state.sessionDockDismissed)state.sessionDockOpen=true"));
const tabs=new Map([
  ['ssh-a',{asset:{host:'192.0.2.50'}}],
  ['ssh-b',{asset:{host:'192.0.2.51'}}],
  ['ssh-c',{asset:{host:'192.0.2.52'}}],
  ['ssh-d',{asset:{host:'192.0.2.53'}}]
]);
const state={tabs,currentTab:'ssh-b',terminalLayout:2,layoutSessionIds:[]};
const ctx=vm.createContext({state});
vm.runInContext(source.slice(start,end),ctx);
const select=vm.runInContext('terminalLayoutSelection',ctx);
function values(){return Array.from(select());}
assert.deepEqual(values(),['ssh-b','ssh-d'],'Two panes should display active and latest other host');
state.currentTab='ssh-d';
assert.deepEqual(values(),['ssh-b','ssh-d'],'Clicking pane must not swap its position');
state.currentTab='ssh-a';
assert.deepEqual(values(),['ssh-b','ssh-a'],'A newly selected tab joins the split without replacing first pane');
state.terminalLayout=4;
assert.deepEqual(values(),['ssh-b','ssh-a','ssh-d','ssh-c'],'Grid should contain four different SSH sessions');
tabs.delete('ssh-b');
state.currentTab='ssh-a';
assert.deepEqual(values(),['ssh-a','ssh-d','ssh-c'],'Closing a connection removes it from the layout');
state.terminalLayout=1;
assert.deepEqual(values(),['ssh-a'],'Single view retains active session only');
console.log('PASS: cross-host 2-up/4-up selection, stable pane ordering, close fallback, new session contract');
