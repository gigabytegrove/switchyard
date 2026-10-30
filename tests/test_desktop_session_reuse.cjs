'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8');
const start=source.indexOf('async function openDesktop(record, {retry = false, newSession = false} = {}) {');
const end=source.indexOf('\n/* SPICE uses',start);
assert(start>=0&&end>start,'Desktop reuse implementation required');
const record={id:'desk-a',protocol:'rdp',label:'Windows',auth_type:'vault'};
const tabs=new Map([['open',{id:'open',record,status:'Connected'}]]);
let selected=null,issued=0;
const context=vm.createContext({desktopTabs:tabs,selectDesktopTab:id=>selected=id,
 window:{Guacamole:{Client:class{},WebSocketTunnel:class{}}},
 api:async()=>{issued++;return {ticket:'one-use-token'};},Error,String});
vm.runInContext(source.slice(start,end),context);
(async()=>{
 assert.equal(await context.openDesktop(record),'open');
 assert.equal(selected,'open');assert.equal(tabs.size,1);assert.equal(issued,0);
 assert(source.includes("$('#desktopReconnect').addEventListener('click'"));
 assert(source.includes('if(existing && !newSession)closeDesktopTab(existing.id)'));
 console.log('PASS: selecting an open desktop focuses original viewer; reconnect action wired');
})().catch(e=>{console.error(e);process.exitCode=1;});
