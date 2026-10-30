'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const js=fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8');
const start=js.indexOf('async function connect(aid, {newSession = false} = {}) {');
const end=js.indexOf('\nfunction renderTabs()',start);
assert(start>=0&&end>start,'Real connect implementation required');
const panels=new Map(),sockets=[];let sequence=0,opened=0,listeners=0,prompts=0;
class Sock{
 static CONNECTING=0;static OPEN=1;static CLOSING=2;static CLOSED=3;
 constructor(url){this.url=url;this.readyState=0;this.sent=[];sockets.push(this);}
 send(data){this.sent.push(JSON.parse(data));}
 connected(){this.readyState=1;this.onopen?.();}
 disconnected(){this.readyState=3;this.onclose?.();}
}
class Terminal{
 constructor(){this.cols=80;this.rows=25;this.events={};}
 loadAddon(){} open(){opened++;}
 onData(f){this.events.data=f;listeners++;}
 onResize(f){this.events.resize=f;listeners++;}
 write(){} writeln(){}
}
const state={tabs:new Map(),assets:[{id:'a',host:'192.168.0.6',label:'Test',auth_type:'interactive'}],currentTab:null};
const context=vm.createContext({state,WebSocket:Sock,window:{Terminal,FitAddon:{FitAddon:class{fit(){}}}},
 promptPassword:async()=>{prompts++;return 'test-password';},
 clientSessionId:()=>`tab-${++sequence}`,navigate:()=>{},updateTerminalStatus:()=>{},
 renderTabs:()=>{for(const id of state.tabs.keys())panels.set('#term-'+id,{});},
 '$':q=>panels.get(q),toast:()=>{},selectTab:id=>{state.currentTab=id;},
 location:{protocol:'http:',host:'192.168.0.19:9791'},encodeURIComponent,JSON,Error});
vm.runInContext(js.slice(start,end),context);
(async()=>{
 const connect=context.connect;const first=await connect('a');
 assert.equal(state.tabs.size,1);assert.equal(opened,1);assert.equal(listeners,2);
 sockets[0].connected();
 assert.equal(sockets[0].sent[0].password,'test-password');
 assert.equal(await connect('a'),first);assert.equal(prompts,1);
 sockets[0].disconnected();
 const same=await connect('a');
 assert.equal(same,first);assert.equal(state.tabs.size,1);assert.equal(opened,1);assert.equal(listeners,2);
 sockets[1].connected();
 state.tabs.get(first).terminal.events.data('pwd\n');
 assert.equal(sockets[1].sent.at(-1).data,'pwd\n');
 sockets[0].onclose();assert.equal(state.tabs.get(first).ws,sockets[1]);
 const second=await connect('a',{newSession:true});
 assert.notEqual(second,first);assert.equal(state.tabs.size,2);assert.equal(opened,2);
 console.log('PASS: SSH reconnect reuses tab/socket listeners; explicit New session creates second tab');
})().catch(e=>{console.error(e);process.exitCode=1;});
