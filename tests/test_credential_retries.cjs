'use strict';
// Run the actual browser credential prompt + SSH connect functions from app.js,
// proving a rejected saved password cannot be silently replayed forever.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const js=fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8');
function section(start,end) {
  const a=js.indexOf(start),b=js.indexOf(end,a);
  assert(a>=0&&b>a, 'Missing shipped function: '+start);
  return js.slice(a,b);
}
const credential=section('function discardRejectedPassword(aid) {','\nfunction initMachineWorkspace()');
const prompt=js.match(/async function promptPassword\(asset,[^\n]+\}/);
assert(prompt,'Shipped promptPassword wrapper missing');
const connect=section('async function connect(aid, {newSession = false} = {}) {','\nfunction renderTabs()');
let prompts=0, opened=0, counter=0;
const panels=new Map(),sockets=[],shown=[];
const asset={id:'machine-1',host:'192.168.0.6',username:'root',label:'Test',auth_type:'interactive',has_saved_password:true};
const state={assets:[asset],machineHost:asset.host,tabs:new Map(),currentTab:null,sessionPasswords:new Map(),failedAuthAssets:new Set()};
class Socket {
  static CONNECTING=0; static OPEN=1; static CLOSING=2; static CLOSED=3;
  constructor(){this.readyState=0;this.sent=[];sockets.push(this);}
  send(value){this.sent.push(JSON.parse(value));}
  connected(){this.readyState=1;this.onopen?.();}
  notify(message){this.onmessage?.({data:JSON.stringify(message)});}
  disconnected(){this.readyState=3;this.onclose?.();}
}
class Terminal{
  constructor(){this.cols=80;this.rows=25;this.events={};}
  loadAddon(){}
  open(){opened++;}
  onData(cb){this.events.data=cb;}
  onResize(cb){this.events.resize=cb;}
  write(){} writeln(){}
}
const context=vm.createContext({state,WebSocket:Socket,
 window:{Terminal,FitAddon:{FitAddon:class{fit(){}}}},
 askDialog:async options=>{prompts++;shown.push(options.title);return prompts===1?'correct-password':'updated-password';},
 clientSessionId:()=> 'session-'+(++counter),navigate:()=>{},updateTerminalStatus:()=>{},
 renderTabs:()=>{for(const id of state.tabs.keys())panels.set('#term-'+id,{})},
 '$':q=>panels.get(q),toast:()=>{},selectTab:id=>{state.currentTab=id;},
 location:{protocol:'http:',host:'192.168.0.19:9791'},encodeURIComponent,JSON,Error});
vm.runInContext(credential+'\n'+prompt[0]+'\n'+connect,context);
(async()=>{
 const first=await context.connect(asset.id);
 assert.equal(prompts,0,'first attempt should use encrypted saved password');
 assert.equal(state.tabs.size,1);
 sockets[0].connected();
 assert.equal(sockets[0].sent[0].password,'');
 sockets[0].notify({type:'error',code:'ssh_auth_rejected',message:'SSH authentication rejected. Check saved password.'});
 sockets[0].disconnected();
 assert(state.failedAuthAssets.has(asset.id),'rejected password must be invalidated');
 assert.equal(state.tabs.get(first).authFailed,true);
 const second=await context.connect(asset.id);
 assert.equal(first,second,'retry must reuse existing terminal tab');
 assert.equal(opened,1,'retry must not create a second terminal');
 assert.equal(prompts,1,'retry must prompt for replacement');
 assert.match(shown[0],/Retry SSH/);
 sockets[1].connected();
 assert.equal(sockets[1].sent[0].password,'correct-password');
 sockets[1].notify({type:'connected'});
 assert(!state.failedAuthAssets.has(asset.id),'successful authentication clears rejected state');
 sockets[1].disconnected();
 await context.connect(asset.id);
 assert.equal(prompts,1,'accepted temporary override must beat stale saved password');
 sockets[2].connected();
 assert.equal(sockets[2].sent[0].password,'correct-password');
 sockets[2].notify({type:'error',code:'ssh_auth_rejected',message:'SSH authentication rejected.'});
 sockets[2].disconnected();
 await context.connect(asset.id);
 assert.equal(prompts,2,'a new rejection must clear temporary password too');
 assert.equal(state.tabs.size,1,'all retries should use the same tab');
 sockets[3].connected();
 assert.equal(sockets[3].sent[0].password,'updated-password');
 console.log('PASS: saved-password rejection -> same-tab prompt -> valid override -> password expiration');
})().catch(error=>{console.error(error);process.exitCode=1;});