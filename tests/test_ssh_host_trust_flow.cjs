'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const js=fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8');
const html=fs.readFileSync(path.join(__dirname,'../static/index.html'),'utf8');
for(const id of ['sshTrustDialog','sshTrustHost','sshTrustAlgorithm','sshTrustFingerprint','sshTrustApprove','sshTrustCancel','sshTrustClose']){
 assert(html.includes('id="'+id+'"'),'Missing trust dialog '+id);
}
function part(start,end){const a=js.indexOf(start),b=js.indexOf(end,a);assert(a>=0&&b>a,start);return js.slice(a,b);}
const code=part('function confirmSSHHostFingerprint(asset,key) {','\nfunction renderTabs()');
const elements=new Map(),sockets=[],calls=[],logs=[];
let opened=0,serial=0;
class Element{
 constructor(){this.textContent='';this.open=false;this.listeners=new Map();}
 addEventListener(type,fn){if(!this.listeners.has(type))this.listeners.set(type,new Set());this.listeners.get(type).add(fn);}
 removeEventListener(type,fn){this.listeners.get(type)?.delete(fn);}
 emit(type){for(const f of [...(this.listeners.get(type)||[])])f({preventDefault(){}});}
 showModal(){this.open=true;}close(){this.open=false;this.emit('close');}focus(){}
}
const $=s=>{if(!elements.has(s))elements.set(s,new Element());return elements.get(s);};
class Socket{
 static CONNECTING=0;static OPEN=1;static CLOSED=3;
 constructor(){this.readyState=0;this.sent=[];sockets.push(this);}
 send(s){this.sent.push(JSON.parse(s));}
 opened(){this.readyState=1;this.onopen?.();}
 notify(msg){this.onmessage?.({data:JSON.stringify(msg)});}
 close(){this.readyState=3;this.onclose?.();}
}
class Terminal{
 constructor(){this.cols=80;this.rows=24;}
 loadAddon(){}open(){opened++;}onData(){}onResize(){}
 write(x){logs.push(x);}writeln(x){logs.push(x);}
}
const a={id:'one',host:'192.168.0.19',port:22,label:'Server',auth_type:'interactive',has_saved_password:true};
const b={...a,id:'two',host:'192.168.0.6'},c={...a,id:'three',host:'192.168.0.7'};
const state={assets:[a,b,c],tabs:new Map(),currentTab:null};
let key={host:a.host,port:22,key_type:'ssh-ed25519',public_key:'AQID',fingerprint:'SHA256:'+'A'.repeat(43)};
const ctx=vm.createContext({state,WebSocket:Socket,window:{Terminal,FitAddon:{FitAddon:class{fit(){}}}},'$':$,
 api:async (url,opt)=>{calls.push(url);if(url==='/hosts/discover')return key;if(url==='/hosts/trust')return {ok:true};throw Error(url);},
 promptPassword:async()=>'',clientSessionId:()=> 'tab-'+(++serial),navigate:()=>{},updateTerminalStatus:()=>{},
 renderTabs:()=>{for(const id of state.tabs.keys())elements.set('#term-'+id,new Element());},
 toast:()=>{},selectTab:id=>{state.currentTab=id;},
 location:{protocol:'http:',host:'192.168.0.19:9791'},encodeURIComponent,Number,JSON,Promise,Error});
vm.runInContext(code,ctx);
const tick=()=>new Promise(r=>setImmediate(r));
async function flush(){await tick();await tick();}
(async()=>{
 const first=await ctx.connect(a.id);
 sockets[0].opened();sockets[0].notify({type:'error',code:'ssh_host_unknown',message:'SSH host is not trusted'});
 await flush();
 assert($('#sshTrustDialog').open,'Unknown SSH host must open modal');
 assert.equal($('#sshTrustFingerprint').textContent,key.fingerprint);
 assert.equal($('#sshTrustHost').textContent,'192.168.0.19:22');
 assert.equal(calls.filter(x=>x==='/hosts/trust').length,0,'No automatic trust');
 $('#sshTrustApprove').emit('click');await flush();
 assert.equal(calls.filter(x=>x==='/hosts/trust').length,1);
 assert.equal(state.tabs.size,1,'No extra SSH tabs allowed');
 assert.equal(opened,1,'Keep same terminal');
 assert.equal(state.currentTab,first);
 assert.equal(sockets.length,2,'Must reconnect after approval');
 sockets[1].opened();
 const second=await ctx.connect(b.id);
 key={...key,host:b.host};
 sockets[2].opened();sockets[2].notify({type:'error',code:'ssh_host_unknown',message:'SSH host is not trusted'});
 await flush();assert($('#sshTrustDialog').open);
 $('#sshTrustCancel').emit('click');await flush();
 assert.equal(calls.filter(x=>x==='/hosts/trust').length,1);
 assert.equal(sockets.length,3,'Cancel cannot reconnect');
 const third=await ctx.connect(c.id);
 sockets[3].opened();sockets[3].notify({type:'error',code:'ssh_host_changed',message:'SSH host key changed'});
 await flush();
 assert(!$('#sshTrustDialog').open,'Changed key must not offer one-click trust');
 assert(logs.some(s=>s.includes('SECURITY WARNING')));
 key={...key,host:c.host};
 sockets[3].notify({type:'error',code:'ssh_host_unknown',message:'SSH host is not trusted'});
 await flush();assert($('#sshTrustDialog').open);
 $('#sshTrustDialog').emit('cancel');await flush();
 assert(!$('#sshTrustDialog').open);
 assert.equal(calls.filter(x=>x==='/hosts/trust').length,1);
 console.log('PASS: fingerprint dialog, explicit trust, same-tab retry, cancel, Escape, changed-host warning');
})().catch(e=>{console.error(e);process.exitCode=1;});
