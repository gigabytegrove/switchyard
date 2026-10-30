'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const root=path.join(__dirname,'..');
const source=fs.readFileSync(path.join(root,'static/app.js'),'utf8');
const html=fs.readFileSync(path.join(root,'static/index.html'),'utf8');
const css=fs.readFileSync(path.join(root,'static/style.css'),'utf8');
for(const key of ['id="machineLayout"','id="machineRailResize"','id="machineTreeToggle"'])
  assert(html.includes(key),key+' must exist in the actual UI');
assert(css.includes('#shell .machine-layout>.machine-context{'));
assert(css.includes('#shell .machine-layout>.machine-rail-resize{'));
assert(html.includes('id="treeClose"'));
assert(!html.includes('id="page-machines"'));
assert(html.includes('id="page-machine"'));
assert(css.includes('@media(max-width:540px)'));
const start=source.indexOf('const TREE_FOLD_KEY');
const end=source.indexOf('function renderMachineSwitcher()',start);
assert(start>=0&&end>start,'Real rail/folder functions must be present');
const storage=new Map();let renders=0;let navigated=[];
function fake(){
 const listeners=new Map(), classes=new Set(), attrs=new Map(), styles=new Map();
 return {
  dataset:{},value:'',focusCount:0,addEventListener:(name,fn)=>listeners.set(name,fn),
  fire:(name,event={})=>listeners.get(name)?.({button:0,pointerId:1,clientX:350,key:'',preventDefault(){},...event}),
  focus(){this.focusCount++;},select(){}, getBoundingClientRect(){return {left:0}},
  setPointerCapture(){},hasPointerCapture(){return false},releasePointerCapture(){},
  setAttribute:(k,v)=>attrs.set(k,v),getAttribute:k=>attrs.get(k),
  classList:{toggle:(k,v)=>{if(v===undefined)v=!classes.has(k);if(v)classes.add(k);else classes.delete(k);},contains:k=>classes.has(k),add:k=>classes.add(k),remove:k=>classes.delete(k)},
  style:{setProperty:(k,v)=>styles.set(k,v)},attrs,styles
 };
}
const ids=new Map(['#machineLayout','#machineRailResize','#machineTreeToggle','#machineSwitchSearch','#machineSwitcher','#treeClose','#machineBackToDirectory','#shell'].map(x=>[x,fake()]));
const windowHandlers=new Map();
const context=vm.createContext({
 window:{localStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v)},
   matchMedia:()=>({matches:false}),addEventListener:(k,fn)=>windowHandlers.set(k,fn)},
 document:{activeElement:null,querySelector:()=>null},
 '$':id=>ids.get(id),'$$':()=>[],renderMachineSwitcher:()=>{renders++;},
 navigate:page=>navigated.push(page),
});
vm.runInContext(source.slice(start,end),context);
vm.runInContext("setFolderFolded('folder1',true);setFolderFolded('folder2',true);setFolderFolded('folder1',false);initMachineRail();",context);
assert.equal(JSON.parse(storage.get('switchyard:folders:folded:v1')).join(','),'folder2');
assert.equal(renders,3);
const resize=ids.get('#machineRailResize');
assert.equal(resize.getAttribute('aria-valuenow'),'236');
resize.fire('keydown',{key:'ArrowRight'});
assert.equal(resize.getAttribute('aria-valuenow'),'292');
resize.fire('keydown',{key:'Home'});assert.equal(resize.getAttribute('aria-valuenow'),'196');
resize.fire('keydown',{key:'End'});assert.equal(resize.getAttribute('aria-valuenow'),'440');
resize.fire('dblclick');assert.equal(resize.getAttribute('aria-valuenow'),'236');
assert.equal(JSON.parse(storage.get('switchyard:directory:width:v1')),236);
ids.get('#machineTreeToggle').fire('click');
assert.equal(ids.get('#machineLayout').classList.contains('tree-open'),true);
assert.equal(ids.get('#machineTreeToggle').getAttribute('aria-expanded'),'true');
windowHandlers.get('keydown')({key:'Escape',preventDefault(){},target:{}});
assert.equal(ids.get('#machineLayout').classList.contains('tree-open'),false);
windowHandlers.get('keydown')({key:'k',ctrlKey:true,preventDefault(){},target:{}});
assert(navigated.includes('machine'));
assert(ids.get('#machineSwitchSearch').focusCount>0);
console.log('PASS: persisted folders, keyboard resize, reset, drawer and quick search');
