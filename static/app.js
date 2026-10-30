'use strict';
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = { page: 'machines', assets: [], folders: [], machineHost: null, tabs: new Map(), currentTab: null, editing: null, vaultItems: [], sessionPasswords: new Map(), failedAuthAssets: new Set() };
let toastTimer;
let dockerMode = 'containers';
let activeFileEdit = null;
let editingRunbookId = null;
let runbooks = [];
let auditBefore = null;
let auditFilter = '';
const sshProbeResults = new Map();

function toast(message, error = false) {
  const el = $('#toast'); el.textContent = message; el.className = error ? 'show error' : 'show';
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.className = '', 4200);
}
function node(tag, cls, content) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (content !== undefined) el.textContent = String(content);
  return el;
}
function button(label, cls, handler) {
  const el = node('button', cls, label); el.type = 'button'; el.addEventListener('click', handler); return el;
}
function showError(error) { toast(error?.message || 'The request failed.', true); }
/**
 * Browser-only session identifier. crypto.randomUUID() is not exposed by
 * Chromium on ordinary LAN HTTP (an insecure context), while getRandomValues()
 * remains available. Keep RFC 4122 v4 shape and CSPRNG strength in both cases.
 * IDs are view identifiers only; authorization remains server-side.
 */
function clientSessionId() {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    throw Error('This browser cannot provide cryptographically secure session IDs.');
  }
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
async function api(path, { method = 'GET', body, headers = {} } = {}) {
  const opts = { method, credentials: 'same-origin', headers: { ...headers } };
  if (body !== undefined) {
    if (body instanceof FormData) opts.body = body;
    else { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  }
  const response = await fetch('/api' + path, opts);
  if (response.status === 401) {
    const data = await response.json().catch(() => ({}));
    if (path !== '/login') setLogin();
    throw Error(typeof data.detail === 'string' ? data.detail : 'Authentication required');
  }
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    const detail = typeof data.detail === 'string' ? data.detail : 'Request failed (' + response.status + ')';
    const remoteAsset=/^\/assets\/([^/]+)\//.exec(path);
    if(remoteAsset && detail.startsWith('SSH authentication rejected'))discardRejectedPassword(remoteAsset[1]);
    throw Error(detail);
  }
  return response.headers.get('content-type')?.includes('application/json') ? response.json() : response;
}
let dialogResolve = null;
function askDialog({ title, description = '', label = '', value = '', secret = false, required = false, confirm = false, action = 'Continue' }) {
  if (dialogResolve) return Promise.reject(Error('Another dialog is already active'));
  const dialog = $('#inputDialog'), field = $('#inputDialogValue');
  $('#inputDialogTitle').textContent = title;
  $('#inputDialogDescription').textContent = description;
  $('#inputDialogLabel').classList.toggle('hidden', confirm);
  field.classList.toggle('hidden', confirm);
  field.type = secret ? 'password' : 'text'; field.required = required && !confirm;
  field.value = value; field.autocomplete = secret ? 'new-password' : 'off';
  $('#inputDialogSubmit').textContent = action;
  return new Promise(resolve => {
    dialogResolve = resolve; dialog.showModal();
    requestAnimationFrame(() => (confirm ? $('#inputDialogSubmit') : field).focus());
  });
}
function finishDialog(result) {
  const resolve = dialogResolve;
  if (!resolve) return;
  dialogResolve = null;
  $('#inputDialog').close();
  $('#inputDialogValue').value = '';
  resolve(result);
}
async function confirmAction(title, description, action = 'Confirm') {
  return (await askDialog({ title, description, confirm: true, action })) !== null;
}
function discardRejectedPassword(aid) {
  // Never automatically replay a password that SSH has rejected.
  const key=String(aid);
  state.sessionPasswords.delete(aid);
  state.sessionPasswords.delete(key);
  state.failedAuthAssets ??= new Set();
  state.failedAuthAssets.add(key);
}
async function promptCredential(asset, {force=false}={}) {
  if(!asset || asset.auth_type!=='interactive')return '';
  const rejected=force || state.failedAuthAssets?.has(String(asset.id));
  if(!rejected) {
    // An accepted temporary override must win over an older saved password.
    const cached=state.sessionPasswords.get(asset.id);
    if(cached!==undefined)return cached;
    if(asset.has_saved_password)return '';
  }
  const password=await askDialog({
    title:rejected?'Retry SSH with another password':'Connect to '+asset.label,
    description:rejected
      ? 'The SSH server rejected the previous login for '+asset.username+'@'+asset.host+'. Enter a different password. You can replace the stored credential in Edit machine.'
      : 'SSH password for '+asset.username+'@'+asset.host+'. It is held in browser memory until logout unless you save it in Edit machine.',
    label:'SSH password',secret:true,required:!!rejected,
    action:rejected?'Retry SSH connection':'Connect'
  });
  if(password!==null && password!=='')state.sessionPasswords.set(asset.id,password);
  return password;
}

function initMachineWorkspace() {
  for (const tab of ['terminals','desktops']) {
    const section = $('#page-' + tab), panel = $('#machinePanel-' + tab);
    section.classList.remove('page', 'hidden');
    section.classList.add('machine-subsection');
    panel.append(section);
  }
  const vault = $('#page-vault');
  vault.classList.remove('page', 'hidden'); vault.classList.add('integration-section');
  $('#settingsIntegrationsPanel').append(vault);
  for (const id of ['fileAsset','dockerAsset','healthAsset']) {
    const field = $('#' + id);
    field.closest('label')?.classList.add('machine-host-select');
    field.tabIndex = -1;
  }
  $('#inputDialogForm').addEventListener('submit', event => {event.preventDefault(); finishDialog($('#inputDialogLabel').classList.contains('hidden') ? '' : $('#inputDialogValue').value);});
  $('#inputDialogCancel').addEventListener('click', () => finishDialog(null));
  $('#inputDialogClose').addEventListener('click', () => finishDialog(null));
  $('#inputDialog').addEventListener('cancel', event => { event.preventDefault(); finishDialog(null); });
  $('#settingsGeneralTab').addEventListener('click', () => settingsTab('general'));
  $('#settingsIntegrationsTab').addEventListener('click', () => settingsTab('integrations'));
  $('#settingsUpdatesTab').addEventListener('click', () => settingsTab('updates'));
  $('#updateCheck').addEventListener('click', safeAsync(checkUpdateStatus));
  $('#updateConfigForm').addEventListener('submit', safeAsync(saveUpdateConfig));
  $('#updateInstall').addEventListener('click', safeAsync(installUpdate));
  $('#updateJobRefresh').addEventListener('click', safeAsync(refreshUpdateJob));
  $('#machineSearch').addEventListener('input', renderMachineDirectory);
  $('#machineEnvironment').addEventListener('change', renderMachineDirectory);
  $('#treeNewFolder').addEventListener('click', () => showFolderDialog());
  $('#treeNewMachine').addEventListener('click', () => openAsset());
  $('#machineInfoToggle').addEventListener('click', () => toggleMachineInfo());
  $('#machineInfoClose').addEventListener('click', () => toggleMachineInfo(false));
  let treeSearchDebounce;
  $('#machineSwitchSearch').addEventListener('input', () => {
    clearTimeout(treeSearchDebounce);
    treeSearchDebounce = setTimeout(renderMachineSwitcher, 110);
  });
  initMachineRail();
  $('#machinePrimaryConnect').addEventListener('click', () => {const a=machineAsset(); if(a) connect(a.id).catch(showError);});
  $('#machineTrust').addEventListener('click', () => {const a=machineAsset();if(!a)return;$('#scanHost').value=a.host;$('#scanPort').value=a.port||22;navigate('trust');$('#scanHost').focus();});
  $('#machineTerminalConnect').addEventListener('click', () => {const a=machineAsset(); if(a) connect(a.id,{newSession:$('#machineTerminalConnect').textContent.startsWith('New session')}).catch(showError);});
  $('#workbenchSessions').addEventListener('auxclick',event=>{
    if(event.button!==1)return;
    const element=event.target.closest('.workbench-session-tab');
    if(!element||!element.dataset.sessionId)return;
    event.preventDefault();
    const id=element.dataset.sessionId;
    if(state.tabs.has(id))closeTab(id);else if(desktopTabs.has(id))closeDesktopTab(id);
  });
  $('#workbenchSessions').addEventListener('keydown', event => {
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    const tabs = $$('[role="tab"]', $('#workbenchSessions'));
    const i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    event.preventDefault();
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 :
      (i + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].focus(); tabs[next].click();
  });
  $('#machineEdit').addEventListener('click', () => {const a = machineAsset(); if (a) openAsset(a);});
  $('#machineAddDesktop').addEventListener('click', () => {
    openDesktopEditor();
    $('#desktopForm').elements.host.value = state.machineHost || '';
    $('#desktopForm').elements.label.value = machineTitle();
  });
  $('#newFolder').addEventListener('click', () => showFolderDialog());
  $('#folderClose').addEventListener('click', () => $('#folderDialog').close());
  $('#folderCancel').addEventListener('click', () => $('#folderDialog').close());
  $('#folderForm').addEventListener('submit', safeAsync(saveFolder));
}
function settingsTab(tab) {
  for (const section of ['general','integrations','updates']) {
    $('#settings' + section[0].toUpperCase() + section.slice(1) + 'Panel').classList.toggle('hidden', tab !== section);
    $('#settings' + section[0].toUpperCase() + section.slice(1) + 'Tab').classList.toggle('active', tab === section);
  }
  if (tab === 'integrations') vaultStatus().catch(showError);
  if (tab === 'updates') { checkUpdateStatus().catch(showError); refreshUpdateConfig().catch(showError); }
}
async function checkUpdateStatus() {
  const btn = $('#updateCheck'); btn.disabled = true;
  try {
    const data = await api('/update/status');
    $('#updateStatus').textContent = `Installed: ${data.installed} · ${data.message}`;
  } finally { btn.disabled = false; }
}
async function refreshUpdateConfig() {
  const [config] = await Promise.all([api('/update/config')]);
  const select = $('#updateHost'); select.replaceChildren(new Option('Select an SSH machine', ''));
  for (const asset of state.assets) select.add(new Option(asset.label + ' · ' + asset.host, asset.id));
  select.value = config.asset_id || '';
  $('#updateProject').value = config.project || '';
  $('#updateDirectory').value = config.directory || '';
  if (config.job) await refreshUpdateJob();
}
async function saveUpdateConfig(event) {
  event.preventDefault();
  const button = $('#updateConfigSave'); button.disabled = true;
  try {
    await api('/update/config', {method:'PUT',body:{
      asset_id:$('#updateHost').value, compose_project:$('#updateProject').value,
      repository_directory:$('#updateDirectory').value,
      current_password:$('#updateConfigPassword').value}});
    $('#updateConfigPassword').value = '';
    toast('Update executor saved inside the appliance.'); await checkUpdateStatus();
  } finally { button.disabled = false; }
}
async function installUpdate() {
  const password = $('#updateInstallPassword').value;
  if (!password) { toast('Enter your administrator password to authorize the update.',true); return; }
  if (!await confirmAction('Install Switchyard update',
    'The configured Docker host will fast-forward the Switchyard Git checkout, pull images and restart the Compose project. Active sessions will close.', 'Install update')) return;
  const button = $('#updateInstall'); button.disabled = true;
  try {
    const result = await api('/update/install',{method:'POST',body:{current_password:password}});
    $('#updateInstallPassword').value = '';
    $('#updateJobLog').textContent = 'Update job scheduled: ' + result.job + '. Reconnect after the container restarts to view the result.';
    toast('Update scheduled on the Docker host.');
  } finally { button.disabled = false; }
}
async function refreshUpdateJob() {
  const output = $('#updateJobLog'); output.textContent = 'Loading update log…';
  const result = await api('/update/job');
  output.textContent = result.job ? result.status.toUpperCase() + ' · ' + result.job + '\n' + (result.log || '') : 'No update has been scheduled.';
}
function normalizedHost(host) { return String(host || '').trim().toLowerCase(); }
function machineAsset() { return state.assets.find(a => normalizedHost(a.host) === state.machineHost); }
function machineDesktops() { return desktopRecords.filter(d => normalizedHost(d.host) === state.machineHost); }
function machineTitle() { return machineAsset()?.label || machineDesktops()[0]?.label || state.machineHost || 'Machine'; }
async function refreshFolders() {
  state.folders = await api('/folders');
  for (const select of [$('#assetFolder'),$('#folderParent')]) {
    const selected = select.value;
    select.replaceChildren(new Option(select.id === 'assetFolder' ? 'Unfiled' : 'Top level', ''));
    for (const f of state.folders) select.add(new Option(f.name, f.id));
    if ([...select.options].some(o => o.value === selected)) select.value = selected;
  }
  renderMachineDirectory(); renderMachineSwitcher();
}
function machines() {
  const map = new Map();
  for (const a of state.assets) {
    const host = normalizedHost(a.host);
    if (!map.has(host)) map.set(host, {host, ssh:[], desktops:[], folder_id:a.folder_id || ''});
    map.get(host).ssh.push(a);
  }
  for (const d of desktopRecords) {
    const host = normalizedHost(d.host);
    if (!map.has(host)) map.set(host, {host, ssh:[], desktops:[], folder_id:''});
    map.get(host).desktops.push(d);
  }
  return [...map.values()].sort((a,b) => (a.ssh[0]?.label || a.desktops[0]?.label || a.host).localeCompare(b.ssh[0]?.label || b.desktops[0]?.label || b.host));
}
function renderMachineDirectory() {
  const target = $('#machineDirectory'); target.replaceChildren();
  const query = ($('#machineSearch')?.value || '').trim().toLowerCase();
  const all = machines();
  const environmentSelect = $('#machineEnvironment'); const selectedEnvironment = environmentSelect.value;
  const environments = [...new Set(all.flatMap(m => [...m.ssh.map(a=>a.environment),...m.desktops.map(d=>d.environment)]).filter(Boolean))].sort();
  environmentSelect.replaceChildren(new Option('All environments',''));
  for (const environment of environments) environmentSelect.add(new Option(environment,environment));
  if (environments.includes(selectedEnvironment)) environmentSelect.value = selectedEnvironment;
  const matches = all.filter(m => (!environmentSelect.value || [...m.ssh,...m.desktops].some(a=>a.environment === environmentSelect.value)) && [m.host, m.ssh[0]?.label, m.desktops[0]?.label, m.ssh[0]?.environment,
    state.folders.find(f => f.id === m.folder_id)?.name].join(' ').toLowerCase().includes(query));
  $('#machineCount').textContent = `${matches.length} of ${all.length} machines`;
  if (!matches.length) {
    target.append(node('div','machine-empty',query ? 'No machines match your search.' : 'No machines yet. Add a machine or desktop connection to start your inventory.'));
    return;
  }
  const folders = new Map([['',[]], ...state.folders.map(f=>[f.id,[]])]);
  for (const machine of matches) (folders.get(machine.folder_id) || folders.get('')).push(machine);
  const renderOne = machine => {
    const name = machine.ssh[0]?.label || machine.desktops[0]?.label || machine.host;
    const el = button('', 'machine-entry', () => openMachine(machine.host));
    const left = node('span','machine-entry-main');
    left.append(node('strong','', name), node('small','mono',machine.host));
    const types = node('span','machine-protocols');
    if (machine.ssh.length) types.append(node('span','protocol-label','SSH · SFTP'));
    for (const protocol of [...new Set(machine.desktops.map(d => d.protocol))]) types.append(node('span','protocol-label', protocol.toUpperCase()));
    el.append(node('span','machine-symbol','▣'),left,types,node('span','machine-chevron','→'));
    return el;
  };
  const renderFolder = (folderId, depth = 0, visited = new Set()) => {
    if (visited.has(folderId) || depth > 12) return;
    visited.add(folderId);
    const children = state.folders.filter(f => (f.parent_id || '') === folderId);
    const list = folders.get(folderId) || [];
    if (folderId) {
      const f = state.folders.find(x => x.id === folderId);
      if (!f) return;
      const heading = node('div','machine-folder-heading');
      const title = node('strong','', '▤  ' + f.name);
      heading.append(title,
        button('Rename','mini-btn', () => showFolderDialog(f)),
        button('Delete','mini-btn danger', async () => {
          if (!await confirmAction('Delete folder',`Delete “${f.name}”? Empty folders only.`, 'Delete')) return;
          await api('/folders/' + f.id,{method:'DELETE'}); await refreshFolders();
        }));
      target.append(heading);
    } else if (list.length) target.append(node('h2','machine-group-label','Unfiled machines'));
    for (const item of list) target.append(renderOne(item));
    for (const f of children) renderFolder(f.id,depth+1,new Set(visited));
  };
  renderFolder('');
}

const TREE_FOLD_KEY='switchyard:folders:folded:v1';
const TREE_WIDTH_KEY='switchyard:directory:width:v1';
function readUiPreference(key,fallback){
  try{const v=window.localStorage.getItem(key);return v===null?fallback:JSON.parse(v);}
  catch{return fallback;}
}
function saveUiPreference(key,value){
  try{window.localStorage.setItem(key,JSON.stringify(value));}catch{/* optional browser preference */}
}
const foldedFolders=new Set((()=>{
  const v=readUiPreference(TREE_FOLD_KEY,[]);
  return Array.isArray(v)?v.filter(id=>typeof id==='string').slice(0,200):[];
})());
function setFolderFolded(id,folded){
  if(folded)foldedFolders.add(id);else foldedFolders.delete(id);
  saveUiPreference(TREE_FOLD_KEY,[...foldedFolders].slice(0,200));
  renderMachineSwitcher();
}
function setMachineTreeOpen(open){
  const expanded=!!open;
  $('#machineLayout').classList.toggle('tree-open',expanded);
  $('#machineTreeToggle').setAttribute('aria-expanded',String(expanded));
  $('#machineTreeToggle').setAttribute('aria-label',expanded?'Hide machine directory':'Show machine directory');
}
function focusMachineSearch(){
  if($('#shell').classList.contains('hidden'))return;
  navigate('machine');
  if(window.matchMedia('(max-width:760px)').matches)setMachineTreeOpen(true);
  const field=$('#machineSwitchSearch');field.focus();field.select();
}
function initMachineRail(){
  const layout=$('#machineLayout'),handle=$('#machineRailResize'),field=$('#machineSwitchSearch');
  function applyWidth(pixels,persist=true){
    const value=Math.max(196,Math.min(440,Math.round(pixels)));
    layout.style.setProperty('--wb-rail',value+'px');
    handle.setAttribute('aria-valuenow',String(value));
    if(persist)saveUiPreference(TREE_WIDTH_KEY,value);
  }
  const saved=Number(readUiPreference(TREE_WIDTH_KEY,276));
  applyWidth(Number.isFinite(saved)?saved:276,false);
  let resizing=false;
  handle.addEventListener('pointerdown',event=>{
    if(event.button!==0||window.matchMedia('(max-width:760px)').matches)return;
    resizing=true;handle.setPointerCapture(event.pointerId);
    layout.classList.add('rail-resizing');event.preventDefault();
  });
  handle.addEventListener('pointermove',event=>{
    if(resizing)applyWidth(event.clientX-layout.getBoundingClientRect().left);
  });
  function finish(event){
    if(!resizing)return;resizing=false;layout.classList.remove('rail-resizing');
    if(handle.hasPointerCapture(event.pointerId))handle.releasePointerCapture(event.pointerId);
  }
  handle.addEventListener('pointerup',finish);
  handle.addEventListener('pointercancel',finish);
  handle.addEventListener('dblclick',()=>applyWidth(276));
  handle.addEventListener('keydown',event=>{
    if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
    event.preventDefault();
    const previous=Number(handle.getAttribute('aria-valuenow'))||276;
    applyWidth(event.key==='Home'?196:event.key==='End'?440:previous+(event.key==='ArrowLeft'?-16:16));
  });
  $('#machineTreeToggle').addEventListener('click',()=>{
    const next=!layout.classList.contains('tree-open');
    setMachineTreeOpen(next);if(next)field.focus();
  });
  layout.addEventListener('click',event=>{
    if(layout.classList.contains('tree-open')&&event.target===layout)setMachineTreeOpen(false);
  });
  window.addEventListener('keydown',event=>{
    if(event.key==='Escape'&&layout.classList.contains('tree-open')){
      setMachineTreeOpen(false);$('#machineTreeToggle').focus();return;
    }
    // Never steal Ctrl+K from SSH terminals (readline kill-line), RDP/VNC,
    // input fields, or an open dialog. Shortcuts operate at workbench scope.
    const remoteInput=event.target?.closest?.('.xterm,.xterm-helper-textarea,.desktop-viewports');
    const formInput=event.target?.closest?.('input,textarea,select,[contenteditable="true"],[role="textbox"]');
    const dialogOpen=!!document.querySelector('dialog[open]');
    if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'
      &&!remoteInput&&!formInput&&!dialogOpen){
      event.preventDefault();focusMachineSearch();return;
    }
    if(event.key==='/'&&!event.ctrlKey&&!event.metaKey&&!event.altKey
      &&!event.target?.closest?.('input,textarea,select,[contenteditable="true"],[role="textbox"]')
      &&!document.querySelector('dialog[open]')&&!$('#shell').classList.contains('hidden')){
      event.preventDefault();focusMachineSearch();
    }
  });
  field.addEventListener('keydown',event=>{
    if(event.key==='Escape'){
      event.preventDefault();field.value='';renderMachineSwitcher();
      if(window.matchMedia('(max-width:760px)').matches){
        setMachineTreeOpen(false);$('#machineTreeToggle').focus();
      }
    }else if(event.key==='ArrowDown'){
      const first=$('#machineSwitcher .tree-machine, #machineSwitcher .tree-folder-toggle');
      if(first){event.preventDefault();first.focus();}
    }
  });
  const tree=$('#machineSwitcher');
  tree.addEventListener('keydown',event=>{
    const buttons=$('.tree-machine, .tree-folder-toggle',tree);
    const index=buttons.indexOf(document.activeElement);
    if(index<0)return;
    if(['ArrowDown','ArrowUp','Home','End'].includes(event.key)){
      event.preventDefault();
      const next=event.key==='Home'?0:event.key==='End'?buttons.length-1:
        Math.max(0,Math.min(buttons.length-1,index+(event.key==='ArrowDown'?1:-1)));
      buttons[next]?.focus();
    }else if(['ArrowLeft','ArrowRight'].includes(event.key)
      &&document.activeElement.classList.contains('tree-folder-toggle')){
      const id=document.activeElement.dataset.folderId,folded=event.key==='ArrowLeft';
      if(foldedFolders.has(id)===folded)return;
      event.preventDefault();setFolderFolded(id,folded);
      $('.tree-folder-toggle',tree).find(button=>button.dataset.folderId===id)?.focus();
    }
  });
}
function renderMachineSwitcher() {
  const target=$('#machineSwitcher');if(!target)return;
  target.replaceChildren();
  const query=($('#machineSwitchSearch').value||'').trim().toLowerCase();
  const all=machines().sort((a,b)=>(a.ssh[0]?.label||a.desktops[0]?.label||a.host).localeCompare((b.ssh[0]?.label||b.desktops[0]?.label||b.host),undefined,{numeric:true,sensitivity:'base'})),folders=state.folders,byId=new Map(folders.map(f=>[f.id,f]));
  $('#treeMachineCount').textContent=`${all.length} machine${all.length===1?'':'s'}`;
  const matches=all.filter(m=>{
    const chain=[];let f=byId.get(m.folder_id);const seen=new Set();
    while(f&&!seen.has(f.id)){seen.add(f.id);chain.push(f.name);f=byId.get(f.parent_id);}
    return [m.host,m.ssh[0]?.label,m.desktops[0]?.label,...chain].join(' ').toLowerCase().includes(query);
  });
  const groups=new Map([['',[]],...folders.map(f=>[f.id,[]])]);
  for(const m of matches)(groups.get(m.folder_id)||groups.get('')).push(m);
  const renderMachine=(m,level)=>{
    const title=m.ssh[0]?.label||m.desktops[0]?.label||m.host;
    const item=button('','tree-machine'+(m.host===state.machineHost?' active':''),()=>openMachine(m.host));
    item.style.setProperty('--tree-level',String(level));
    item.setAttribute('aria-label',`Select ${title}, ${m.host}`);item.title=`${title} · ${m.host}`;
    if(m.host===state.machineHost)item.setAttribute('aria-current','page');
    item.addEventListener('dblclick',()=>{if(m.ssh.length)connect(m.ssh[0].id).catch(showError);else if(m.desktops.length)openDesktop(m.desktops[0]).catch(showError);});
    const copy=node('span','tree-machine-copy');copy.append(node('strong','',title),node('small','mono',m.host));
    item.append(node('span','tree-machine-icon',m.ssh.length?'▣':'▤'),copy,node('span','tree-protocols',m.ssh.length?'SSH':m.desktops[0]?.protocol?.toUpperCase()||''));
    target.append(item);
  };
  const count=(id,seen=new Set())=>{
    if(seen.has(id))return 0;seen.add(id);
    return (groups.get(id)||[]).length+folders.filter(f=>(f.parent_id||'')===id).reduce((sum,f)=>sum+count(f.id,seen),0);
  };
  const visited=new Set();
  const renderFolder=(id,level=0)=>{
    if(visited.has(id)||level>16)return;if(id)visited.add(id);
    const folder=byId.get(id),own=groups.get(id)||[];
    if(id){
      const num=count(id);if(query&&!num&&!folder.name.toLowerCase().includes(query))return;
      const line=node('div','tree-folder-line');line.style.setProperty('--tree-level',String(level-1));
      const closed=foldedFolders.has(id)&&!query;
      const toggle=button((closed?'▸':'▾')+'  '+folder.name,'tree-folder-toggle',()=>setFolderFolded(id,!foldedFolders.has(id)));
      toggle.dataset.folderId=id;toggle.title=folder.name;toggle.setAttribute('aria-expanded',String(!closed));
      toggle.setAttribute('aria-label',`${folder.name}, ${num} machines`);
      const edit=button('⋯','tree-folder-menu',()=>showFolderDialog(folder));
      edit.setAttribute('aria-label','Edit '+folder.name);
      line.append(toggle,node('span','tree-folder-count',String(num)),edit);target.append(line);
      if(closed)return;
    }
    for(const m of own)renderMachine(m,level);
    for(const f of folders.filter(f=>(f.parent_id||'')===id).sort((a,b)=>a.name.localeCompare(b.name,undefined,{numeric:true,sensitivity:'base'})))renderFolder(f.id,level+1);
  };
  const unfiled=groups.get('')||[];
  if(unfiled.length){target.append(node('div','tree-group-label','UNFILED'));for(const m of unfiled)renderMachine(m,0);}
  for(const f of folders.filter(f=>!f.parent_id||!byId.has(f.parent_id)).sort((a,b)=>a.name.localeCompare(b.name,undefined,{numeric:true,sensitivity:'base'})))renderFolder(f.id,1);
  if(!target.children.length)target.append(node('div','context-empty',query?'No matching machines.':'No connections yet. Choose + to add one.'));
}
function toggleMachineInfo(show=!$('#machineInfoDrawer').classList.contains('hidden')) {
  const visible=!!show&&!!state.machineHost;
  $('#machineInfoDrawer').classList.toggle('hidden',!visible);
  $('#machineInfoToggle').setAttribute('aria-expanded',String(visible));
  if(visible)renderMachineInfo();
}
function renderMachineInfo() {
  const a=machineAsset(),ds=machineDesktops(),target=$('#machineInfoContents');target.replaceChildren();
  const rows=[['Machine',machineTitle()],['Address',state.machineHost||'—'],['SSH',a?`${a.username}@${a.host}:${a.port||22}`:'Not configured'],['Folder',state.folders.find(f=>f.id===a?.folder_id)?.name||'Unfiled'],['Environment',a?.environment||ds[0]?.environment||'Unassigned'],['Desktop profiles',String(ds.length)]];
  const dl=node('dl','workbench-info-list');
  for(const [k,v] of rows){const row=node('div');row.append(node('dt','',k),node('dd','',v));dl.append(row);}
  target.append(dl);
  if(a)target.append(button('Edit SSH profile','action-quiet',()=>openAsset(a)));
  target.append(button('Add remote desktop','action-quiet',()=>$('#machineAddDesktop').click()));
}
function renderWorkbenchSessions() {
  const nav=$('#workbenchSessions');if(!nav)return;nav.replaceChildren();
  const home=button('⌂  Connections','workbench-session-tab'+(state.machineTab==='overview'?' active':''),()=>machineTab('overview'));
  home.setAttribute('role','tab');home.setAttribute('aria-selected',String(state.machineTab==='overview'));nav.append(home);
  for(const [id,session] of state.tabs){
    const wrap=node('div','workbench-session-item'),active=state.machineTab==='terminals'&&state.currentTab===id;
    const tab=button('›_  '+session.asset.label+(session.ws?.readyState===WebSocket.CLOSED?' · Disconnected':''),'workbench-session-tab'+(active?' active':''),()=>selectTab(id));tab.dataset.sessionId=id;
    tab.setAttribute('role','tab');tab.setAttribute('aria-selected',String(active));
    const close=button('×','workbench-tab-close',()=>closeTab(id));close.setAttribute('aria-label','Close SSH session for '+session.asset.label);
    wrap.append(tab,close);nav.append(wrap);
  }
  for(const [id,session] of desktopTabs){
    const wrap=node('div','workbench-session-item'),active=state.machineTab==='desktops'&&currentDesktopTab===id;
    const tab=button('▣  '+session.record.label,'workbench-session-tab'+(active?' active':''),()=>selectDesktopTab(id));tab.dataset.sessionId=id;
    tab.setAttribute('role','tab');tab.setAttribute('aria-selected',String(active));
    const close=button('×','workbench-tab-close',()=>closeDesktopTab(id));close.setAttribute('aria-label','Disconnect '+session.record.label);
    wrap.append(tab,close);nav.append(wrap);
  }
}
function updateMachineHeader(){
  const a=machineAsset();
  $('#machineTitle').textContent=state.machineHost?machineTitle():'No machine selected';
  $('#machineAddress').textContent=state.machineHost||'Choose a machine from the directory';
  $('#machineAvailability').textContent=a?' · SSH configured':state.machineHost?' · Desktop only':'';
  $('#machinePrimaryConnect').disabled=!a;$('#machinePrimaryConnect').classList.toggle('hidden',!a);
  $('#machineEdit').disabled=!a;$('#machineAddDesktop').disabled=!state.machineHost;
  $('#machineInfoToggle').disabled=!state.machineHost;
  $('#machineTrust').disabled=!a;
  $('#machineProbe').disabled=!a;
  if(a && sshProbeResults.has(a.id))$('#machineAvailability').textContent=' · '+sshProbeLabel(sshProbeResults.get(a.id));
  renderMachineSwitcher();
  if(!$('#machineInfoDrawer').classList.contains('hidden'))renderMachineInfo();
}
function updateTerminalStatus() {
  const status = $('#machineTerminalStatus');
  if (!status) return;
  const sessions = [...state.tabs.values()].filter(t => normalizedHost(t.asset.host) === state.machineHost);
  const connected = sessions.filter(t => t.ws?.readyState === WebSocket.OPEN).length;
  const connecting = sessions.filter(t => t.ws?.readyState === WebSocket.CONNECTING).length;
  status.className = connected ? 'session-state connected' : connecting ? 'session-state connecting' : 'session-state';
  status.textContent = connected ? `${connected} connected` : connecting ? 'Connecting…' : sessions.length ? 'Disconnected' : 'No session';
  const connect = $('#machineTerminalConnect');
  if (connect) connect.textContent = connected || connecting ? 'New session ↗' : sessions.some(t=>t.authFailed) ? 'Retry with password ↗' : sessions.length ? 'Reconnect ↗' : 'Connect via SSH ↗';
}

function openMachine(host){
  state.machineHost=normalizedHost(host);
  setMachineTreeOpen(false);
  const asset=machineAsset();
  for(const id of ['fileAsset','dockerAsset','healthAsset','serviceAsset'])if(asset)$('#'+id).value=asset.id;
  $('#filePath').value='.';
  state.currentTab=[...state.tabs.keys()].find(id=>normalizedHost(state.tabs.get(id).asset.host)===state.machineHost)||null;
  updateMachineHeader();renderTabs();renderMachineOverview();renderDesktopList();
  navigate('machine');machineTab(state.currentTab?'terminals':'overview');
}
function renderMachineOverview(){
  const asset=machineAsset(),desktops=machineDesktops(),target=$('#machineOverviewContent');target.replaceChildren();
  if(!state.machineHost){
    const empty=node('div','workbench-welcome');
    empty.append(node('div','workbench-empty-mark','⇄'),node('h2','','Your connections, one workspace.'),
      node('p','','Select a machine from the directory on the left, or create your first connection.'));
    empty.append(button('+ Add machine','action-primary',()=>openAsset()));target.append(empty);return;
  }
  const header=node('header','workbench-connection-heading'),copy=node('div');
  copy.append(node('h2','','Connect to '+machineTitle()),
    node('p','',`${state.machineHost} · Choose an available protocol to open a session.`));
  header.append(copy);target.append(header);
  const list=node('div','workbench-connections');
  if(asset){
    const action=button('','workbench-connect-row',()=>connect(asset.id).catch(showError));
    const label=node('span','workbench-connect-copy');
    label.append(node('strong','','SSH terminal'),node('small','',`${asset.username}@${asset.host}:${asset.port||22}`));
    action.append(node('span','workbench-connect-symbol','›_'),label,node('span','workbench-connect-action','Connect →'));
    list.append(action);
  }
  for(const d of desktops){
    const action=button('','workbench-connect-row',()=>openDesktop(d).catch(showError));
    const label=node('span','workbench-connect-copy');
    label.append(node('strong','',`${d.protocol.toUpperCase()} · ${d.label}`),node('small','',`${d.host}:${d.port||''}`));
    action.append(node('span','workbench-connect-symbol','▣'),label,node('span','workbench-connect-action','Open →'));
    list.append(action);
  }
  if(!asset&&!desktops.length)list.append(node('div','context-empty','No connection profiles exist for this machine. Add SSH or remote desktop access.'));
  target.append(list,node('div','workbench-connection-note','Double-click a machine to connect. Ctrl+K searches your machines. Drag the divider to resize the directory. Open sessions remain in the tabs above.'));
}
function machineTab(tab){
  if(['files','docker','health'].includes(tab)){navigate(tab);return;}
  if(!['overview','terminals','desktops'].includes(tab))tab='overview';
  if(tab==='terminals'&&!machineAsset())tab='overview';
  state.machineTab=tab;
  for(const id of ['overview','terminals','desktops'])$('#machinePanel-'+id).classList.toggle('hidden',tab!==id);
  if(tab==='terminals'){renderTabs();updateTerminalStatus();
    if(state.currentTab)requestAnimationFrame(()=>state.tabs.get(state.currentTab)?.fit.fit());}
  if(tab==='desktops'){renderDesktopTabs();requestAnimationFrame(()=>fitDesktop(desktopCurrent()));}
  renderWorkbenchSessions();
}
function showFolderDialog(folder = null) {
  $('#folderForm').reset(); $('#folderForm').dataset.edit = folder?.id || '';
  $('#folderDialogTitle').textContent = folder ? 'Edit folder' : 'New folder';
  $('#folderName').value = folder?.name || '';
  $('#folderParent').value = folder?.parent_id || '';
  $('#folderDialog').showModal();
}
async function saveFolder(event) {
  event.preventDefault();
  const form = event.target, id = form.dataset.edit;
  await api('/folders' + (id ? '/' + id : ''),{method:id?'PUT':'POST',body:{name:$('#folderName').value.trim(),parent_id:$('#folderParent').value || null}});
  $('#folderDialog').close(); await refreshFolders(); toast(id ? 'Folder updated.' : 'Folder created.');
}
async function refreshLoginOptions() {
  try {const options = await api('/login/options'); $('#loginTotpGroup').classList.toggle('hidden', !options.mfa_required); $('#loginTotp').required = !!options.mfa_required;}
  catch {$('#loginTotpGroup').classList.add('hidden'); $('#loginTotp').required = false;}
}

function setLogin() {
  $('#setup').classList.add('hidden'); $('#shell').classList.add('hidden'); $('#login').classList.remove('hidden');
  for (const tab of state.tabs.values()) tab.ws?.close();
  state.tabs.clear(); state.currentTab = null; state.sessionPasswords.clear(); state.failedAuthAssets?.clear(); closeAllDesktops(); refreshLoginOptions();
}
async function setShell() {
  $('#setup').classList.add('hidden'); $('#login').classList.add('hidden'); $('#shell').classList.remove('hidden');
  // Fetch independent inventory sources concurrently instead of serial startup roundtrips.
  await Promise.all([refreshFolders(), refreshAssets(), refreshDesktops()]);
  state.machineHost = machines()[0]?.host || null;
  updateMachineHeader(); renderMachineOverview(); renderDesktopList();
  navigate('machine'); machineTab('overview');
}
async function refreshAssets() {
  const [assets,info] = await Promise.all([api('/assets'),api('/overview').catch(() => null)]);
  state.assets = assets;
  renderAssets(); renderQuick(); renderFileSelect(); renderDockerSelect(); renderServiceSelect(); renderHealthSelect();
  renderMachineDirectory(); renderMachineSwitcher();
  if (info) {
    $('#metricAssets').textContent = info.assets;
    $('#metricGroups').textContent = info.environments;
    $('#metricEvents').textContent = info.audit_events;
  }
}
function navigate(page) {
  if (page === 'vault') { navigate('settings'); settingsTab('integrations'); return; }
  if (page === 'machines') page = 'machine';
  if (['terminals','desktops'].includes(page)) {
    if (!state.machineHost) {navigate('machine');machineTab('overview');return;}
    navigate('machine'); machineTab(page); return;
  }
  state.page = page;
  $('#shell')?.classList.remove('nav-open');
  $('#navMobileToggle')?.setAttribute('aria-expanded','false');
  $$('.page').forEach(el => el.classList.toggle('hidden', el.id !== 'page-' + page));
  $$('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.page === page || (page === 'machine' && el.dataset.page === 'machines')));
  if (page === 'machine') {updateMachineHeader();renderWorkbenchSessions();}
  $('#bread').textContent = ({ machine:'Machine / ' + machineTitle(), machines:'Machines', overview: 'Overview', assets: 'Assets', terminals: 'Terminals', files: 'File transfer', docker: 'Docker', health: 'Host health', services: 'System services', runbooks: 'Runbooks', desktops: 'Remote desktops', vault: 'Vaultwarden', keys: 'SSH keys', trust: 'Host trust', activity: 'Audit trail', settings: 'Settings' })[page];
  if (page === 'desktops') { refreshDesktops().catch(showError); refreshDesktopHistory().catch(showError); refreshDesktopActive().catch(showError); fitDesktop(desktopCurrent()); }
  if (page === 'runbooks') refreshRunbooks().catch(showError);
  if (page === 'files') {const a=machineAsset(); if(a){$('#fileAsset').value=a.id;browseFiles().catch(showError);}}
  if (page === 'docker') {const a=machineAsset(); if(a){$('#dockerAsset').value=a.id;refreshDocker().catch(showError);}}
  if (page === 'services') {const a=machineAsset();if(a)$('#serviceAsset').value=a.id;refreshServices().catch(showError);}
  if (page === 'health') {const a=machineAsset();if(a)$('#healthAsset').value=a.id;refreshHealthHistory().catch(showError);}
  if (page === 'vault') vaultStatus().catch(showError);
  if (page === 'trust') refreshHosts().catch(showError);
  if (page === 'keys') refreshKeys().catch(showError);
  if (page === 'settings') { settingsTab('general'); refreshMfaStatus().catch(showError); refreshNetwork().catch(showError); }
  if (page === 'activity') refreshAudit().catch(showError);
  if (page === 'terminals' && state.currentTab) requestAnimationFrame(() => state.tabs.get(state.currentTab)?.fit.fit());
}
function renderQuick() {
  const target = $('#quickAssets'); target.replaceChildren();
  if (!state.assets.length) { target.append(node('div', 'empty-state', 'No saved assets. Add your first SSH connection to begin.')); return; }
  for (const asset of state.assets.slice(0, 6)) {
    const el = button('', 'quick-asset', () => openMachine(asset.host));
    el.append(node('span', 'env', asset.environment || 'UNASSIGNED'), node('h3', '', asset.label), node('div', 'host', asset.username + '@' + asset.host + ':' + asset.port), node('span', 'arrow', '↗'));
    target.append(el);
  }
}

function sshProbeLabel(result) {
  return result.reachable ? 'TCP reachable · login not verified' : 'TCP unreachable · check host, port, or firewall';
}
async function checkSSHPort(a) {
  if(!a)throw Error('Choose an SSH machine first.');
  const result=await api('/assets/'+a.id+'/probe',{method:'POST'});
  sshProbeResults.set(a.id,result);
  renderAssets();
  if(normalizedHost(a.host)===state.machineHost)updateMachineHeader();
  toast(a.label+': '+sshProbeLabel(result),!result.reachable);
  return result;
}
async function checkSSHBatch() {
  const query=$('#assetSearch').value.trim().toLowerCase();
  const selected=state.assets.filter(a=>(a.label+' '+a.host+' '+a.username+' '+a.environment).toLowerCase().includes(query)).slice(0,20);
  if(!selected.length){toast('No SSH machines to check.',true);return;}
  const trigger=$('#sshProbeBatch');trigger.disabled=true;
  $('#sshProbeStatus').textContent='Checking '+selected.length+' SSH TCP ports…';
  try {
    const data=await api('/assets/probes',{method:'POST',body:{ids:selected.map(a=>a.id)}});
    for(const result of data.results)sshProbeResults.set(result.id,result);
    const count=data.results.filter(r=>r.reachable).length;
    $('#sshProbeStatus').textContent=count+' of '+data.count+' TCP ports reachable; host identity and SSH login not verified.';
    renderAssets();updateMachineHeader();
  } finally {trigger.disabled=false;}
}

function renderAssets() {
  const query = $('#assetSearch').value.toLowerCase().trim();
  const assets = state.assets.filter(a => (a.label + ' ' + a.host + ' ' + a.username + ' ' + a.environment).toLowerCase().includes(query));
  $('#assetTotal').textContent = `${assets.length} of ${state.assets.length} assets`;
  const target = $('#assetList'); target.replaceChildren();
  if (!assets.length) { target.append(node('div', 'empty-state', query ? 'Nothing matches your search.' : 'No assets yet. Select New asset to begin.')); return; }
  for (const a of assets) {
    const row = node('div', 'asset-row');
    const name = node('div'); name.append(node('strong', '', a.label), node('small', '', a.username + ' · ' + (a.auth_type === 'vault' ? 'VAULT' : a.auth_type.toUpperCase())));
    const host = node('div', 'host-column mono', a.host + ':' + a.port);
    const env = node('div', 'environment-column env-tag', a.environment || '—');
    const actions = node('div', 'asset-row-actions');
    actions.append(button('Connect ↗', 'mini-btn', () => connect(a.id)), button('Check port', 'mini-btn', () => checkSSHPort(a).catch(showError)), button('Files', 'mini-btn', () => { navigate('files'); $('#fileAsset').value = a.id; browseFiles(); }), button('Edit', 'mini-btn', () => openAsset(a)), button('Delete', 'mini-btn danger', () => removeAsset(a)));
    const check=sshProbeResults.get(a.id);
    if(check)name.append(node('small',check.reachable?'status-good':'status-bad',sshProbeLabel(check)));
    row.append(name, host, env, actions); target.append(row);
  }
}
function openAsset(asset = null) {
  state.editing = asset?.id || null; const form = $('#assetForm'); form.reset();
  $('#assetModalTitle').textContent = asset ? 'Edit connection' : 'Add a connection';
  if (asset) {
    for (const [key, value] of Object.entries(asset)) {
      const input = form.elements.namedItem(key);
      if (!input) continue;
      if (input.type === 'checkbox') input.checked = !!value;
      else input.value = value;
    }
  }
  $('#assetPassword').value = '';
  $('#assetSavedPasswordState').textContent = asset?.has_saved_password ? 'A password is saved. Leave this field empty to keep it.' : 'Encrypted in the persistent /data volume; never returned to browsers.';
  $('#assetFolder').value = asset?.folder_id || '';
  syncAuthFields(); $('#assetDialog').showModal();
}
function syncAuthFields() {
  const auth = $('#assetAuth').value;
  $('#credentialGroup').classList.toggle('hidden', auth !== 'vault');
  $('#keyGroup').classList.toggle('hidden', auth !== 'key');
  $('#assetPasswordGroup').classList.toggle('hidden',auth !== 'interactive');
}
async function saveAsset(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  data.port = Number(data.port); data.use_tmux = event.target.elements.use_tmux.checked;
  data.credential_ref ||= ''; data.key_file ||= ''; data.folder_id ||= '';
  data.clear_password = event.target.elements.clear_password.checked;
  if (!data.password) delete data.password;
  const editing = state.editing;
  await api('/assets' + (editing ? '/' + editing : ''), { method: editing ? 'PUT' : 'POST', body: data });
  $('#assetDialog').close(); await refreshAssets(); if (state.machineHost) renderMachineOverview(); toast(editing ? 'Connection updated.' : 'Connection added.');
}
async function removeAsset(asset) {
  if (!await confirmAction('Remove machine',`Delete ${asset.label}? Remote files will not be modified.`,'Delete machine')) return;
  await api('/assets/' + asset.id, { method: 'DELETE' }); await refreshAssets(); renderMachineDirectory(); toast('Connection removed.');
}
async function promptPassword(asset, options={}) { return promptCredential(asset,options); }
/** Review the first observed SSH key. Cancel/Escape must never save trust. */
function confirmSSHHostFingerprint(asset,key) {
  const dialog=$('#sshTrustDialog');
  if(dialog.open)return Promise.reject(Error('An SSH fingerprint review is already open.'));
  $('#sshTrustHost').textContent=asset.host+':'+Number(asset.port||22);
  $('#sshTrustAlgorithm').textContent=key.key_type;
  $('#sshTrustFingerprint').textContent=key.fingerprint;
  $('#sshTrustName').textContent=asset.label||asset.host;
  const approve=$('#sshTrustApprove'),cancel=$('#sshTrustCancel'),close=$('#sshTrustClose');
  return new Promise(resolve=>{
    let settled=false;
    const cleanup=()=>{
      approve.removeEventListener('click',accept);
      cancel.removeEventListener('click',decline);
      close.removeEventListener('click',decline);
      dialog.removeEventListener('cancel',escape);
      dialog.removeEventListener('close',closed);
    };
    const finish=approved=>{
      if(settled)return;
      settled=true;cleanup();
      if(dialog.open)dialog.close();
      resolve(approved);
    };
    const accept=()=>finish(true);
    const decline=()=>finish(false);
    const escape=event=>{event.preventDefault();finish(false);};
    const closed=()=>finish(false);
    approve.addEventListener('click',accept);
    cancel.addEventListener('click',decline);
    close.addEventListener('click',decline);
    dialog.addEventListener('cancel',escape);
    dialog.addEventListener('close',closed);
    dialog.showModal();
    approve.focus();
  });
}
async function resolveUnknownSSHHost(asset,tab,ws) {
  try {
    const key=await api('/hosts/discover',{method:'POST',body:{host:asset.host,port:Number(asset.port||22)}});
    if(key.host!==asset.host || Number(key.port)!==Number(asset.port||22)
       || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(key.fingerprint)
       || !key.key_type || !key.public_key)
      throw Error('SSH fingerprint discovery returned inconsistent data. Host remains untrusted.');
    if(state.tabs.get(tab.id)!==tab)return;
    if(!await confirmSSHHostFingerprint(asset,key)){
      tab.terminal.writeln('\r\n[SSH host trust declined. Connection cancelled.]');
      return;
    }
    await api('/hosts/trust',{method:'POST',body:{
      host:key.host,port:Number(key.port),key_type:key.key_type,public_key:key.public_key
    }});
    toast('SSH fingerprint trusted for '+asset.host+'. Connecting…');
    if(state.tabs.get(tab.id)!==tab)return;
    if(tab.ws===ws){tab.ws=null;ws.close();}
    tab.trustPending=false;
    await connect(asset.id);  // Same tab, same credentials; never silently trust.
  }finally{
    tab.trustPending=false;
    updateTerminalStatus();
  }
}
async function connect(aid, {newSession = false} = {}) {
  const asset = state.assets.find(a => String(a.id) === String(aid));
  if (!asset) { toast('Machine connection was not found.', true); return; }
  if (!window.Terminal || !window.FitAddon) { toast('Terminal assets are missing from the container.', true); return; }
  const matches = [...state.tabs.values()].filter(t => String(t.asset.id) === String(aid));
  if(!newSession){
    const reviewing=matches.find(t=>t.trustPending);
    if(reviewing){selectTab(reviewing.id);return reviewing.id;}
  }
  const active = matches.find(t => !t.authFailed && t.ws && [WebSocket.CONNECTING, WebSocket.OPEN].includes(t.ws.readyState));
  if (active && !newSession) { selectTab(active.id); return active.id; }
  const previous = newSession ? null : matches.find(t => t.authFailed || !t.ws || t.ws.readyState === WebSocket.CLOSED);
  let password = await promptPassword(asset,{force:state.failedAuthAssets?.has(String(aid))});
  if (password === null) return null;
  let tab = previous;
  if (!tab) {
    const id = clientSessionId();
    tab = {id, asset, ws: null,
      terminal: new window.Terminal({cursorBlink: true, fontFamily:'Cascadia Code, Consolas, monospace',
        fontSize:14,lineHeight:1.25,scrollback:5000,
        theme:{background:'#1c1c20',foreground:'#F5F2F0',cursor:'#E56C7B',selectionBackground:'#58515A'}}),
      fit:new window.FitAddon.FitAddon()};
    tab.terminal.loadAddon(tab.fit);
    // Bind listeners once to this tab. Reconnect must not multiply handlers.
    tab.terminal.onData(data => {
      if(tab.ws?.readyState === WebSocket.OPEN) tab.ws.send(JSON.stringify({type:'input',data}));
    });
    tab.terminal.onResize(size => {
      if(tab.ws?.readyState === WebSocket.OPEN)
        tab.ws.send(JSON.stringify({type:'resize',cols:size.cols,rows:size.rows}));
    });
    state.tabs.set(id,tab);
  } else {
    tab.asset = asset;
    tab.terminal.writeln('\r\n\x1b[90m[Reconnecting this terminal]\x1b[0m');
  }
  state.currentTab = tab.id;
  navigate('terminals');renderTabs();updateTerminalStatus();
  const panel = $('#term-'+tab.id);
  if(!previous) tab.terminal.open(panel);
  tab.fit.fit();
  const wsUrl=(location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/terminal/'+encodeURIComponent(aid);
  let ws;
  try{ws=new WebSocket(wsUrl);}
  catch(error){
    password=null;
    tab.terminal.writeln('\r\n\x1b[31mCould not start the browser connection.\x1b[0m');
    toast('Connection transport could not start for '+asset.host+'.',true);
    renderTabs();updateTerminalStatus();return tab.id;
  }
  tab.ws=ws;
  tab.reportedServerError=false;
  tab.terminal.writeln('\r\nSwitchyard · connecting to '+asset.host);
  renderTabs();updateTerminalStatus();
  let upgraded=false;
  ws.onopen=()=>{
    if(tab.ws!==ws)return;
    upgraded=true;
    ws.send(JSON.stringify({type:'auth',password}));
    password=null;
    ws.send(JSON.stringify({type:'resize',cols:tab.terminal.cols,rows:tab.terminal.rows}));
    renderTabs();updateTerminalStatus();
  };
  ws.onmessage=event=>{
    if(tab.ws!==ws)return;
    try{
      const message=JSON.parse(event.data);
      if(message.type==='connected') {
        state.failedAuthAssets?.delete(String(asset.id));
        tab.authFailed=false;
        updateTerminalStatus();
      } else if(message.type==='data')tab.terminal.write(message.data);
      else if(message.type==='error'){
        tab.reportedServerError=true;
        const detail=typeof message.message==='string'?message.message:'SSH connection failed';
        const untrusted=message.code==='ssh_host_unknown'||detail.startsWith('SSH host is not trusted');
        const changed=message.code==='ssh_host_changed'||detail.startsWith('SSH host key changed');
        const rejected=message.code==='ssh_auth_rejected'||detail.startsWith('SSH authentication rejected');
        if(untrusted && !tab.trustPending){
          tab.trustPending=true;
          tab.terminal.writeln('\r\n[First connection: discovering SSH fingerprint for approval…]');
          void resolveUnknownSSHHost(asset,tab,ws).catch(error=>{
            tab.terminal.writeln('\r\n[SSH host trust failed: '+error.message+']');
            toast(error.message,true);
          });
          return;
        }
        if(changed){
          tab.terminal.writeln('\r\n\x1b[31m[SECURITY WARNING: Host key changed. Connection blocked. Verify the replacement out of band before updating Host trust.]\x1b[0m');
        }
        if(rejected && asset.auth_type==='interactive'){
          discardRejectedPassword(asset.id);
          tab.authFailed=true;
          tab.terminal.writeln('\r\n\x1b[33m[SSH password rejected; reconnect will prompt for another. To permanently replace a saved password, use Edit machine.]\x1b[0m');
        }
        tab.terminal.writeln('\r\n\x1b[31m'+detail+'\x1b[0m');
        toast(rejected&&asset.auth_type==='interactive'?'SSH login rejected. Reconnect to enter another password.':detail,true);
        renderTabs();updateTerminalStatus();
      }
    }catch{tab.terminal.writeln('\r\nUnexpected terminal message.');}
  };
  ws.onerror=()=>{
    if(tab.ws!==ws)return;
    password=null;
    // A server-side rejection is more useful than a generic WebSocket error.
    if(tab.reportedServerError)return;
    const reason=upgraded
      ? 'SSH WebSocket transport disconnected after connecting.'
      : 'Switchyard WebSocket handshake failed. Confirm the container has WebSocket support and that any reverse proxy forwards Upgrade and Connection headers.';
    tab.terminal.writeln('\r\n\x1b[31m'+reason+'\x1b[0m');
    toast(reason,true);
  };
  ws.onclose=()=>{
    if(tab.ws!==ws)return;
    password=null;
    tab.terminal.writeln(tab.authFailed ? '\r\n\x1b[90m[Disconnected — reconnect to enter a different password]\x1b[0m' : '\r\n\x1b[90m[Disconnected — reconnect will reuse this tab]\x1b[0m');
    renderTabs();updateTerminalStatus();
  };
  return tab.id;
}
function renderTabs() {
  const nav = $('#terminalTabs'); nav.replaceChildren();
  const panels = $('#terminalPanels');
  const visible = [...state.tabs.values()].filter(t => normalizedHost(t.asset.host) === state.machineHost);
  if (!visible.length) panels.querySelector(':scope > .empty-state') || panels.append(node('div', 'empty-state', 'No SSH session open. Select Connect to start.'));
  else panels.querySelector(':scope > .empty-state')?.remove();
  for (const [id, t] of state.tabs) {
    if (normalizedHost(t.asset.host) !== state.machineHost) continue;
    const wrap = node('div', 'terminal-tab' + (id === state.currentTab ? ' active' : ''));
    const select = button(t.asset.label + (t.ws?.readyState === WebSocket.CLOSED ? ' · closed' : ''), 'tab-select', () => selectTab(id));
    select.setAttribute('role', 'tab'); select.setAttribute('aria-selected', String(id === state.currentTab));
    const close = button('×', 'tab-close', () => closeTab(id)); close.setAttribute('aria-label', 'Close ' + t.asset.label);
    wrap.append(select, close); nav.append(wrap);
    if (!$('#term-' + id)) { const panel = node('div', 'terminal-host'); panel.id = 'term-' + id; panels.append(panel); }
  }
  $$('.terminal-host', panels).forEach(el => el.classList.toggle('active', el.id === 'term-' + state.currentTab && normalizedHost(state.tabs.get(state.currentTab)?.asset.host) === state.machineHost));
  $('#terminalCount').textContent = state.tabs.size; updateTerminalStatus(); renderWorkbenchSessions();
}
function selectTab(id) { state.currentTab = id; const host = state.tabs.get(id)?.asset?.host; if (host) state.machineHost = normalizedHost(host); updateMachineHeader(); navigate('terminals'); renderTabs(); requestAnimationFrame(() => { const t = state.tabs.get(id); if (t) { t.fit.fit(); t.terminal.focus(); } }); }
function closeTab(id) { const t = state.tabs.get(id); if (!t) return; t.ws?.close(); t.terminal.dispose(); state.tabs.delete(id); $('#term-' + id)?.remove(); if (state.currentTab === id) state.currentTab = [...state.tabs.keys()].find(k => normalizedHost(state.tabs.get(k).asset.host) === state.machineHost) || null; renderTabs(); updateTerminalStatus(); if (state.currentTab) selectTab(state.currentTab); else if (state.machineTab==='terminals') machineTab('overview'); }

async function exportSSHInventory() {
  await savePrivateDownload('/assets/export', 'switchyard-ssh-inventory.json');
  toast('SSH inventory exported without passwords or private keys.');
}
async function importSSHInventory(event) {
  const input=event.target, file=input.files?.[0];
  if(!file)return;
  try {
    if(file.size>1024*1024)throw Error('SSH inventory exceeds the 1 MiB import limit.');
    const inventory=JSON.parse(await file.text());
    if(inventory?.format!=='switchyard-ssh-v1' || !Array.isArray(inventory.assets) || !Array.isArray(inventory.folders))
      throw Error('Not a Switchyard SSH inventory export.');
    if(inventory.assets.length>1000 || inventory.folders.length>300)
      throw Error('SSH inventory exceeds the machine or folder limit.');
    if(!await confirmAction('Import SSH inventory',
      'Add '+inventory.assets.length+' SSH machines and '+inventory.folders.length+
      ' folders? Existing entries will not be overwritten. Passwords and private keys are not imported.',
      'Import machines'))return;
    const result=await api('/assets/import',{method:'POST',body:inventory});
    await refreshFolders();await refreshAssets();
    toast('Imported '+result.assets_created+' machines and '+result.folders_created+' folders. Reconfigure credentials where required.');
  }finally{input.value='';}
}

function fileMessage(message,error=false){
  const target=$('#fileTransferStatus');
  target.textContent=message;
  target.setAttribute('data-state',error?'error':'ready');
}
async function copyRemote(a,path){
  const destination=await askDialog({title:'Copy remote file',
    description:'Copy a regular file on '+a.host+'. Existing destinations are protected.',
    label:'Full destination path',value:path+'.copy',required:true,action:'Copy file'});
  if(destination===null)return;
  const headers=await fileAuth(a);if(headers===null)return;
  const result=await api('/assets/'+a.id+'/files/copy',
    {method:'POST',body:{source:path,destination},headers});
  fileMessage('Copied '+sizeLabel(result.bytes_copied)+' to '+destination);
  toast('Remote file copied.');await browseFiles();
}
async function moveRemote(a,path){
  const destination=await askDialog({title:'Move remote item',
    description:'Move or rename on '+a.host+'. Existing destinations are protected.',
    label:'Full destination path',value:path,required:true,action:'Move item'});
  if(destination===null || destination===path)return;
  const headers=await fileAuth(a);if(headers===null)return;
  await api('/assets/'+a.id+'/files/rename',
    {method:'POST',body:{source:path,destination},headers});
  fileMessage('Moved '+path+' to '+destination);
  toast('Remote item moved.');await browseFiles();
}
async function chmodRemote(a,path,existing){
  const mode=await askDialog({title:'Set remote permissions',
    description:'Unix access bits for '+path+' (three octal digits such as 640 or 755).',
    label:'Permissions (octal)',value:existing==='---'?'644':existing,required:true,action:'Set permissions'});
  if(mode===null)return;
  if(!/^[0-7]{3}$/.test(mode)){toast('Enter exactly three octal digits, such as 644.',true);return;}
  const headers=await fileAuth(a);if(headers===null)return;
  await api('/assets/'+a.id+'/files/chmod',{method:'POST',body:{path,mode},headers});
  toast('Permissions updated to '+mode+'.');await browseFiles();
}
function renderFileSelect() {
  const select = $('#fileAsset'); const selected = select.value; select.replaceChildren(node('option', '', 'Select an asset'));
  for (const a of state.assets) { const opt = node('option', '', a.label + ' · ' + a.host); opt.value = a.id; select.append(opt); }
  if (state.assets.some(a => a.id === selected)) select.value = selected;
}
async function fileAuth(a) { const pass = await promptPassword(a); return pass === null ? null : pass ? { 'X-SSH-Password': pass } : {}; }
async function browseFiles() {
  const a = state.assets.find(x => x.id === $('#fileAsset').value);
  if (!a) { toast('Choose a remote host first.', true); return; }
  const headers = await fileAuth(a); if (headers === null) return;
  $('#fileList').replaceChildren(node('div', 'empty-state', 'Opening remote directory…'));
  const data = await api(`/assets/${a.id}/files?path=${encodeURIComponent($('#filePath').value || '.')}`, { headers });
  $('#filePath').value = data.path; $('#fileLocation').textContent = a.host + ' : ' + data.path;
  const target = $('#fileList'); target.replaceChildren();
  if (data.path !== '/') {
    const parent = node('div', 'file-row');
    parent.append(button('↰  Parent directory', 'file-name', () => { $('#filePath').value = data.path.split('/').slice(0, -1).join('/') || '/'; browseFiles(); }), node('span'), node('span')); target.append(parent);
  }
  if (!data.entries.length) target.append(node('div', 'empty-state', 'This directory is empty.'));
  for (const entry of data.entries) {
    const row = node('div', 'file-row'); const fullPath = (data.path === '/' ? '' : data.path) + '/' + entry.name;
    const name = button((entry.directory ? '▣ ' : entry.symlink ? '↪ ' : '▤ ') + entry.name, 'file-name', () => { if (entry.directory) { $('#filePath').value = fullPath; browseFiles(); } else downloadFile(a, fullPath); });
    const tools = node('div', 'file-tools');
    tools.append(node('span', 'file-size', entry.directory ? 'DIR' : sizeLabel(entry.size)),
      node('span', 'file-size mono', entry.permissions || '---'),
      ...(!entry.directory && !entry.symlink ? [
        button('Edit text', 'mini-btn', () => openFileEditor(a, fullPath).catch(showError)),
        button('Copy', 'mini-btn', () => copyRemote(a, fullPath).catch(showError))] : []),
      button('Move', 'mini-btn', () => moveRemote(a, fullPath).catch(showError)),
      ...(!entry.symlink ? [button('Permissions', 'mini-btn',
        () => chmodRemote(a, fullPath, entry.permissions).catch(showError))] : []),
      button('Rename', 'mini-btn', () => renameRemote(a, fullPath).catch(showError)),
      button('Delete', 'mini-btn danger', () => deleteRemote(a, fullPath, entry.directory).catch(showError)));
    row.append(name, tools, node('span', 'file-size', new Date(entry.modified * 1000).toLocaleString())); target.append(row);
  }
}
function sizeLabel(bytes) { if (bytes < 1024) return bytes + ' B'; if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'; return (bytes / (1024 * 1024)).toFixed(1) + ' MB'; }
async function downloadFile(a, path) {
  const headers = await fileAuth(a); if (headers === null) return;
  const response = await api(`/assets/${a.id}/download?path=${encodeURIComponent(path)}`, { headers });
  const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = node('a');
  link.href = url; link.download = path.split('/').pop() || 'file'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 30000);
  toast('File download started.');
}
async function uploadFile(event) {
  const input=event.target, files=[...(input.files||[])];
  if(!files.length)return;
  const a=state.assets.find(x=>x.id===$('#fileAsset').value);
  if(!a){input.value='';toast('Select a remote host first.',true);return;}
  if(files.length>20){input.value='';toast('Choose up to 20 files per batch.',true);return;}
  const oversized=files.find(file=>file.size>64*1024*1024);
  if(oversized){input.value='';toast('File exceeds 64 MiB: '+oversized.name,true);return;}
  const headers=await fileAuth(a);if(headers===null){input.value='';return;}
  const trigger=$('#fileUploadButton');trigger.disabled=true;
  let uploaded=0;const failed=[];
  try{
    for(let i=0;i<files.length;i++){
      const file=files[i];
      fileMessage('Uploading '+(i+1)+' of '+files.length+': '+file.name);
      const body=new FormData();body.set('file',file);
      try{
        await api('/assets/'+a.id+'/upload?path='+encodeURIComponent($('#filePath').value||'.'),
          {method:'POST',body,headers});
        uploaded++;
      }catch(error){
        failed.push(file.name+': '+error.message);
        if(error.message.startsWith('SSH authentication rejected'))break;
      }
    }
    if(failed.length){
      fileMessage(uploaded+' uploaded. Failed: '+failed.join(' | '),true);
      toast('Some uploads failed. Review transfer status.',true);
    }else{
      fileMessage('Uploaded '+uploaded+' file'+(uploaded===1?'':'s')+' without overwriting remote files.');
      toast('Batch upload complete.');
    }
    await browseFiles();
  }finally{input.value='';trigger.disabled=false;}
}
async function createRemoteFolder() {
  const a = state.assets.find(x => x.id === $('#fileAsset').value);
  if (!a) { toast('Choose a remote host.', true); return; }
  const name = await askDialog({title:'Create remote folder',description:'Create a directory in ' + ($('#filePath').value || '.'),label:'Folder name',required:true,action:'Create folder'}); if (!name) return;
  if (name === '.' || name === '..' || name.includes('/') || name.includes('\\')) { toast('Choose a single directory name.', true); return; }
  const headers = await fileAuth(a); if (headers === null) return;
  const path = ($('#filePath').value === '/' ? '' : $('#filePath').value) + '/' + name;
  await api(`/assets/${a.id}/files/mkdir`, { method: 'POST', body: { path }, headers });
  toast('Remote directory created.'); await browseFiles();
}
async function renameRemote(a, path) {
  const oldName = path.split('/').pop(); const name = await askDialog({title:'Rename remote item',description:path,label:'New filename',value:oldName,required:true,action:'Rename'});
  if (!name || name === oldName) return;
  if (name === '..' || name === '.' || name.includes('/') || name.includes('\\')) { toast('Enter a single file or directory name.', true); return; }
  const headers = await fileAuth(a); if (headers === null) return;
  const destination = path.substring(0, path.lastIndexOf('/') + 1) + name;
  await api(`/assets/${a.id}/files/rename`, { method: 'POST', body: { source: path, destination }, headers });
  toast('Remote item renamed.'); await browseFiles();
}
async function deleteRemote(a, path, directory) {
  if (!await confirmAction('Delete remote item',`Permanently remove ${path}? Directories must be empty.`, 'Delete')) return;
  const headers = await fileAuth(a); if (headers === null) return;
  await api(`/assets/${a.id}/files?directory=${directory}`, { method: 'DELETE', body: { path }, headers });
  toast('Remote item deleted.'); await browseFiles();
}

let serviceRows=[];
function renderServiceSelect(){
  const el=$('#serviceAsset'),selected=el.value;
  el.replaceChildren(new Option('Choose an SSH machine',''));
  for(const a of state.assets)el.add(new Option(a.label+' · '+a.host,a.id));
  if(state.assets.some(a=>a.id===selected))el.value=selected;
}
function renderServices(){
  const list=$('#serviceList'),query=$('#serviceSearch').value.trim().toLowerCase();
  list.replaceChildren();
  const rows=serviceRows.filter(item=>(item.unit+' '+item.active+' '+item.sub+' '+item.description).toLowerCase().includes(query));
  if(!rows.length){list.append(node('div','empty-state',serviceRows.length?'No matching systemd services.':'No systemd services loaded.'));return;}
  for(const item of rows){
    const row=node('div','service-row');
    const info=node('div','service-identity');
    info.append(node('strong','mono',item.unit),node('small','',item.description));
    const status=node('div',item.active==='active'?'service-state-active':item.active==='failed'?'status-bad':'service-state-idle',item.active+' / '+item.sub);
    const actions=node('div','file-tools');
    actions.append(button('Journal','mini-btn',()=>showServiceJournal(item.unit).catch(showError)));
    actions.append(button('Start','mini-btn',()=>operateService(item,'start').catch(showError)));
    actions.append(button('Restart','mini-btn',()=>operateService(item,'restart').catch(showError)));
    actions.append(button('Stop','mini-btn danger',()=>operateService(item,'stop').catch(showError)));
    row.append(info,status,actions);list.append(row);
  }
}
async function refreshServices(){
  const selected=$('#serviceAsset').value;
  const asset=state.assets.find(x=>x.id===selected);
  if(!asset){serviceRows=[];renderServices();$('#serviceStatus').textContent='Choose a configured SSH host first.';return;}
  const headers=await fileAuth(asset);if(headers===null)return;
  const status=$('#serviceStatus');
  status.textContent='Loading systemd services from '+asset.host+'…';
  try{
    const data=await api('/assets/'+asset.id+'/services',{headers});
    if($('#serviceAsset').value!==asset.id)return;
    serviceRows=data.services;
    renderServices();
    status.textContent=data.count+' systemd services on '+asset.host+(data.limited?' (first 500 shown)':'')+'. Actions use the remote account’s existing permissions.';
  }catch(error){
    serviceRows=[];renderServices();status.textContent='Failed to load services: '+error.message;throw error;
  }
}
async function operateService(item,action){
  const asset=state.assets.find(x=>x.id===$('#serviceAsset').value);
  if(!asset)throw Error('Choose an SSH machine first.');
  const msg=action==='stop'?'Stopping this service may disconnect your remote machine or critical workloads.':'The remote systemd manager will attempt this operation.';
  if(!await confirmAction(action.charAt(0).toUpperCase()+action.slice(1)+' '+item.unit,
    msg+' '+action+' '+item.unit+' on '+asset.host+'?',action.charAt(0).toUpperCase()+action.slice(1)))return;
  const headers=await fileAuth(asset);if(headers===null)return;
  $('#serviceStatus').textContent='Executing '+action+' for '+item.unit+'…';
  await api('/assets/'+asset.id+'/services/action',{method:'POST',body:{unit:item.unit,action,confirmed:true},headers});
  toast('Requested '+action+' for '+item.unit+'.');
  await refreshServices();
}
async function showServiceJournal(unit){
  const asset=state.assets.find(x=>x.id===$('#serviceAsset').value);
  if(!asset)throw Error('Choose an SSH machine first.');
  const headers=await fileAuth(asset);if(headers===null)return;
  $('#serviceLogArea').classList.remove('hidden');
  $('#serviceLogTitle').textContent='Journal · '+unit;
  $('#serviceLogText').textContent='Retrieving up to 100 journal entries…';
  try{
    const response=await api('/assets/'+asset.id+'/services/'+encodeURIComponent(unit)+'/logs',{headers});
    $('#serviceLogText').textContent=response.lines||'No journal entries returned.';
  }catch(error){$('#serviceLogText').textContent='Journal unavailable: '+error.message;throw error;}
}

function renderDockerSelect() {
  const el = $('#dockerAsset'); const selected = el.value; el.replaceChildren(node('option', '', 'Select a Docker host'));
  for (const a of state.assets) { const opt = node('option', '', a.label + ' · ' + a.host); opt.value = a.id; el.append(opt); }
  if (state.assets.some(a => a.id === selected)) el.value = selected;
}
function detailLine(label, value) {
  const row = node('div', 'detail-line');
  row.append(node('strong', '', label), node('span', 'mono', value === null || value === undefined || value === '' ? '—' : String(value)));
  return row;
}
async function refreshDocker() {
  const a = state.assets.find(x => x.id === $('#dockerAsset').value);
  if (!a) { toast('Select a Docker host.', true); return; }
  const headers = await fileAuth(a); if (headers === null) return;
  $('#dockerList').replaceChildren(node('div', 'empty-state', 'Inspecting Docker workloads over SSH…'));
  $('#dockerDetails').classList.add('hidden');
  let summary;
  try {
    summary = await api(`/assets/${a.id}/docker/summary`, { headers });
    $('#dockerSummary').textContent = `${summary.name || a.host} · Engine ${summary.server_version || '?'} · ${summary.running ?? '?'} running / ${summary.containers ?? '?'} total · ${summary.images ?? '?'} images · ${summary.cpus ?? '?'} CPUs`;
  } catch (error) { $('#dockerSummary').textContent = 'Daemon summary unavailable: ' + error.message; }
  const endpoint = ({containers:'containers', images:'images', networks:'networks', volumes:'volumes', stacks:'stacks'})[dockerMode];
  const items = await api(`/assets/${a.id}/docker/${endpoint}`, { headers });
  $('#dockerHostLabel').textContent = a.username + '@' + a.host + ' · ' + items.length + ' ' + endpoint;
  const target = $('#dockerList'); target.replaceChildren();
  if (!items.length) target.append(node('div', 'empty-state', 'No ' + endpoint + ' found on this host.'));
  for (const item of items) {
    const row = node('div', 'docker-row');
    const title = dockerMode === 'stacks' ? item.name : dockerMode === 'containers' ? item.name || item.id?.slice(0,12) :
      dockerMode === 'images' ? (item.repository || '<none>') + ':' + (item.tag || '<none>') : item.name;
    const meta = dockerMode === 'stacks' ? item.config_files : dockerMode === 'containers' ? item.image + ' · ' + item.id.slice(0, 12) :
      dockerMode === 'images' ? (item.size || '—') + ' · ' + (item.created || '—') : (item.driver || '—');
    const left = node('div'); left.append(node('strong', '', title || 'Unnamed'), node('small', '', meta));
    if (dockerMode === 'stacks') {
      const actions = node('div', 'asset-row-actions');
      for (const action of ['start', 'stop', 'restart']) {
        actions.append(button(action[0].toUpperCase() + action.slice(1), 'mini-btn' + (action === 'stop' ? ' danger' : ''), safeAsync(async () => {
          if (!await confirmAction('Manage Compose stack', `${action.toUpperCase()} ${item.name} on ${a.host}?`, action.toUpperCase())) return;
          const auth = await fileAuth(a); if (auth === null) return;
          await api(`/assets/${a.id}/docker/stacks/action`, {method:'POST', headers:auth, body:{project:item.name, action}});
          toast('Compose project ' + action + ' completed.'); await refreshDocker();
        })));
      }
      row.append(left, node('span', 'docker-state', item.status), node('span', 'docker-ports', item.config_files), actions);
      target.append(row); continue;
    }
    if (dockerMode !== 'containers') {
      row.append(left, node('span', 'docker-ports', dockerMode === 'networks' ? item.scope || '—' : dockerMode === 'images' ? (item.id || '').slice(0, 18) : 'Persisted volume'));
      target.append(row); continue;
    }
    const status = node('span', 'docker-state' + (/^up\b/i.test(item.status) ? ' running' : ''), item.status || item.state);
    const ports = node('span', 'docker-ports', item.ports || 'No published ports');
    const actions = node('div', 'asset-row-actions');
    actions.append(button('Inspect', 'mini-btn', () => showDockerDetails(a, item.id)));
    for (const action of ['start', 'stop', 'restart']) {
      const b = button(action[0].toUpperCase() + action.slice(1), 'mini-btn' + (action === 'stop' ? ' danger' : ''), async () => {
        if (!await confirmAction('Manage container', `${action.toUpperCase()} ${item.name || item.id.slice(0, 12)} on ${a.host}?`, action.toUpperCase())) return;
        const auth = await fileAuth(a); if (auth === null) return;
        try { await api(`/assets/${a.id}/docker/action`, { method: 'POST', headers: auth, body: { action, container_id: item.id } }); toast('Docker ' + action + ' completed.'); await refreshDocker(); } catch (error) { showError(error); }
      });
      b.disabled = !/^[0-9a-f]{12,64}$/i.test(item.id) || (action === 'start' && /^up\b/i.test(item.status)) || (action === 'stop' && !/^up\b/i.test(item.status));
      actions.append(b);
    }
    row.append(left, status, ports, actions); target.append(row);
  }
}
async function showDockerDetails(asset, id) {
  const headers = await fileAuth(asset); if (headers === null) return;
  const pane = $('#dockerDetails'); const content = $('#dockerDetailContent');
  pane.classList.remove('hidden'); content.replaceChildren(node('div', 'empty-state', 'Loading container inspection…'));
  $('#dockerDetailTitle').textContent = 'Inspecting ' + id.slice(0, 12);
  try {
    const [item, stats] = await Promise.all([
      api(`/assets/${asset.id}/docker/containers/${id}/inspect`, { headers }),
      api(`/assets/${asset.id}/docker/containers/${id}/stats`, { headers }).catch(error => ({error: error.message}))
    ]);
    $('#dockerDetailTitle').textContent = item.name || id.slice(0, 12);
    content.replaceChildren();
    for (const [key, value] of Object.entries({
      'Image':item.image, 'State':item.status, 'Health':item.health, 'Created':item.created,
      'Started':item.started_at, 'Restarts':item.restart_count, 'Exit code':item.exit_code,
      'Restart policy':item.restart_policy, 'Networks':item.networks?.join(', '),
      'CPU':stats.CPUPerc, 'Memory':stats.MemUsage, 'Network I/O':stats.NetIO,
      'Block I/O':stats.BlockIO, 'PIDs':stats.PIDs,
      'Metrics':stats.error
    })) { if (value !== null && value !== undefined && value !== '') content.append(detailLine(key, value)); }
    const controls = node('div', 'file-controls');
    const tailLabel = node('label', '', 'Log tail');
    const tail = node('select');
    for (const n of [50, 200, 500]) { const opt = node('option', '', n + ' lines'); opt.value = n; if (n === 200) opt.selected = true; tail.append(opt); }
    tailLabel.append(tail);
    const output = node('pre', 'log-console', 'Load logs to inspect recent output.');
    controls.append(tailLabel, button('Load logs', 'action-small', async () => {
      const auth = await fileAuth(asset); if (auth === null) return;
      output.textContent = 'Loading recent container logs…';
      try {
        const result = await api(`/assets/${asset.id}/docker/containers/${id}/logs?tail=${tail.value}`, { headers: auth });
        output.textContent = result.logs || 'No log output for this container.';
      } catch (error) { output.textContent = 'Log retrieval failed: ' + error.message; }
    }));
    content.append(controls, output);
    pane.scrollIntoView({block:'nearest', behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth'});
  } catch (error) { content.replaceChildren(node('div', 'empty-state', error.message)); }
}
function dockerView(mode) { dockerMode = mode; refreshDocker().catch(showError); }
async function vaultStatus() {
  const status = await api('/vault/status');
  $('#vaultState').textContent = status.unlocked ? 'Unlocked' : (status.status || 'Unavailable');
  $('#vaultServer').textContent = status.server || 'No server configured';
}
async function vaultItems() {
  const items = await api('/vault/items'); state.vaultItems = items;
  const options = $('#availableVaultItems'); options.replaceChildren();
  for (const item of items) { const opt = node('option', '', item.name || 'Unnamed login'); opt.value = item.id; options.append(opt); }
  const target = $('#vaultItems'); target.replaceChildren();
  if (!items.length) target.append(node('div', 'empty-state', 'No login credentials found.'));
  for (const item of items) {
    const row = node('div', 'asset-row'); const heading = node('div'); heading.append(node('strong', '', item.name || 'Unnamed login'), node('small', '', item.username || 'No username'));
    row.append(heading, node('span', 'mono', item.id), node('span'), button('Copy item ID', 'mini-btn', () => { navigator.clipboard.writeText(item.id).then(() => toast('Item ID copied.')).catch(showError); }));
    target.append(row);
  }
}
async function refreshHosts() {
  const hosts = await api('/hosts'); const target = $('#trustedList'); target.replaceChildren();
  if (!hosts.length) target.append(node('div', 'empty-state', 'No trusted host keys. Verify a server fingerprint before first access.'));
  for (const host of hosts) {
    const row = node('div', 'asset-row'); row.append(node('strong', '', host.host), node('span', 'mono', host.algorithm), node('span', 'mono', host.fingerprint),
      button('Revoke', 'mini-btn danger', safeAsync(async () => {
        if (!await confirmAction('Revoke SSH trust',`Remove ${host.fingerprint} from ${host.host}? Connections will fail until you trust the new fingerprint.`, 'Revoke')) return;
        await api('/hosts/revoke', { method: 'POST', body: host }); toast('Host trust revoked.'); await refreshHosts();
      }))); target.append(row);
  }
}
let scannedHost = null;
async function scanHost(event) {
  event.preventDefault(); const data = { host: $('#scanHost').value.trim(), port: Number($('#scanPort').value) };
  const key = await api('/hosts/discover', { method: 'POST', body: data }); scannedHost = key;
  const target = $('#scanResult'); target.classList.remove('hidden'); target.replaceChildren();
  target.append(node('strong', '', 'UNVERIFIED REMOTE KEY · ' + key.host + ':' + key.port), node('code', '', key.fingerprint), node('p', '', 'Compare this fingerprint against a trusted out-of-band source (server console, administrator, or known-good inventory). Do not approve an unexpected fingerprint.'));
  target.append(button('I verified this fingerprint — trust host', 'action-primary', async () => {
    if (!await confirmAction('Trust SSH fingerprint', 'Have you verified ' + key.fingerprint + ' for ' + key.host + ' using another trusted channel?', 'Trust key')) return;
    await api('/hosts/trust', { method: 'POST', body: { host: key.host, port: key.port, key_type: key.key_type, public_key: key.public_key } });
    target.classList.add('hidden'); scannedHost = null; toast('Host key saved.'); refreshHosts().catch(showError);
  }));
}
async function refreshKeys() {
  const items = await api('/keys'); const target = $('#keysList'); target.replaceChildren();
  $('#keyCount').textContent = items.length + ' keys';
  if (!items.length) target.append(node('div', 'empty-state', 'No SSH keys stored. Generate Ed25519 or import an existing private key.'));
  for (const item of items) {
    const row = node('div', 'key-row');
    const left = node('div'); left.append(node('strong', '', item.name), node('small', '', item.used_by + ' assigned assets'));
    const pub = node('code', 'key-public', item.public_key);
    const actions = node('div', 'asset-row-actions');
    actions.append(button('Copy public key', 'mini-btn', safeAsync(async () => {
      await navigator.clipboard.writeText(item.public_key); toast('Public key copied.');
    })));
    const remove = button('Delete', 'mini-btn danger', safeAsync(async () => {
      if (!await confirmAction('Delete private key', `Permanently delete ${item.name}? This cannot be undone.`, 'Delete key')) return;
      await api(`/keys/${encodeURIComponent(item.name)}`, { method: 'DELETE' }); await refreshKeys(); toast('SSH key deleted.');
    }));
    remove.disabled = item.used_by > 0;
    actions.append(remove); row.append(left, pub, actions); target.append(row);
  }
}
async function refreshAudit(more = false) {
  if (!more) auditBefore = null;
  const query = new URLSearchParams({limit: '100'});
  if (auditFilter) query.set('action', auditFilter);
  if (auditBefore !== null) query.set('before', String(auditBefore));
  const entries = await api('/audit?' + query);
  const target = $('#auditList'); if (!more) target.replaceChildren();
  if (!entries.length && !more) target.append(node('div', 'empty-state', 'No audit events match this filter.'));
  for (const entry of entries) {
    const row = node('div', 'asset-row'); const a = node('div'); a.append(node('strong', '', entry.action), node('small', '', new Date(entry.at * 1000).toLocaleString()));
    row.append(a, node('div', 'mono', entry.actor), node('div', '', entry.target || '—'), node('span', entry.outcome === 'ok' ? '' : 'status-bad', entry.outcome)); target.append(row);
  }
  if (entries.length) auditBefore = entries.at(-1).id;
  $('#auditMore').disabled = entries.length < 100;
}
async function savePrivateDownload(path, filename) {
  const response = await fetch('/api' + path, { credentials: 'same-origin', cache: 'no-store' });
  if (response.status === 401) {
    const data = await response.json().catch(() => ({}));
    if (path !== '/login') setLogin();
    throw Error(typeof data.detail === 'string' ? data.detail : 'Authentication required');
  }
  if (!response.ok) { const result = await response.json().catch(() => ({})); throw Error(result.detail || 'Download failed (' + response.status + ')'); }
  const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = node('a');
  link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}
function renderHealthSelect() {
  const el = $('#healthAsset'); const selected = el.value;
  el.replaceChildren(node('option', '', 'Select a Linux host'));
  for (const a of state.assets) { const opt = node('option', '', a.label + ' · ' + a.host); opt.value = a.id; el.append(opt); }
  if (state.assets.some(a => a.id === selected)) el.value = selected;
}
function durationLabel(seconds) {
  const d = Math.floor(seconds / 86400); const h = Math.floor(seconds % 86400 / 3600);
  return `${d}d ${h}h`;
}
function bytesLabel(size) {
  if (!Number.isFinite(size) || size < 0) return '—';
  return (size / 1073741824).toFixed(1) + ' GiB';
}
async function refreshHealthHistory() {
  const a = state.assets.find(a => a.id === $('#healthAsset').value);
  const target = $('#healthHistory'); target.replaceChildren();
  if (!a) { target.append(node('div', 'empty-state', 'Select a Linux host to view recent observations.')); return; }
  const rows = await api(`/assets/${a.id}/health/history?limit=50`);
  if (!rows.length) { target.append(node('div', 'empty-state', 'No health checks recorded. Select Check health to take one.')); return; }
  for (const item of rows) {
    const row = node('div', 'health-history-row');
    const status = node('strong', item.status === 'online' ? 'status-good' : 'status-bad', item.status);
    row.append(node('span', 'mono', new Date(item.at * 1000).toLocaleString()), status,
      node('span', 'mono', item.status === 'online' ? `Load ${item.load1} · Free RAM ${bytesLabel(item.memory_available)}` : 'SSH check failed'));
    target.append(row);
  }
}
async function checkHealth() {
  const a = state.assets.find(a => a.id === $('#healthAsset').value);
  if (!a) { toast('Select a Linux host first.', true); return; }
  const headers = await fileAuth(a); if (headers === null) return;
  $('#healthRefresh').disabled = true; $('#healthStatus').textContent = 'Checking Linux host over SSH…';
  try {
    const data = await api(`/assets/${a.id}/health`, { headers });
    $('#healthStatus').textContent = `${data.hostname} · ${data.kernel} · Last checked ${new Date(data.at * 1000).toLocaleString()}`;
    const target = $('#healthMetrics'); target.replaceChildren();
    for (const [label, value, detail] of [
      ['Uptime', durationLabel(data.uptime_seconds), 'Since last boot'],
      ['Load average', [data.load1, data.load5, data.load15].join(' / '), '1 / 5 / 15 minutes'],
      ['Available memory', bytesLabel(data.memory_available), `of ${bytesLabel(data.memory_total)} total`],
      ['Root disk used', bytesLabel(data.disk_used), `of ${bytesLabel(data.disk_total)} total`]]) {
      const item = node('div', 'health-metric'); item.append(node('small', '', label), node('strong', '', value), node('span', '', detail)); target.append(item);
    }
  } catch (error) { $('#healthStatus').textContent = 'Health check failed: ' + error.message; showError(error); }
  finally { $('#healthRefresh').disabled = false; await refreshHealthHistory(); }
}
async function openFileEditor(asset, path) {
  const headers = await fileAuth(asset); if (headers === null) return;
  const dialog = $('#fileEditorDialog');
  $('#fileEditorTitle').textContent = 'Opening text file';
  $('#fileEditorPath').textContent = asset.label + ' · ' + path;
  $('#fileEditorContent').value = ''; $('#saveFileEdit').disabled = true;
  dialog.showModal();
  try {
    const result = await api(`/assets/${asset.id}/files/edit?path=${encodeURIComponent(path)}`, {headers});
    activeFileEdit = {aid:asset.id, path, sha256:result.sha256, asset};
    $('#fileEditorTitle').textContent = 'Edit ' + path.split('/').pop();
    $('#fileEditorContent').value = result.content;
    $('#saveFileEdit').disabled = false;
  } catch (error) { activeFileEdit = null; dialog.close(); showError(error); }
}
async function saveFileEditor(event) {
  event.preventDefault();
  if (!activeFileEdit) return;
  const data = activeFileEdit;
  if (!await confirmAction('Save remote file', 'Replace ' + data.path + ' on ' + data.asset.host + '?', 'Save file')) return;
  const headers = await fileAuth(data.asset); if (headers === null) return;
  $('#saveFileEdit').disabled = true;
  try {
    const result = await api(`/assets/${data.aid}/files/edit`, {method:'PUT', headers,
      body:{path:data.path, content:$('#fileEditorContent').value, original_sha256:data.sha256}});
    data.sha256 = result.sha256;
    $('#fileEditorDialog').close(); toast('Remote text saved atomically.');
    await browseFiles();
  } catch (error) { showError(error); }
  finally { $('#saveFileEdit').disabled = false; }
}
function resetRunbookForm() {
  editingRunbookId = null;
  $('#runbookForm').reset(); $('#runbookFormTitle').textContent = 'Create a runbook';
  $('#runbookConfirm').checked = true;
}
async function saveRunbook(event) {
  event.preventDefault();
  const body = {name:$('#runbookName').value, description:$('#runbookDescription').value,
    command:$('#runbookCommand').value, requires_confirmation:$('#runbookConfirm').checked};
  const id = editingRunbookId;
  await api('/runbooks' + (id ? '/' + id : ''), {method: id ? 'PUT' : 'POST', body});
  resetRunbookForm(); await refreshRunbooks(); toast(id ? 'Runbook updated.' : 'Runbook created.');
}
function editRunbook(item) {
  editingRunbookId = item.id; $('#runbookFormTitle').textContent = 'Edit ' + item.name;
  $('#runbookName').value = item.name; $('#runbookDescription').value = item.description;
  $('#runbookCommand').value = item.command; $('#runbookConfirm').checked = !!item.requires_confirmation;
  $('#runbookForm').scrollIntoView({behavior:'auto', block:'start'});
}
async function executeRunbook(item, select) {
  const asset = state.assets.find(a => a.id === select.value);
  if (!asset) { toast('Choose a target asset.', true); return; }
  if (item.requires_confirmation && !await confirmAction('Execute runbook',`${item.name} on ${asset.label} (${asset.host})?\n${item.command}`, 'Execute')) return;
  const headers = await fileAuth(asset); if (headers === null) return;
  $('#runbookOutput').textContent = 'Executing on ' + asset.host + '…';
  try {
    const result = await api(`/runbooks/${item.id}/execute`, {method:'POST', headers, body:{asset_id:asset.id, confirm:true}});
    $('#runbookResultMeta').textContent = `${item.name} · ${asset.label} · exit ${result.exit_code}`;
    $('#runbookOutput').textContent = `Exit ${result.exit_code}\n\n${result.stdout || '(no stdout)'}${result.stderr ? '\n\nSTDERR:\n' + result.stderr : ''}`;
    toast(result.exit_code === 0 ? 'Runbook completed.' : 'Command exited with code ' + result.exit_code, result.exit_code !== 0);
  } catch (error) { $('#runbookOutput').textContent = 'Runbook failed: ' + error.message; showError(error); }
  await refreshRunbookHistory();
}
async function refreshRunbookHistory() {
  const target = $('#runbookHistory'); target.replaceChildren();
  const rows = await api('/runbooks/history?limit=50');
  if (!rows.length) { target.append(node('div', 'empty-state', 'No commands have been executed yet.')); return; }
  for (const item of rows) {
    const row = node('div', 'health-history-row');
    row.append(node('span', 'mono', new Date(item.started_at * 1000).toLocaleString()),
      node('strong', '', item.runbook_name), node('span', '', `${item.asset_name} · ${item.outcome} · ${item.duration_ms} ms`));
    target.append(row);
  }
}
async function refreshRunbooks() {
  runbooks = await api('/runbooks');
  const target = $('#runbookList'); target.replaceChildren();
  if (!runbooks.length) target.append(node('div', 'empty-state', 'No procedures saved. Add a runbook to create one.'));
  for (const item of runbooks) {
    const row = node('div', 'runbook-row'); const info = node('div');
    info.append(node('strong', '', item.name), node('small', '', item.description || 'No description'));
    const select = node('select'); select.setAttribute('aria-label', 'Execution target for ' + item.name);
    select.append(node('option', '', 'Choose host'));
    for (const a of state.assets) { const opt = node('option', '', a.label + ' · ' + a.host); opt.value = a.id; select.append(opt); }
    const controls = node('div', 'file-tools');
    controls.append(button('Run', 'mini-btn', safeAsync(() => executeRunbook(item, select))),
      button('Edit', 'mini-btn', () => editRunbook(item)),
      button('Delete', 'mini-btn danger', safeAsync(async () => {
        if (!await confirmAction('Delete runbook', 'Delete ' + item.name + '? Execution history is retained.', 'Delete')) return;
        await api('/runbooks/' + item.id, {method:'DELETE'});
        if (editingRunbookId === item.id) resetRunbookForm();
        await refreshRunbooks(); toast('Runbook deleted.');
      })));
    row.append(info, select, controls); target.append(row);
  }
  await refreshRunbookHistory();
}

/* Switchyard remote desktops: persistent inventory and ephemeral browser sessions. */
let desktopRecords = [];
let desktopEditing = null;
let desktopTabs = new Map();
let currentDesktopTab = null;

function desktopAuthChange() {
  $('#desktopPasswordGroup').classList.toggle('hidden', $('#desktopAuth').value !== 'interactive');
  $('#desktopVaultGroup').classList.toggle('hidden', $('#desktopAuth').value !== 'vault');
}
function desktopProtocolChange() {
  const protocol = $('#desktopProtocol').value;
  const rdp = protocol === 'rdp', spice = protocol === 'spice';
  $$('.desktop-rdp-only', $('#desktopDialog')).forEach(el => el.classList.toggle('hidden', !rdp));
  $$('.desktop-spice-only', $('#desktopDialog')).forEach(el => el.classList.toggle('hidden', !spice));
  const readOnly = $('#desktopForm').elements.read_only;
  readOnly.disabled = spice;
  if (spice) readOnly.checked = false;
  const port = $('#desktopPort');
  if (['3389', '5900', '5901', ''].includes(port.value)) port.value = rdp ? '3389' : (spice ? '5901' : '5900');
  if (!rdp) {
    $('#desktopForm').elements.domain.value = '';
    $('#desktopForm').elements.security.value = 'nla';
    $('#desktopForm').elements.ignore_cert.checked = false;
  }
}
function openDesktopEditor(record = null) {
  desktopEditing = record?.id || null;
  const form = $('#desktopForm'); form.reset();
  if (record) {
    Object.entries(record).forEach(([key, value]) => {
      const field = form.elements.namedItem(key);
      if (!field) return;
      if (field.type === 'checkbox') field.checked = !!value;
      else field.value = value;
    });
  }
  $('#desktopModalTitle').textContent = record ? 'Edit desktop' : 'Add a desktop';
  $('#desktopPassword').value = '';
  $('#desktopSavedPasswordState').textContent = record?.has_saved_password ? 'Saved credential will be retained unless replaced.' : 'Encrypted in appliance storage.';
  desktopAuthChange(); desktopProtocolChange(); $('#desktopDialog').showModal();
}
async function saveDesktop(event) {
  event.preventDefault();
  const submit = $('#desktopSave'); submit.disabled = true;
  try {
    const form = $('#desktopForm');
    const data = Object.fromEntries(new FormData(form));
    for (const field of ['port', 'width', 'height', 'dpi']) data[field] = Number(data[field]);
    data.ignore_cert = form.elements.ignore_cert.checked && data.protocol === 'rdp';
    data.spice_tls = form.elements.spice_tls.checked && data.protocol === 'spice';
    data.read_only = form.elements.read_only.checked && data.protocol !== 'spice';
    data.credential_ref ||= '';
    data.clear_password = form.elements.clear_password.checked;
    if (!data.password) delete data.password;
    data.favorite = desktopEditing ? !!desktopRecords.find(item => item.id === desktopEditing)?.favorite : false;
    if (data.protocol !== 'rdp') { data.domain = ''; data.security = 'nla'; data.ignore_cert = false; }
    await api('/desktops' + (desktopEditing ? '/' + desktopEditing : ''), {
      method: desktopEditing ? 'PUT' : 'POST', body: data,
    });
    $('#desktopDialog').close(); await refreshDesktops();
    toast(desktopEditing ? 'Desktop updated.' : 'Desktop saved.');
  } finally { submit.disabled = false; }
}
async function deleteDesktop(record) {
  if (!await confirmAction('Remove desktop connection',`Delete ${record.label}? This will not modify the remote computer.`, 'Delete connection')) return;
  await api('/desktops/' + record.id, { method: 'DELETE' });
  await refreshDesktops(); toast('Saved desktop removed.');
}
function renderDesktopList() {
  const query = $('#desktopSearch').value.toLowerCase().trim();
  const visible = desktopRecords.filter(x => normalizedHost(x.host) === state.machineHost && [x.label, x.host, x.username, x.environment, x.protocol].join(' ').toLowerCase().includes(query));
  $('#desktopTotal').textContent = `${visible.length} connections for this machine`;
  $('#desktopCount').textContent = desktopRecords.length;
  const target = $('#desktopList'); target.replaceChildren();
  if (!visible.length) {
    target.append(node('div', 'empty-state', query ? 'No matching desktop connections.' : 'No desktops saved. Choose Add desktop to configure RDP, VNC or SPICE.'));
    return;
  }
  for (const d of visible) {
    const row = node('div', 'asset-row desktop-row');
    const name = node('div'); name.append(node('strong', '', d.label), node('small', '', d.protocol.toUpperCase() + ' · ' + (d.username || 'No username') + ' · ' + (d.auth_type === 'vault' ? 'Vaultwarden' : d.auth_type)));
    const address = node('div', 'host-column mono', `${d.host}:${d.port}`);
    const env = node('div', 'environment-column env-tag', d.environment || '—');
    const actions = node('div', 'asset-row-actions');
    const favoriteButton = button(d.favorite ? '★ Favorite' : '☆ Favorite', 'mini-btn', async () => {
      favoriteButton.disabled = true;
      try {
        await api(`/desktops/${d.id}`, {method:'PUT', body:{...d, favorite:!d.favorite}});
        await refreshDesktops();
        toast(d.favorite ? 'Removed from favorites.' : 'Added to favorites.');
      } catch (error) { favoriteButton.disabled = false; showError(error); }
    });
    favoriteButton.setAttribute('aria-pressed', String(!!d.favorite));
    favoriteButton.setAttribute('aria-label', (d.favorite ? 'Unfavorite ' : 'Favorite ') + d.label);
    actions.append(favoriteButton, button('Open desktop ↗', 'mini-btn', () => openDesktop(d).catch(showError)),
      button('Check port', 'mini-btn', async function () {
        this.disabled = true; const previous = this.textContent; this.textContent = 'Checking…';
        try {
          const result = await api(`/desktops/${d.id}/probe`, {method:'POST', body:{}});
          this.textContent = result.reachable ? `Reachable · ${result.elapsed_ms} ms` : 'Unreachable';
          this.title = result.message;
          toast(`${d.label}: ${result.message}`, !result.reachable);
        } catch (err) { this.textContent = previous; showError(err); }
        finally { this.disabled = false; }
      }),
      button('Duplicate', 'mini-btn', async function () {
        this.disabled = true;
        try {
          const copy = await api(`/desktops/${d.id}/duplicate`, {method:'POST', body:{}});
          await refreshDesktops();
          toast(`Created “${copy.label}”.`);
          openDesktopEditor(copy);
        } catch (error) { this.disabled = false; showError(error); }
      }),
      button('Edit', 'mini-btn', () => openDesktopEditor(d)),
      button('Delete', 'mini-btn danger', () => deleteDesktop(d).catch(showError)));
    row.append(name, address, env, actions); target.append(row);
  }
}
async function refreshDesktopGateway() {
  const target = $('#desktopGateway');
  target.textContent = 'Checking private RDP/VNC gateway…';
  target.classList.remove('desktop-gateway-error');
  try {
    const result = await api('/desktops/gateway/status');
    target.textContent = result.ready
      ? 'RDP / VNC gateway: available · private Docker network'
      : 'RDP / VNC gateway: unavailable · inspect guacd service';
    target.classList.toggle('desktop-gateway-error', !result.ready);
  } catch (error) {
    target.textContent = 'RDP / VNC gateway: status unavailable';
    target.classList.add('desktop-gateway-error');
  }
}
async function refreshDesktops() {
  // Never block host inventory on an independent gateway health check.
  desktopRecords = await api('/desktops');
  renderDesktopList(); renderMachineDirectory();
  if (state.machineHost) renderMachineOverview();
  void refreshDesktopGateway().catch(showError);
}
async function refreshDesktopActive() {
  const sessions = await api('/desktops/sessions/active');
  const target = $('#desktopActiveSessions'); target.replaceChildren();
  if (!sessions.length) {
    target.append(node('div','empty-state','No server-side remote desktop sessions.'));
    return;
  }
  for (const session of sessions) {
    const row = node('div','asset-row desktop-history-row');
    const title = node('div'); title.append(
      node('strong','', session.label || 'Remote desktop'),
      node('small','', session.protocol.toUpperCase() + ' · Active connection'));
    const started = node('div','mono',new Date(session.started_at*1000).toLocaleString());
    const disconnect = button('Disconnect session','mini-btn danger',async function () {
      if (!await confirmAction('Disconnect remote desktop',`Disconnect “${session.label}” now?`, 'Disconnect')) return;
      this.disabled = true;
      try {
        await api(`/desktops/sessions/${session.id}/disconnect`,{method:'POST',body:{}});
        await refreshDesktopActive(); toast('Remote session disconnected.');
      } catch (error) { this.disabled=false; showError(error); }
    });
    row.append(title, started, disconnect); target.append(row);
  }
}
async function refreshDesktopHistory() {
  const params = new URLSearchParams({limit:'50'});
  const protocol = $('#desktopHistoryProtocol').value;
  const outcome = $('#desktopHistoryOutcome').value;
  if (protocol) params.set('protocol', protocol);
  if (outcome) params.set('outcome', outcome);
  const items = await api('/desktops/sessions/history?' + params);
  const target = $('#desktopHistory'); target.replaceChildren();
  if (!items.length) {
    target.append(node('div','empty-state','No remote desktop sessions recorded yet.'));
    return;
  }
  for (const item of items) {
    const row = node('div','asset-row desktop-history-row');
    const title = node('div');
    title.append(node('strong','',item.label),
      node('small','',`${item.protocol.toUpperCase()} · ${item.channel_count} channel(s)`));
    const start = node('div','mono',new Date(item.started_at*1000).toLocaleString());
    const duration = item.ended_at ? `${Math.max(0,item.ended_at-item.started_at)}s` : 'In progress';
    const status = node('div','environment-column',`${item.outcome} · ${duration}`);
    row.append(title,start,status); target.append(row);
  }
}
function desktopCurrent() { return desktopTabs.get(currentDesktopTab); }
function desktopActionsEnabled(enabled, session) {
  $('#desktopCAD').disabled = !enabled || !!session?.record.read_only;
  $('#desktopClipboard').disabled = !enabled || !!session?.record.read_only || session?.record.protocol === 'spice';
  $('#desktopRemoteClipboard').disabled = !enabled || !session?.clipboardText;
  $('#desktopFullscreen').disabled = !enabled;
  $('#desktopDisconnect').disabled = !enabled;
  $('#desktopReconnect').disabled = !enabled;
}
function renderDesktopTabs() {
  const nav = $('#desktopSessionTabs'); const host = $('#desktopViewports'); nav.replaceChildren();
  for (const [id, session] of desktopTabs) {
    const tab = node('div', 'tab-group');
    const select = button(`${session.record.protocol.toUpperCase()} · ${session.record.label}`, 'tab-select' + (id === currentDesktopTab ? ' active' : ''), () => selectDesktopTab(id));
    select.setAttribute('role', 'tab'); select.setAttribute('aria-selected', String(id === currentDesktopTab));
    select.setAttribute('aria-controls', 'desktop-' + id);
    const close = button('×', 'tab-close', () => closeDesktopTab(id)); close.setAttribute('aria-label', `Disconnect ${session.record.label}`);
    tab.append(select, close); nav.append(tab);
    session.surface.classList.toggle('active', id === currentDesktopTab);
  }
  $('#desktopSessionCount').textContent = `${desktopTabs.size} session${desktopTabs.size === 1 ? '' : 's'} open`;
  $('#desktopConnectionState').textContent = desktopCurrent()?.status || 'No active session';
  desktopActionsEnabled(!!desktopCurrent(), desktopCurrent()); renderWorkbenchSessions();
  const empty = host.querySelector('.empty-state');
  if (empty) empty.classList.toggle('hidden', desktopTabs.size > 0);
}
function selectDesktopTab(id) {
  if (!desktopTabs.has(id)) return;
  currentDesktopTab = id; const session = desktopTabs.get(id);
  if (session?.record?.host) state.machineHost = normalizedHost(session.record.host);
  updateMachineHeader(); navigate('desktops'); renderDesktopTabs();
  requestAnimationFrame(() => { fitDesktop(session); session.surface.focus(); });
}
function closeDesktopTab(id) {
  const session = desktopTabs.get(id); if (!session) return;
  session.keyboard?.reset();
  if (session.frame) {
    session.frame.contentWindow?.postMessage({kind:'switchyard-spice-stop'}, location.origin);
    session.frame.src = 'about:blank';
  } else session.client.disconnect();
  session.surface.remove();
  session.resizeObserver?.disconnect(); desktopTabs.delete(id);
  if (currentDesktopTab === id) currentDesktopTab = desktopTabs.keys().next().value || null;
  renderDesktopTabs();
  if (currentDesktopTab) selectDesktopTab(currentDesktopTab);
}
function closeAllDesktops() {
  for (const id of [...desktopTabs.keys()]) closeDesktopTab(id);
}
function fitDesktop(session) {
  if (!session || session.frame || !session.client) return;
  const screen = session.client.getDisplay();
  const width = screen.getWidth(), height = screen.getHeight();
  if (!width || !height) return;
  const maxWidth = session.surface.clientWidth - 16, maxHeight = session.surface.clientHeight - 16;
  screen.scale(Math.max(0.15, Math.min(maxWidth / width, maxHeight / height, 1.5)));
}
async function openDesktop(record, {retry = false, newSession = false} = {}) {
  const existing=[...desktopTabs.values()].find(session =>
    String(session.record.id)===String(record.id) && session.record.protocol===record.protocol);
  const disconnected=existing && (existing.status==='Disconnected' || existing.status.startsWith('Connection error') || existing.status==='SPICE connection failed');
  if(existing && !retry && !newSession && !disconnected){selectDesktopTab(existing.id);return existing.id;}
  if (record.protocol !== 'spice' && (!window.Guacamole?.Client || !window.Guacamole?.WebSocketTunnel)) {
    throw Error('The Guacamole browser library is not installed. Rebuild the full Switchyard image.');
  }
  let password;
  if (record.auth_type === 'interactive') {
    password = record.has_saved_password ? undefined : await askDialog({title:'Desktop credentials',description:`Password for ${record.protocol.toUpperCase()} on ${record.host}.`,label:'Password',secret:true,action:'Connect'});
    if (password === null) return;
  }
  if (desktopTabs.size >= 8 && !(existing && !newSession)) throw Error('At most 8 remote desktops can remain connected.');
  const size = {
    width: record.width, height: record.height, dpi: record.dpi,
  };
  const response = await api(`/desktops/${record.id}/ticket`, { method: 'POST', body: { ...size, ...(password !== undefined ? {password} : {}) } });
  password = null;
  if(existing && !newSession)closeDesktopTab(existing.id); // Only after the replacement ticket succeeds.
  if (record.protocol === 'spice') {
    return openSpiceDesktop(record, response);
  }
  const id = clientSessionId();
  const surface = node('div', 'desktop-surface'); surface.id = 'desktop-' + id;
  surface.tabIndex = 0; surface.setAttribute('role', 'tabpanel');
  surface.setAttribute('aria-label', `${record.label} ${record.protocol.toUpperCase()} remote desktop`);
  surface.append(node('p', 'desktop-initial-message', 'Negotiating encrypted browser connection…'));
  $('#desktopViewports').append(surface);
  const url = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws/desktop/${encodeURIComponent(response.ticket)}`;
  const tunnel = new window.Guacamole.WebSocketTunnel(url);
  const client = new window.Guacamole.Client(tunnel);
  const session = {id, record, client, keyboard: null, surface, status: 'Connecting…', resizeObserver: null, clipboardText: ''};
  desktopTabs.set(id, session); currentDesktopTab = id;
  selectDesktopTab(id);
  client.onerror = status => {
    session.status = `Connection error (${status?.code ?? 'unknown'})`;
    if (currentDesktopTab === id) $('#desktopConnectionState').textContent = session.status;
    toast(`${record.label}: ${session.status}`, true);
  };
  client.onstatechange = value => {
    const states = {0: 'Idle', 1: 'Connecting…', 2: 'Waiting for desktop…', 3: 'Connected', 4: 'Disconnecting', 5: 'Disconnected'};
    session.status = states[value] || 'Unknown connection state';
    if (currentDesktopTab === id) $('#desktopConnectionState').textContent = session.status;
  };
  client.onclipboard = (stream, mime) => {
    if (!mime || !mime.startsWith('text/')) return;
    // Explicitly require a user click before copying a remote secret into
    // the local operating-system clipboard. Content is never persisted.
    let text = '', tooLarge = false;
    const reader = new window.Guacamole.StringReader(stream);
    reader.ontext = chunk => {
      if (tooLarge) return;
      text += chunk;
      if (new TextEncoder().encode(text).length > 65536) {
        tooLarge = true; text = '';
      }
    };
    reader.onend = () => {
      session.clipboardText = tooLarge ? '' : text;
      if (session.id === currentDesktopTab) desktopActionsEnabled(true, session);
    };
  };
  client.onresize = () => fitDesktop(session);
  const display = client.getDisplay().getElement();
  surface.replaceChildren(display);
  const mouse = new window.Guacamole.Mouse(display);
  for (const eventName of ['onmousedown', 'onmouseup', 'onmousemove']) {
    mouse[eventName] = state => { if (!record.read_only) client.sendMouseState(state, true); };
  }
  const keyboard = new window.Guacamole.Keyboard(surface);
  keyboard.onkeydown = keysym => { if (!record.read_only) client.sendKeyEvent(1, keysym); return false; };
  keyboard.onkeyup = keysym => { if (!record.read_only) client.sendKeyEvent(0, keysym); return false; };
  surface.addEventListener('blur', () => keyboard.reset());
  session.keyboard = keyboard;
  session.resizeObserver = new ResizeObserver(() => fitDesktop(session));
  session.resizeObserver.observe(surface);
  try { client.connect(); }
  catch (err) { closeDesktopTab(id); throw err; }
}

/* SPICE uses an isolated iframe because its upstream HTML5 client owns fixed
 * DOM IDs and keyboard listeners. Every frame has a single-use server ticket.
 */
function openSpiceDesktop(record, response) {
  const id = clientSessionId();
  const surface = node('div', 'desktop-surface');
  surface.id = 'desktop-' + id; surface.tabIndex = 0;
  surface.setAttribute('role', 'tabpanel');
  surface.setAttribute('aria-label', `${record.label} SPICE remote console`);
  const frame = document.createElement('iframe');
  frame.className = 'spice-viewport';
  frame.title = `${record.label} SPICE console`;
  frame.src = '/static/spice-view.html';
  frame.referrerPolicy = 'no-referrer';
  frame.allowFullscreen = true;
  surface.append(frame);
  $('#desktopViewports').append(surface);
  const session = {id, record, surface, frame, status: 'Loading SPICE viewer…', client: null, keyboard: null};
  desktopTabs.set(id, session); currentDesktopTab = id;
  // The upstream module announces readiness only after it is initialized.
  session.spiceCredentials = {token: response.ticket, password: response.spice_password || ''};
  selectDesktopTab(id);
  return id;
}
window.addEventListener('message', event => {
  if (event.origin !== location.origin || !event.data || typeof event.data !== 'object') return;
  for (const session of desktopTabs.values()) {
    if (!session.frame || event.source !== session.frame.contentWindow) continue;
    if (event.data.kind === 'switchyard-spice-ready' && session.spiceCredentials) {
      session.frame.contentWindow.postMessage({
        kind: 'switchyard-spice-start', ...session.spiceCredentials,
      }, location.origin);
      session.spiceCredentials = null;
    } else if (event.data.kind === 'switchyard-spice-status' && typeof event.data.status === 'string') {
      session.status = event.data.status.slice(0, 100);
      if (session.id === currentDesktopTab) $('#desktopConnectionState').textContent = session.status;
    }
    break;
  }
});

function desktopCAD() {
  const session = desktopCurrent(); if (!session || session.record.read_only) return;
  if (session.frame) {
    session.frame.contentWindow?.postMessage({kind:'switchyard-spice-cad'}, location.origin);
    return;
  }
  const client = session.client;
  // X11 keysyms: Control_L, Alt_L, Delete.
  for (const key of [0xffe3, 0xffe9, 0xffff]) client.sendKeyEvent(1, key);
  for (const key of [0xffff, 0xffe9, 0xffe3]) client.sendKeyEvent(0, key);
}
async function desktopSendClipboard() {
  const session = desktopCurrent(); if (!session || session.record.read_only) return;
  const text = await askDialog({title:'Send clipboard text',description:'Send text to the remote desktop. Up to 16 KiB.',label:'Clipboard text',action:'Send'});
  if (text === null) return;
  if (new TextEncoder().encode(text).length > 16384) { toast('Clipboard text exceeds 16 KiB.', true); return; }
  session.client.setClipboard(text); toast('Text sent to remote clipboard.');
}
async function importSpiceVirtViewer() {
  const picker = $('#spiceVVFile');
  const file = picker.files?.[0];
  if (!file) return;
  try {
    if (file.size > 16384) throw Error('Virt-viewer file exceeds 16 KiB.');
    if (desktopTabs.size >= 8) throw Error('At most 8 desktop sessions may remain connected.');
    const contents = await file.text();
    const response = await api('/desktops/spice/import-vv', {method:'POST',body:{contents}});
    openSpiceDesktop({
      id: clientSessionId(), label: response.label, protocol: 'spice', read_only: false,
      auth_type: 'interactive', environment: 'Imported session',
    }, response);
    toast('SPICE connection imported into a temporary session.');
  } finally {
    picker.value = '';
  }
}
async function desktopCopyRemoteClipboard() {
  const session = desktopCurrent();
  if (!session?.clipboardText || session.record.protocol === 'spice') return;
  try {
    await navigator.clipboard.writeText(session.clipboardText);
    toast('Remote text copied to the local clipboard.');
  } catch {
    const text = await askDialog({title:'Copy remote clipboard',description:'Select the text in this dialog and copy it manually.',label:'Remote text',value:session.clipboardText,action:'Close'});
  }
}
function bindDesktopUI() {
  $('#desktopNew').addEventListener('click', () => openDesktopEditor());
  $('#spiceImport').addEventListener('click', () => $('#spiceVVFile').click());
  $('#spiceVVFile').addEventListener('change', safeAsync(importSpiceVirtViewer));
  $('#desktopRefresh').addEventListener('click', safeAsync(refreshDesktops));
  $('#desktopHistoryRefresh').addEventListener('click', safeAsync(refreshDesktopHistory));
  $('#desktopActiveRefresh').addEventListener('click', safeAsync(refreshDesktopActive));
  $('#desktopHistoryProtocol').addEventListener('change', safeAsync(refreshDesktopHistory));
  $('#desktopHistoryOutcome').addEventListener('change', safeAsync(refreshDesktopHistory));
  $('#desktopHistoryExport').addEventListener('click', () => { window.location.assign('/api/desktops/sessions/export'); });
  $('#desktopBatchProbe').addEventListener('click', async function () {
    const button = this;
    const query = $('#desktopSearch').value.toLowerCase().trim();
    const visible = desktopRecords.filter(x =>
      [x.label,x.host,x.username,x.environment,x.protocol].join(' ').toLowerCase().includes(query));
    if (!visible.length) return toast('No visible desktops to check.');
    button.disabled = true; button.textContent = `Checking ${Math.min(20,visible.length)}…`;
    try {
      const result = await api('/desktops/probes', {method:'POST',
        body:{ids:visible.slice(0,20).map(x => x.id)}});
      const reachable = result.results.filter(x => x.reachable).length;
      toast(`${reachable} of ${result.count} reachable; port checks are not logins.`, reachable !== result.count);
    } catch (error) { showError(error); }
    finally { button.disabled=false; button.textContent='Check first 20'; }
  });
  $('#desktopExport').addEventListener('click', () => { window.location.assign('/api/desktops/export'); });
  $('#desktopImport').addEventListener('click', () => $('#desktopImportFile').click());
  $('#desktopImportFile').addEventListener('change', async function () {
    const file = this.files?.[0]; this.value = '';
    if (!file) return;
    if (file.size > 1024 * 1024) return showError(Error('Inventory file must be at most 1 MiB.'));
    try {
      const parsed = JSON.parse(await file.text());
      if (parsed.format !== 'switchyard-desktops-v1' || !Array.isArray(parsed.connections))
        throw Error('Not a Switchyard desktop inventory export.');
      if (!await confirmAction('Import connections', `Import ${parsed.connections.length} desktops? Existing entries will not be overwritten.`, 'Import')) return;
      const result = await api('/desktops/import', {method:'POST', body:parsed});
      await refreshDesktops(); toast(`Imported ${result.created} desktop configurations.`);
    } catch (error) { showError(error); }
  });
  $('#desktopSearch').addEventListener('input', renderDesktopList);
  $('#desktopProtocol').addEventListener('change', desktopProtocolChange);
  $('#desktopAuth').addEventListener('change', desktopAuthChange);
  $('#desktopModalClose').addEventListener('click', () => $('#desktopDialog').close());
  $('#desktopCancel').addEventListener('click', () => $('#desktopDialog').close());
  $('#desktopForm').addEventListener('submit', safeAsync(saveDesktop));
  $('#desktopCAD').addEventListener('click', desktopCAD);
  $('#desktopClipboard').addEventListener('click', desktopSendClipboard);
  $('#desktopRemoteClipboard').addEventListener('click', safeAsync(desktopCopyRemoteClipboard));
  $('#desktopReconnect').addEventListener('click', () => {const session=desktopCurrent();if(session)openDesktop(session.record,{retry:true}).catch(showError);});
  $('#desktopDisconnect').addEventListener('click', () => { if (currentDesktopTab) closeDesktopTab(currentDesktopTab); });
  $('#desktopFullscreen').addEventListener('click', safeAsync(async () => { const session = desktopCurrent(); if (!session) return; if (document.fullscreenElement) await document.exitFullscreen(); else await session.surface.requestFullscreen(); fitDesktop(session); }));
  document.addEventListener('fullscreenchange', () => fitDesktop(desktopCurrent()));
  $('#desktopSessionTabs').addEventListener('keydown', event => {
    if (!['ArrowRight','ArrowLeft'].includes(event.key)) return;
    const ids = [...desktopTabs.keys()]; if (!ids.length) return;
    const index = ids.indexOf(currentDesktopTab);
    event.preventDefault(); selectDesktopTab(ids[(index + (event.key === 'ArrowRight' ? 1 : -1) + ids.length) % ids.length]);
  });
  window.addEventListener('resize', () => fitDesktop(desktopCurrent()));
}

async function refreshMfaStatus() {
  const state = await api('/mfa/status');
  $('#mfaStatus').textContent = state.enabled
    ? 'Enabled. Remote HTTPS sign-in requires a 6-digit authenticator code.'
    : 'Off (optional). Password-only sign-in works on the LAN and through your configured HTTPS proxy.';
  $('#mfaSetupForm').classList.toggle('hidden', state.enabled);
  $('#mfaDisableForm').classList.toggle('hidden', !state.enabled);
  if (state.enabled) { $('#mfaEnrollment').classList.add('hidden'); $('#mfaQr').removeAttribute('src'); $('#mfaQr').classList.add('hidden'); }
}

let setupStep = 0;
function showSetupStep(step) {
  setupStep = step;
  $$('[data-setup-step]').forEach(el => el.classList.toggle('hidden', Number(el.dataset.setupStep) !== step));
  $('#setupProgress').textContent = `0${step + 1} / 03`;
  $('#setupBack').classList.toggle('hidden', step === 0);
  $('#setupNext').textContent = step === 2 ? 'Finish setup →' : 'Continue →';
  $('#setupError').textContent = '';
  // Hidden controls do not participate in HTML form constraint validation.
  $$('[data-setup-step] input').forEach(input => { input.disabled = Number(input.closest('[data-setup-step]').dataset.setupStep) !== step; });
}
function setSetup() {
  $('#login').classList.add('hidden'); $('#shell').classList.add('hidden');
  $('#setup').classList.remove('hidden'); showSetupStep(0);
  $('#setupCode').focus();
}
async function refreshNetwork() {
  const settings = await api('/network');
  $('#networkPublic').value = settings.public_origin || '';
  $('#networkLan').value = (settings.lan_origins || []).join('\n');
  $('#networkVaultHttp').checked = settings.allow_http_vault;
}
function aliases(value) { return value.split(/\r?\n/).map(x => x.trim()).filter(Boolean); }
async function bootstrap() {
  try {
    const setup = await api('/setup/status');
    if (setup.setup_required) { setSetup(); return; }
    try { await api('/me'); await setShell(); } catch { setLogin(); }
  } catch (error) {
    setLogin(); showError(error);
  }
}

function safeAsync(fn) { return event => { Promise.resolve(fn(event)).catch(showError); }; }
function bind() {
  initMachineWorkspace();
  bindDesktopUI();
  $('#clock').textContent = new Date().toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  $('#setupBack').addEventListener('click', () => showSetupStep(Math.max(0, setupStep - 1)));
  $('#setupForm').addEventListener('submit', safeAsync(async event => {
    event.preventDefault();
    const form = $('#setupForm');
    if (!form.reportValidity()) return;
    if (setupStep === 0 && $('#setupPassword').value !== $('#setupConfirm').value) {
      $('#setupError').textContent = 'Administrator passwords do not match.'; return;
    }
    if (setupStep < 2) { showSetupStep(setupStep + 1); return; }
    const next = $('#setupNext'); next.disabled = true;
    $('#setupError').textContent = '';
    try {
      await api('/setup/complete', {method:'POST', body:{
        claim_code:$('#setupCode').value.trim(),username:$('#setupUsername').value.trim(),
        password:$('#setupPassword').value, lan_origins:aliases($('#setupLanOrigins').value),
        public_origin:$('#setupPublicOrigin').value.trim()
      }});
      $('#loginUsername').value = $('#setupUsername').value.trim();
      $('#setupCode').value = ''; $('#setupPassword').value = ''; $('#setupConfirm').value = '';
      setLogin(); toast('Setup complete. Sign in with your administrator account.');
    } catch(error) { $('#setupError').textContent = error.message; }
    finally { next.disabled = false; }
  }));
  $('#networkForm').addEventListener('submit', safeAsync(async event => {
    event.preventDefault();
    const input = $('#networkPassword');
    const save = $('#networkForm button[type="submit"]'); save.disabled = true;
    try {
      await api('/network', {method:'PUT', body:{ current_password:input.value,
        lan_origins:aliases($('#networkLan').value), public_origin:$('#networkPublic').value.trim(),
        allow_http_vault:$('#networkVaultHttp').checked }});
      input.value = ''; toast('Network settings saved in Switchyard persistent storage.');
      await refreshNetwork();
    } finally { save.disabled = false; }
  }));
  $('#loginUsername').addEventListener('focus', () => refreshLoginOptions());
  $('#loginForm').addEventListener('submit', safeAsync(async event => { event.preventDefault(); $('#loginError').textContent = ''; try { await api('/login', { method: 'POST', body: { username: $('#loginUsername').value, password: $('#loginPassword').value, totp: $('#loginTotp').value.trim() } }); $('#loginPassword').value = ''; $('#loginTotp').value = ''; await setShell(); } catch (err) { $('#loginError').textContent = err.message; } }));
  $('[data-page]').forEach(b => b.addEventListener('click', () => navigate(b.dataset.page)));
  const navToggle = $('#navMobileToggle');
  const closeGlobalNavigation = () => {
    $('#shell').classList.remove('nav-open');
    navToggle.setAttribute('aria-expanded','false');
  };
  navToggle.addEventListener('click', () => {
    const open = $('#shell').classList.toggle('nav-open');
    navToggle.setAttribute('aria-expanded',String(open));
  });
  $('#navDismiss').addEventListener('click', closeGlobalNavigation);
  window.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeGlobalNavigation();
  });
  $('#globalFind').addEventListener('click', () => {
    navigate('machine');
    if (window.matchMedia('(max-width:620px)').matches) setMachineTreeOpen(true);
    $('#machineSwitchSearch').focus();
  });
  $('#machineCommandMenu').addEventListener('click', event => {
    if (event.target.closest('button')) $('#machineCommandMenu').open = false;
  });
  $$('[data-action="new-asset"]').forEach(b => b.addEventListener('click', () => openAsset()));
  $('#logoutBtn').addEventListener('click', safeAsync(async () => { await api('/logout', { method: 'POST' }); setLogin(); }));
  $('#assetAuth').addEventListener('change', syncAuthFields);
  $('#assetSearch').addEventListener('input', renderAssets);
  $('#sshProbeBatch').addEventListener('click',safeAsync(checkSSHBatch));
  $('#machineProbe').addEventListener('click',safeAsync(()=>checkSSHPort(machineAsset())));
  $('#sshExport').addEventListener('click', safeAsync(exportSSHInventory));
  $('#sshImport').addEventListener('click', () => $('#sshImportFile').click());
  $('#sshImportFile').addEventListener('change', safeAsync(importSSHInventory));
  $('#assetForm').addEventListener('submit', safeAsync(saveAsset));
  $('#closeAssetDialog').addEventListener('click', () => $('#assetDialog').close());
  $('#cancelAsset').addEventListener('click', () => $('#assetDialog').close());
  $('#fileBrowse').addEventListener('click', safeAsync(browseFiles));
  $('#fileUpload').addEventListener('change', safeAsync(uploadFile));
  $('#fileUploadButton').addEventListener('click', () => $('#fileUpload').click());
  $('#terminalTabs').addEventListener('keydown', event => {
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
    const ids = [...state.tabs.keys()].filter(id => normalizedHost(state.tabs.get(id).asset.host) === state.machineHost); if (ids.length < 2) return;
    const index = ids.indexOf(state.currentTab), delta = event.key === 'ArrowRight' ? 1 : -1;
    const next = ids[(index + delta + ids.length) % ids.length];
    event.preventDefault(); selectTab(next);
    const tabs = $$('.tab-select', $('#terminalTabs')); tabs[ids.indexOf(next)]?.focus();
  });
  $('#fileMkdir').addEventListener('click', safeAsync(createRemoteFolder));
  $('#closeFileEditor').addEventListener('click', () => $('#fileEditorDialog').close());
  $('#cancelFileEdit').addEventListener('click', () => $('#fileEditorDialog').close());
  $('#fileEditorForm').addEventListener('submit', safeAsync(saveFileEditor));
  $('#healthRefresh').addEventListener('click', safeAsync(checkHealth));
  $('#healthAsset').addEventListener('change', safeAsync(refreshHealthHistory));
  $('#newRunbook').addEventListener('click', resetRunbookForm);
  $('#cancelRunbook').addEventListener('click', resetRunbookForm);
  $('#runbookForm').addEventListener('submit', safeAsync(saveRunbook));
  $('#runbookRefresh').addEventListener('click', safeAsync(refreshRunbooks));
  $('#serviceRefresh').addEventListener('click',safeAsync(refreshServices));
  $('#serviceAsset').addEventListener('change',()=>{serviceRows=[];renderServices();$('#serviceLogArea').classList.add('hidden');});
  $('#serviceSearch').addEventListener('input',renderServices);
  $('#serviceLogClose').addEventListener('click',()=>$('#serviceLogArea').classList.add('hidden'));
  $('#dockerRefresh').addEventListener('click', safeAsync(refreshDocker));
  $('#dockerShowContainers').addEventListener('click', () => dockerView('containers'));
  $('#dockerShowImages').addEventListener('click', () => dockerView('images'));
  $('#dockerShowNetworks').addEventListener('click', () => dockerView('networks'));
  $('#dockerShowVolumes').addEventListener('click', () => dockerView('volumes'));
  $('#dockerShowStacks').addEventListener('click', () => dockerView('stacks'));
  $('#dockerDetailClose').addEventListener('click', () => $('#dockerDetails').classList.add('hidden'));
  $('#keysRefresh').addEventListener('click', safeAsync(refreshKeys));
  $('#keyGenerateForm').addEventListener('submit', safeAsync(async event => {
    event.preventDefault(); const name = $('#keyGenerateName').value;
    await api('/keys/generate', { method: 'POST', body: { name } });
    $('#keyGenerateForm').reset(); toast('Ed25519 key created. Install its public key on the remote account.'); await refreshKeys();
  }));
  $('#keyImportForm').addEventListener('submit', safeAsync(async event => {
    event.preventDefault(); const file = $('#keyImportFile').files?.[0]; if (!file) return;
    if (file.size > 16384) { toast('Private key exceeds 16 KiB.', true); return; }
    const data = new FormData(); data.set('file', file);
    await api('/keys/import?name=' + encodeURIComponent($('#keyImportName').value), { method: 'POST', body: data });
    $('#keyImportForm').reset(); toast('Private key imported.'); await refreshKeys();
  }));
  $('#backupDownload').addEventListener('click', safeAsync(async () => {
    await savePrivateDownload('/backup', 'switchyard-backup.zip'); toast('Backup downloaded. Store it in a protected location.');
  }));
  $('#vaultRefresh').addEventListener('click', safeAsync(vaultStatus));
  $('#vaultConfigForm').addEventListener('submit', safeAsync(async event => { event.preventDefault(); await api('/vault/configure', { method: 'POST', body: { server_url: $('#vaultUrl').value } }); toast('Vault server configured.'); vaultStatus(); }));
  $('#vaultLoginForm').addEventListener('submit', safeAsync(async event => { event.preventDefault(); await api('/vault/login', { method: 'POST', body: { client_id: $('#vaultClientId').value, client_secret: $('#vaultClientSecret').value } }); $('#vaultClientSecret').value = ''; toast('Bitwarden CLI authenticated. Unlock your vault next.'); vaultStatus(); }));
  $('#vaultUnlockForm').addEventListener('submit', safeAsync(async event => { event.preventDefault(); await api('/vault/unlock', { method: 'POST', body: { master_password: $('#vaultMaster').value } }); $('#vaultMaster').value = ''; toast('Vault unlocked in server memory.'); await vaultStatus(); await vaultItems(); }));
  $('#vaultLock').addEventListener('click', safeAsync(async () => { await api('/vault/lock', { method: 'POST' }); $('#vaultItems').replaceChildren(node('div', 'empty-state', 'Vault locked.')); toast('Vault locked.'); vaultStatus(); }));
  $('#vaultLogout').addEventListener('click', safeAsync(async () => { if (!await confirmAction('Sign out of Vaultwarden', 'Unlock and authenticate again before retrieving credentials.', 'Sign out')) return; await api('/vault/logout', { method: 'POST' }); $('#vaultItems').replaceChildren(node('div', 'empty-state', 'Vault logged out.')); toast('CLI logged out.'); await vaultStatus(); }));
  $('#vaultItemsRefresh').addEventListener('click', safeAsync(async () => { await api('/vault/sync', { method: 'POST' }); await vaultItems(); toast('Vault synced.'); }));
  $('#scanForm').addEventListener('submit', safeAsync(scanHost));
  $('#refreshHosts').addEventListener('click', safeAsync(refreshHosts));
  $('#auditRefresh').addEventListener('click', safeAsync(() => refreshAudit()));
  $('#auditApply').addEventListener('click', safeAsync(async () => { auditFilter = $('#auditFilter').value.trim(); await refreshAudit(); }));
  $('#auditReset').addEventListener('click', safeAsync(async () => { auditFilter = ''; $('#auditFilter').value = ''; await refreshAudit(); }));
  $('#auditMore').addEventListener('click', safeAsync(() => refreshAudit(true)));
  $('#auditExport').addEventListener('click', safeAsync(async () => {
    await savePrivateDownload('/audit/export', 'switchyard-audit.csv'); toast('Audit journal downloaded.');
  }));
  $('#mfaSetupForm').addEventListener('submit', safeAsync(async event => {
    event.preventDefault();
    const result = await api('/mfa/setup', { method: 'POST', body: {password: $('#mfaSetupPassword').value} });
    event.target.reset();
    $('#mfaSecret').textContent = result.secret;
    $('#mfaUri').setAttribute('href', result.otpauth_uri);
    const qr = $('#mfaQr');
    if (!result.qr_data_uri?.startsWith('data:image/svg+xml;base64,')) throw new Error('Authenticator QR image unavailable');
    qr.src = result.qr_data_uri;
    qr.classList.remove('hidden');
    $('#mfaEnrollment').classList.remove('hidden');
    toast('Authenticator enrollment started. Verify a code to enable MFA.');
  }));
  $('#mfaEnableForm').addEventListener('submit', safeAsync(async event => {
    event.preventDefault();
    await api('/mfa/enable', { method: 'POST', body: {code: $('#mfaEnableCode').value.trim()} });
    event.target.reset();
    $('#mfaSecret').textContent = '';
    $('#mfaUri').removeAttribute('href');
    $('#mfaQr').removeAttribute('src');
    $('#mfaQr').classList.add('hidden');
    $('#mfaEnrollment').classList.add('hidden');
    await refreshMfaStatus();
    toast('Authenticator verified. MFA is now enabled for external HTTPS sign-in.');
  }));
  $('#mfaDisableForm').addEventListener('submit', safeAsync(async event => {
    event.preventDefault();
    if (!await confirmAction('Disable MFA', 'External HTTPS logins will use username and password only.', 'Disable MFA')) return;
    await api('/mfa/disable', { method: 'POST', body: {password: $('#mfaDisablePassword').value, code: $('#mfaDisableCode').value.trim()} });
    event.target.reset();
    await refreshMfaStatus();
    toast('MFA disabled. External HTTPS sign-in now uses username and password.');
  }));
  $('#passwordForm').addEventListener('submit', safeAsync(async event => { event.preventDefault(); await api('/password', { method: 'POST', body: { current_password: $('#currentPassword').value, new_password: $('#newPassword').value } }); event.target.reset(); toast('Administrator password changed.'); }));
  window.addEventListener('resize', () => { if (state.page === 'terminals' && state.currentTab) state.tabs.get(state.currentTab)?.fit.fit(); });
  bootstrap();
}
window.addEventListener('DOMContentLoaded', bind);
