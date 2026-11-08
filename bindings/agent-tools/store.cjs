'use strict';
// SPDX-License-Identifier: Apache-2.0
const fs=require('node:fs'),path=require('node:path'),{DatabaseSync}=require('node:sqlite');
const fail=code=>{throw Object.assign(Error(code),{code});};
function privateFile(file,max=1048576){
 const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||(s.mode&0o077)||s.size>max)fail('TOOLS_FILE_NOT_PRIVATE');
 return new TextDecoder('utf-8',{fatal:true}).decode(fs.readFileSync(file));
}
function processToken(pid){try{return fs.readFileSync('/proc/'+pid+'/stat','utf8').split(') ').at(-1).split(' ')[19];}catch{try{process.kill(pid,0);return 'alive';}catch(e){return e.code==='EPERM'?'alive':null;}}}
class ToolStore{
 constructor(directory,pin){
  fs.mkdirSync(directory,{recursive:true,mode:0o700});const s=fs.lstatSync(directory);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077))fail('TOOLS_STATE_NOT_PRIVATE');
  const file=path.join(directory,'agent-tools.sqlite');if(fs.existsSync(file)){const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||(s.mode&0o077))fail('TOOLS_STATE_NOT_PRIVATE');}
  // Restrict the file before SQLite opens it, including on concurrent first use.
  try{fs.closeSync(fs.openSync(file,'wx',0o600));}catch(e){if(e.code!=='EEXIST')throw e;}
  this.db=new DatabaseSync(file);this.db.exec('PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, input TEXT, prepared TEXT, outcome TEXT, phase TEXT NOT NULL, pid INTEGER, process_token TEXT);');
  this.db.prepare('INSERT OR IGNORE INTO meta VALUES(?,?)').run('binding',pin);
  if(this.get('binding')!==pin){this.close();fail('TOOLS_PROFILE_MISMATCH');}
 }
 get(key){const r=this.db.prepare('SELECT value FROM meta WHERE key=?').get(key);return r?.value;}
 set(key,value){this.db.prepare('INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,value);}
 row(id){const r=this.db.prepare('SELECT * FROM operations WHERE id=?').get(id);if(!r)fail('TOOLS_OPERATION_NOT_FOUND');return {...r,input:r.input?JSON.parse(r.input):null,prepared:r.prepared?JSON.parse(r.prepared):null,outcome:r.outcome?JSON.parse(r.outcome):null};}
 reserve(id,hash,input){this.db.prepare("INSERT OR IGNORE INTO operations(id,request_hash,input,phase) VALUES(?,?,?,'PREPARING')").run(id,hash,JSON.stringify(input));const r=this.row(id);if(r.request_hash!==hash)fail('TOOLS_OPERATION_INPUT_CONFLICT');return r;}
 claim(id){
  this.db.exec('BEGIN IMMEDIATE');try{const r=this.row(id);if(r.pid&&processToken(r.pid)!==null&&(!r.process_token||processToken(r.pid)===r.process_token||processToken(r.pid)==='alive'))fail('TOOLS_OPERATION_BUSY');this.db.prepare('UPDATE operations SET pid=?,process_token=? WHERE id=?').run(process.pid,processToken(process.pid),id);this.db.exec('COMMIT');}catch(e){this.db.exec('ROLLBACK');throw e;}
 }
 release(id){this.db.prepare('UPDATE operations SET pid=NULL,process_token=NULL WHERE id=? AND pid=?').run(id,process.pid);}
 prepare(id,value){this.db.prepare("UPDATE operations SET prepared=?,phase='PREPARED' WHERE id=?").run(JSON.stringify(value),id);}
 submitting(id){this.db.prepare("UPDATE operations SET phase='SUBMITTING' WHERE id=?").run(id);}
 finish(id,outcome){const terminal=['ACCEPTED','COMPLETED','REJECTED'].includes(outcome.state);this.db.prepare('UPDATE operations SET outcome=?,phase=?,input=CASE WHEN ? THEN NULL ELSE input END,prepared=CASE WHEN ? THEN NULL ELSE prepared END WHERE id=?').run(JSON.stringify(outcome),outcome.state,terminal?1:0,terminal?1:0,id);}
 page(after='',limit=16){if(!Number.isSafeInteger(limit)||limit<1||limit>32)fail('TOOLS_PAGE_INVALID');const rows=this.db.prepare('SELECT id,phase FROM operations WHERE id>? ORDER BY id LIMIT ?').all(after,limit+1);return {items:rows.slice(0,limit),next_after:rows.length>limit?rows[limit-1].id:null};}
 close(){this.db.close();}
}
module.exports={ToolStore,privateFile,fail};
