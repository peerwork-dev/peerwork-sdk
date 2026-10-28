'use strict';
// SPDX-License-Identifier: Apache-2.0
const fs=require('node:fs'),path=require('node:path'),{DatabaseSync}=require('node:sqlite'),{createHash}=require('node:crypto');
const {DeliveryError}=require('./client.cjs');
const digest=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
class ReceiverStore {
 constructor(directory,binding){
  fs.mkdirSync(directory,{mode:0o700,recursive:true});const stat=fs.lstatSync(directory);
  if(!stat.isDirectory()||stat.isSymbolicLink()||(stat.mode&0o077))throw new DeliveryError('RECEIVER_STATE_NOT_PRIVATE');
  this.directory=fs.realpathSync(directory);const file=path.join(this.directory,'receiver.sqlite');
  if(fs.existsSync(file)){const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||(s.mode&0o077))throw new DeliveryError('RECEIVER_STATE_NOT_PRIVATE');}
  else fs.closeSync(fs.openSync(file,'wx',0o600));
  this.db=new DatabaseSync(file);this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=3000; CREATE TABLE IF NOT EXISTS control(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS deliveries(sequence INTEGER PRIMARY KEY,event TEXT NOT NULL,status TEXT NOT NULL,receipt TEXT,body_hash TEXT);');
  const pin=digest(binding),old=this.get('binding');if(old!==null&&old!==pin){this.db.close();throw new DeliveryError('DELIVERY_BINDING_MISMATCH');}if(old===null)this.set('binding',pin);
 }
 get(key){const row=this.db.prepare('SELECT value FROM control WHERE key=?').get(key);return row?JSON.parse(row.value):null;}
 set(key,value){this.db.prepare('INSERT INTO control VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,JSON.stringify(value));}
 lock(){
  const file=path.join(this.directory,'receiver.lock'),start=pid=>{try{return fs.readFileSync('/proc/'+pid+'/stat','utf8').split(') ').at(-1).split(' ')[19];}catch{return null;}};
  if(fs.existsSync(file)){
   const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||(s.mode&0o077))throw new DeliveryError('RECEIVER_LOCKED');
   const owner=JSON.parse(fs.readFileSync(file,'utf8'));let alive=true;try{process.kill(owner.pid,0);}catch(e){alive=e.code!=='ESRCH';}
   if(alive&&(!owner.start||!start(owner.pid)||start(owner.pid)===owner.start))throw new DeliveryError('RECEIVER_LOCKED');
   if(fs.lstatSync(file).ino!==s.ino)throw new DeliveryError('RECEIVER_LOCKED');fs.unlinkSync(file);
  }
  const fd=fs.openSync(file,'wx',0o600);fs.writeFileSync(fd,JSON.stringify({pid:process.pid,start:start(process.pid)}));fs.fsyncSync(fd);fs.closeSync(fd);const inode=fs.lstatSync(file).ino;
  this.unlock=()=>{if(fs.existsSync(file)&&fs.lstatSync(file).ino===inode)fs.unlinkSync(file);};
 }
 persist(events){this.db.exec('BEGIN IMMEDIATE');try{const put=this.db.prepare("INSERT INTO deliveries(sequence,event,status) VALUES(?,?,'RECEIVED') ON CONFLICT(sequence) DO NOTHING");for(const e of events)put.run(e.sequence,JSON.stringify(e));this.db.exec('COMMIT');}catch(error){this.db.exec('ROLLBACK');throw error;}}
 delivery(sequence){return this.db.prepare('SELECT * FROM deliveries WHERE sequence=?').get(sequence);}
 mark(sequence,status,receipt=null,bodyHash=null){this.db.prepare('UPDATE deliveries SET status=?,receipt=COALESCE(?,receipt),body_hash=COALESCE(?,body_hash) WHERE sequence=?').run(status,receipt,bodyHash,sequence);}
 pending(){return this.db.prepare("SELECT sequence,status FROM deliveries WHERE status<>'ACKED' ORDER BY sequence LIMIT 32").all();}
 prune(){this.db.exec("DELETE FROM deliveries WHERE status='ACKED' AND sequence < COALESCE((SELECT sequence FROM deliveries WHERE status='ACKED' ORDER BY sequence DESC LIMIT 1 OFFSET 63),-1)");}
 close(){this.unlock?.();this.db.close();}
}
module.exports={ReceiverStore,digest};
