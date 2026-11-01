//! Restricted local clients and resumable revocation. No identity, message
//! payload or second signing journal is stored in this bounded registry.
use super::*;
use peerwork_core::crypto::sha256_hex;
const LIMIT:usize=128;
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry{parent:String,alias:String,name:String,capability:Capability,#[serde(default)] generation:u64}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Revocation{pub target:String,pub binding:String,removed:Vec<Entry>}
impl Revocation{pub fn names(&self)->std::collections::BTreeSet<String>{self.removed.iter().map(|e|e.name.clone()).collect()}}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved{version:u8,generation:u64,entries:Vec<Entry>,revocations:Vec<Revocation>}
impl Default for Saved{fn default()->Self{Self{version:2,generation:0,entries:Vec::new(),revocations:Vec::new()}}}
pub(super) struct Clients{store:SecureStateStore,data:Saved}
fn name(parent:&str,alias:&str)->String{format!("derived-{}",&sha256_hex(json!([parent,alias]).to_string().as_bytes())[..40])}
fn binding(entry:&Entry)->String{sha256_hex(serde_json::to_vec(entry).unwrap().as_slice())}
impl Clients{
    pub fn open(directory:&Path)->Result<Self>{
        let store=SecureStateStore::open(&directory.join("derived-clients.state")).map_err(|_|local("CLIENT_REGISTRY_NOT_PRIVATE"))?;
        let data=match store.read_exact().map_err(|_|local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?{
            None=>Saved::default(),
            Some(bytes)=>{
                let value=peerwork_core::strict_json::parse_strict_json(&bytes).map_err(|_|local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
                if value.is_array(){
                    // Local candidate checkpoint migration only. Signed packets,
                    // state namespaces and old capabilities are not rewritten.
                    let mut entries:Vec<Entry>=serde_json::from_value(value).map_err(|_|local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
                    for (i,entry) in entries.iter_mut().enumerate(){entry.generation=i as u64+1;}
                    Saved{generation:entries.len() as u64,entries,..Saved::default()}
                }else{serde_json::from_value(value).map_err(|_|local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?}
            }
        };
        if data.version!=2||data.entries.len()+data.revocations.iter().map(|r|r.removed.len()).sum::<usize>()>LIMIT
            ||data.entries.iter().chain(data.revocations.iter().flat_map(|r|&r.removed)).any(|e|e.generation==0||e.generation>data.generation||!identifier(&e.alias)||e.name!=name(&e.parent,&e.alias)){
            return Err(local("CLIENT_REGISTRY_RECOVERY_REQUIRED"));
        }
        Ok(Self{store,data})
    }
    fn save(&mut self,data:Saved)->Result<()>{
        self.store.write_exact(&serde_json::to_vec(&data).map_err(|_|local("CLIENT_REGISTRY_INVALID"))?).map_err(|_|local("CLIENT_REGISTRY_WRITE_FAILED"))?;self.data=data;Ok(())
    }
    pub fn restore(&self,sessions:&mut Vec<Session>)->Result<()>{
        for entry in &self.data.entries{
            if sessions.iter().any(|s|s.name==entry.name){return Err(local("CLIENT_REGISTRY_RECOVERY_REQUIRED"));}
            let parent=sessions.iter().find(|s|s.name==entry.parent).ok_or_else(||local("CLIENT_PARENT_RECOVERY_REQUIRED"))?;
            sessions.push(Session{name:entry.name.clone(),client:parent.client.restrict(&entry.alias,entry.capability.clone())?,token:random_token().map_err(|_|local("ENTROPY_UNAVAILABLE"))?,generation:Some(entry.generation),watches:Default::default()});
        }Ok(())
    }
    pub fn pending(&self)->Vec<Revocation>{self.data.revocations.clone()}
    pub fn blocked_names(&self)->std::collections::BTreeSet<String>{self.data.revocations.iter().flat_map(Revocation::names).collect()}
    pub fn detached(job:&Revocation,sessions:&[Session])->Result<Vec<ParticipantClient>>{
        let mut available:BTreeMap<String,ParticipantClient>=sessions.iter().map(|s|(s.name.clone(),s.client.clone())).collect();let mut revoked=Vec::new();
        for entry in &job.removed{
            let parent=available.get(&entry.parent).ok_or_else(||local("CLIENT_PARENT_RECOVERY_REQUIRED"))?;
            let client=parent.restrict(&entry.alias,entry.capability.clone())?;available.insert(entry.name.clone(),client.clone());revoked.push(client);
        }Ok(revoked)
    }
    pub fn complete(&mut self,job:&Revocation)->Result<()>{
        let mut data=self.data.clone();data.revocations.retain(|r|r.target!=job.target||r.binding!=job.binding);self.save(data)
    }
    pub fn version(&self,name:&str)->Option<String>{self.data.entries.iter().find(|e|e.name==name).map(binding)}
}
impl Runtime{
    pub(super) fn revoke_derived(&self,parent:&Session,alias:&str,expected:&str)->Result<Option<Revocation>>{
        if !identifier(alias)||!crate::participant_migration::digest(expected){return Err(local("CLIENT_BINDING_SELECTION_INVALID"));}
        let target=name(&parent.name,alias);let mut registry=self.derived.lock().map_err(|_|local("CLIENT_REGISTRY_UNAVAILABLE"))?;
        if !self.sessions.read().map_err(|_|local("CLIENT_REGISTRY_UNAVAILABLE"))?.iter().any(|s|s.name==parent.name&&s.token==parent.token){return Err(local("IPC_UNAUTHORIZED"));}
        if let Some(job)=registry.data.revocations.iter().find(|r|r.target==target){if job.binding!=expected{return Err(local("CLIENT_BINDING_CHANGED"));}return Ok(Some(job.clone()));}
        let Some(entry)=registry.data.entries.iter().find(|e|e.name==target) else{return Ok(None);};
        if binding(entry)!=expected{return Err(local("CLIENT_BINDING_CHANGED"));}
        let mut names=std::collections::BTreeSet::from([target.clone()]);
        for entry in &registry.data.entries{if names.contains(&entry.parent){names.insert(entry.name.clone());}}
        let removed=registry.data.entries.iter().filter(|e|names.contains(&e.name)).cloned().collect();
        let job=Revocation{target,binding:expected.into(),removed};let mut data=registry.data.clone();data.entries.retain(|e|!names.contains(&e.name));data.revocations.push(job.clone());registry.save(data)?;
        let mut removed=Vec::new();{
            let mut sessions=self.sessions.write().map_err(|_|local("CLIENT_REGISTRY_UNAVAILABLE"))?;
            sessions.retain(|s|{if names.contains(&s.name){s.client.revoke_local();removed.push(s.clone());false}else{true}});
        }
        for session in removed{
            let path=self.directory.join(format!("client-{}.json",session.name));
            if load_endpoint(&path).is_ok_and(|e|e.token==session.token&&e.address==self.address){let _=std::fs::remove_file(path);}
        }
        Ok(Some(job))
    }
    pub(super) fn derive_client(&self,parent:&Session,alias:&str,capability:Capability,expected_capability:Option<Capability>)->Result<Value>{
        if !identifier(alias){return Err(local("CLIENT_ALIAS_INVALID"));}
        let mut client=parent.client.restrict(alias,capability.clone())?;let name=name(&parent.name,alias);let path=self.directory.join(format!("client-{name}.json"));
        let mut registry=self.derived.lock().map_err(|_|local("CLIENT_REGISTRY_UNAVAILABLE"))?;
        if !self.sessions.read().map_err(|_|local("CLIENT_REGISTRY_UNAVAILABLE"))?.iter().any(|s|s.name==parent.name&&s.token==parent.token){return Err(local("IPC_UNAUTHORIZED"));}
        if registry.data.revocations.iter().any(|r|r.removed.iter().any(|e|e.name==name)){return Err(local("CLIENT_REVOCATION_PENDING"));}
        if let Some(index)=registry.data.entries.iter().position(|e|e.name==name){
            let entry=registry.data.entries[index].clone();
            if entry.capability!=capability{
                if !entry.capability.is_subset_of(&capability){return Err(local("CLIENT_NARROWING_REQUIRES_REVOCATION"));}
                if expected_capability.as_ref()!=Some(&entry.capability){return Err(local("CLIENT_BINDING_CONFLICT"));}
                let mut data=registry.data.clone();data.entries[index].capability=capability.clone();registry.save(data)?;
                let mut sessions=self.sessions.write().map_err(|_|local("CLIENT_REGISTRY_UNAVAILABLE"))?;
                let session=sessions.iter_mut().find(|s|s.name==name).ok_or_else(||local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
                client.inherit_lifecycle(&session.client);session.client=client;
            }
            let session=self.sessions.read().map_err(|_|local("CLIENT_REGISTRY_UNAVAILABLE"))?.iter().find(|s|s.name==name).cloned().ok_or_else(||local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
            match std::fs::symlink_metadata(&path){
                Ok(_)=>{let existing=load_endpoint(&path)?;if existing.token!=session.token||existing.address!=self.address||existing.access!="CLIENT"{return Err(local("CLIENT_ENDPOINT_CONFLICT"));}},
                Err(e) if e.kind()==std::io::ErrorKind::NotFound=>endpoint(&path,self.address,&session.token,"CLIENT")?,
                Err(_)=>return Err(local("CLIENT_ENDPOINT_CONFLICT")),
            }
        }else{
            if registry.data.entries.len()+registry.data.revocations.iter().map(|r|r.removed.len()).sum::<usize>()>=LIMIT{return Err(local("CLIENT_DERIVATION_LIMIT"));}
            if std::fs::symlink_metadata(&path).is_ok(){return Err(local("CLIENT_ENDPOINT_CONFLICT"));}
            let mut data=registry.data.clone();data.generation=data.generation.checked_add(1).ok_or_else(||local("CLIENT_GENERATION_LIMIT"))?;
            let session=Session{name:name.clone(),client,token:random_token().map_err(|_|local("ENTROPY_UNAVAILABLE"))?,generation:Some(data.generation),watches:Default::default()};
            data.entries.push(Entry{parent:parent.name.clone(),alias:alias.into(),name:name.clone(),capability:capability.clone(),generation:data.generation});registry.save(data)?;
            let token=session.token.clone();self.sessions.write().map_err(|_|local("CLIENT_REGISTRY_UNAVAILABLE"))?.push(session);endpoint(&path,self.address,&token,"CLIENT")?;
        }
        let entry=registry.data.entries.iter().find(|e|e.name==name).ok_or_else(||local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
        Ok(json!({"state":"LOCAL_CLIENT_READY","client_name":name,"endpoint_path":path,"actor_id":parent.client.actor_id(),"origin":parent.client.origin(),"capability":capability,"engine_restarted":false,"client_generation":entry.generation,"binding_version":binding(entry)}))
    }
}
