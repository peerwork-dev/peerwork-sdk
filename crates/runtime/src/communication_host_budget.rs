//! One logical operation budget. The status snapshot never locks provider I/O.
use serde_json::{json, Value};
use std::{io::{Read,Write},sync::{Arc,Mutex},time::{Duration,Instant,SystemTime,UNIX_EPOCH}};
#[derive(Clone)]
pub(crate) struct Budget(Arc<Mutex<State>>);
struct State { limit:Duration,deadline:Instant,started:Instant,depth:usize,phase:&'static str,last_error:Option<&'static str>,original_error:Option<&'static str>,failure_phase:Option<&'static str>,rpc_code:Option<i64>,last_success:Option<u64>,last_failure:Option<(&'static str,&'static str,u64)> }
fn now()->u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(u64::MAX as u128) as u64 }
pub(crate) struct Scope(Budget);
impl Budget {
 pub fn new(limit:Duration)->Self { let at=Instant::now();Self(Arc::new(Mutex::new(State{limit,deadline:at+limit,started:at,depth:0,phase:"IDLE",last_error:None,original_error:None,failure_phase:None,rpc_code:None,last_success:None,last_failure:None}))) }
 pub fn scope(&self,phase:&'static str)->Scope { let mut s=self.0.lock().unwrap_or_else(|p|p.into_inner());if s.depth==0 {s.started=Instant::now();s.deadline=s.started+s.limit;s.last_error=None;s.original_error=None;s.failure_phase=None;s.rpc_code=None;}s.depth+=1;s.phase=phase;Scope(self.clone()) }
 pub fn clamp(&self,deadline:Instant){let mut s=self.0.lock().unwrap_or_else(|p|p.into_inner());s.deadline=s.deadline.min(deadline);}
 pub fn phase(&self,phase:&'static str){self.0.lock().unwrap_or_else(|p|p.into_inner()).phase=phase;}
 pub fn remaining(&self)->std::io::Result<Duration>{ self.0.lock().unwrap_or_else(|p|p.into_inner()).deadline.checked_duration_since(Instant::now()).filter(|d|!d.is_zero()).ok_or_else(||std::io::Error::new(std::io::ErrorKind::TimedOut,"HOST_OPERATION_TIMEOUT")) }
 pub fn deadline(&self)->Instant{self.0.lock().unwrap_or_else(|p|p.into_inner()).deadline}
 pub fn failure(&self,code:&'static str,rpc_code:Option<i64>){let mut s=self.0.lock().unwrap_or_else(|p|p.into_inner());if s.original_error.is_none(){s.original_error=Some(code);s.failure_phase=Some(s.phase);}s.last_failure=Some((s.original_error.unwrap_or(code),s.failure_phase.unwrap_or(s.phase),now()));s.last_error=Some(code);if rpc_code.is_some(){s.rpc_code=rpc_code;}}
 pub fn snapshot(&self)->Value {let s=self.0.lock().unwrap_or_else(|p|p.into_inner());json!({"phase":s.phase,"inflight":s.depth>0,"elapsed_ms":s.started.elapsed().as_millis() as u64,"budget_ms":s.limit.as_millis() as u64,"remaining_ms":s.deadline.saturating_duration_since(Instant::now()).as_millis() as u64,"last_error_code":s.last_error,"original_error_code":s.original_error,"failure_phase":s.failure_phase,"rpc_error_code":s.rpc_code,"last_success_at":s.last_success,"last_failure_code":s.last_failure.map(|v|v.0),"last_failure_phase":s.last_failure.map(|v|v.1),"last_failure_at":s.last_failure.map(|v|v.2),"observed_at":now()})}
}
impl Drop for Scope { fn drop(&mut self){let mut s=self.0.0.lock().unwrap_or_else(|p|p.into_inner());s.depth=s.depth.saturating_sub(1);if s.depth==0&&s.last_error.is_none(){s.last_success=Some(now());}} }
pub(super) trait Timed {fn timeouts(&self,remaining:Duration)->std::io::Result<()>;}
impl Timed for std::net::TcpStream {fn timeouts(&self,d:Duration)->std::io::Result<()>{self.set_read_timeout(Some(d))?;self.set_write_timeout(Some(d))}}
#[cfg(unix)] impl Timed for std::os::unix::net::UnixStream {fn timeouts(&self,d:Duration)->std::io::Result<()>{self.set_read_timeout(Some(d))?;self.set_write_timeout(Some(d))}}
pub(super) struct Deadline<S>{pub stream:S,pub budget:Budget}
impl<S:Timed+Read> Read for Deadline<S> {fn read(&mut self,b:&mut[u8])->std::io::Result<usize>{self.stream.timeouts(self.budget.remaining()?)?;self.stream.read(b)}}
impl<S:Timed+Write> Write for Deadline<S> {fn write(&mut self,b:&[u8])->std::io::Result<usize>{self.stream.timeouts(self.budget.remaining()?)?;self.stream.write(b)}fn flush(&mut self)->std::io::Result<()>{self.stream.timeouts(self.budget.remaining()?)?;self.stream.flush()}}

// OS DNS calls cannot always be cancelled. Bound both their waiter and total
// outstanding resolver work; a timed-out resolver owns no socket or input writer.
pub(super) fn resolve(executor:&tokio::runtime::Handle,budget:&Budget,name:&str,port:u16)->Result<Vec<std::net::SocketAddr>,&'static str>{
    use std::net::ToSocketAddrs;
    if let Ok(ip)=name.parse::<std::net::IpAddr>(){return Ok(vec![std::net::SocketAddr::new(ip,port)]);}
    if name=="localhost"{return Ok(vec![std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(),port),std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(),port)]);}
    static RESOLVERS:std::sync::OnceLock<Arc<tokio::sync::Semaphore>>=std::sync::OnceLock::new();
    let admission=RESOLVERS.get_or_init(||Arc::new(tokio::sync::Semaphore::new(8))).clone();
    let name=name.to_owned();
    executor.block_on(async{
        let permit=tokio::time::timeout(budget.remaining().map_err(|_|"HOST_OPERATION_TIMEOUT")?,admission.acquire_owned()).await.map_err(|_|"HOST_RESOLUTION_BUSY")?.map_err(|_|"HOST_RESOLUTION_BUSY")?;
        let lookup=tokio::task::spawn_blocking(move||{let _permit=permit;(name.as_str(),port).to_socket_addrs().map(|it|it.take(8).collect::<Vec<_>>())});
        tokio::time::timeout(budget.remaining().map_err(|_|"HOST_OPERATION_TIMEOUT")?,lookup).await.map_err(|_|"HOST_DNS_TIMEOUT")?.map_err(|_|"HOST_RESOLUTION_FAILED")?.map_err(|_|"HOST_RESOLUTION_FAILED")
    })
}

pub(crate) fn with_host<T>(host:&std::sync::Mutex<super::Host>,deadline:Instant,call:impl FnOnce(&mut super::Host)->Result<T,&'static str>)->Result<T,&'static str>{
    loop {
        if Instant::now()>=deadline{return Err("HOST_LOCK_TIMEOUT");}
        match host.try_lock(){
            Ok(mut selected)=>{
                let _operation=selected.progress.scope("HOST_CALL");selected.progress.clamp(deadline);
                return call(&mut selected);
            },
            Err(std::sync::TryLockError::Poisoned(_))=>return Err("HOST_STATE_INVALID"),
            Err(std::sync::TryLockError::WouldBlock)=>std::thread::sleep(deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(2))),
        }
    }
}


pub(super) fn terminate_helper(child:&mut std::process::Child,token:Option<&str>,budget:&Budget){
    budget.phase("TERMINATING");
    if !crate::communication_store::process_alive(child.id(),token){let _=child.try_wait();return;}
    let _=child.kill();let start=Instant::now();
    loop {match child.try_wait(){Ok(Some(_))=>return,_=>{}}
        if !crate::communication_store::process_alive(child.id(),token){return;}
        if start.elapsed()>=Duration::from_secs(2){budget.phase("STALLED_TERMINATION");}
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub(crate) fn retry_delay(attempt:u32,salt:&str)->Duration{
    let base=(1000u64<<attempt.min(5)).min(25000);
    let digest=peerwork_core::crypto::sha256_hex(format!("{salt}:{attempt}").as_bytes());
    let spread=u64::from_str_radix(&digest[..16],16).unwrap_or(0)%(base/4).clamp(1,5000);
    Duration::from_millis(base+spread)
}
