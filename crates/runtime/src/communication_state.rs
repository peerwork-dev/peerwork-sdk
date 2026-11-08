//! Communication evidence and current blockers are separate. These DTOs never
//! turn an RPC timeout, a queue receipt or a participant reply into a read proof.
use serde::{Deserialize,Serialize};

#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum Submission {Preparing,Ready,Unresolved,Accepted,RejectedNoEffect,CancelledBeforeSubmit}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum Custody {Unconfirmed,ReceiverStored}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum BodyReadiness {Unknown,Available,KeyRequired,Withdrawn,Invalid}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum HostEvidence {NoConfirmedInvocation,CallOpen,ResultUnknown,HostQueued,HostAccepted}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum Dispatch {Eligible,Blocked,Stopped}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum ReplyEvidence {NoneObserved,CorrelatedReplyObserved}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum RetryScope {None,SameFrozenPacketOnly,ReadOriginalOperationOnly,SameHostFrameOnlyAfterProvenNotSent,ReadOriginalHostResultOnly,NewIntentRequired}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct NextAction {
    pub actor:String,pub location:String,pub principal:String,
    pub action:String,pub retry_scope:RetryScope,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct Blocker {
    pub stage:String,pub code:String,pub certainty:String,pub observed_by:String,
    pub reporting:String,pub next_action:NextAction,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct DeliveryState {
    pub custody:Custody,pub body_readiness:BodyReadiness,pub host:HostEvidence,
    pub dispatch:Dispatch,pub response:ReplyEvidence,pub blocker:Option<Blocker>,
    pub host_receipt:Option<String>,pub late:bool,pub version:u64,
}
impl Default for DeliveryState{
    fn default()->Self{Self{custody:Custody::Unconfirmed,body_readiness:BodyReadiness::Unknown,host:HostEvidence::NoConfirmedInvocation,dispatch:Dispatch::Eligible,response:ReplyEvidence::NoneObserved,blocker:None,host_receipt:None,late:false,version:0}}
}
impl DeliveryState {
    pub fn stored(&mut self,body:BodyReadiness){self.custody=Custody::ReceiverStored;self.body_readiness=body;self.version+=1;}
    pub fn can_inject(&self)->bool{self.custody==Custody::ReceiverStored&&self.body_readiness==BodyReadiness::Available&&self.dispatch==Dispatch::Eligible&&self.host==HostEvidence::NoConfirmedInvocation}
    pub fn begin_host(&mut self)->Result<(),&'static str>{if !self.can_inject(){return Err("HOST_INJECTION_NOT_SAFE");}self.host=HostEvidence::CallOpen;self.version+=1;Ok(())}
    pub fn host_unknown(&mut self){if matches!(self.host,HostEvidence::CallOpen|HostEvidence::ResultUnknown){self.host=HostEvidence::ResultUnknown;self.version+=1;}}
    pub fn host_confirmed(&mut self,queued:bool,receipt:String)->Result<(),&'static str>{
        let wanted=if queued{HostEvidence::HostQueued}else{HostEvidence::HostAccepted};
        if self.host_receipt.as_ref().is_some_and(|old|old!=&receipt)||matches!(self.host,HostEvidence::HostQueued|HostEvidence::HostAccepted)&&self.host!=wanted{return Err("EVIDENCE_CONFLICT");}
        self.custody=Custody::ReceiverStored;self.host=wanted;self.host_receipt=Some(receipt);self.late=self.dispatch==Dispatch::Stopped;self.version+=1;Ok(())
    }
    /// A later local precondition failure cannot undo an earlier open/unknown
    /// invocation. Only an explicit reconciliation of that call can do so.
    pub fn block(&mut self,reason:Blocker){if self.dispatch!=Dispatch::Stopped{self.dispatch=Dispatch::Blocked;}self.blocker=Some(reason);self.version+=1;}
    pub fn confirm_original_not_sent(&mut self)->Result<(),&'static str>{if !matches!(self.host,HostEvidence::CallOpen|HostEvidence::ResultUnknown){return Err("NO_UNRESOLVED_HOST_CALL");}self.host=HostEvidence::NoConfirmedInvocation;self.version+=1;Ok(())}
    pub fn unblock(&mut self){if self.dispatch==Dispatch::Blocked{self.dispatch=Dispatch::Eligible;self.blocker=None;self.version+=1;}}
    pub fn stop(&mut self){self.dispatch=Dispatch::Stopped;self.version+=1;}
    pub fn replied(&mut self){self.response=ReplyEvidence::CorrelatedReplyObserved;self.version+=1;}
}

pub fn host_blocker(code:&str,principal:&str,possibly_sent:bool)->Blocker{
    let normalized=match code{"HOST_NOT_READY"=>"HOST_UNAVAILABLE","HOST_INBOX_FULL"=>"HOST_QUEUE_FULL","HOST_INPUT_TOO_LARGE"=>"HOST_FRAME_INVALID",other=>other};
    let (actor,action,scope)=if possibly_sent{("RUNTIME","RECONCILE_HOST",RetryScope::ReadOriginalHostResultOnly)}else{match normalized{
        "HOST_QUEUE_FULL"=>("RUNTIME","WAIT_FOR_HOST_CAPACITY",RetryScope::SameHostFrameOnlyAfterProvenNotSent),
        "HOST_FRAME_INVALID"=>("HOST_USER","REPAIR_HOST_ADAPTER",RetryScope::None),
        "HOST_ACCESS_DENIED"|"HOST_SOCKET_ACCESS_DENIED"=>("HOST_USER","CONFIGURE_SCOPED_HOST_BRIDGE",RetryScope::None),
        "CONTENT_KEY_MISSING"|"DELIVERY_CONTENT_KEYS_REQUIRED"=>("RUNTIME","SYNC_AUTHORIZED_KEY_DELIVERY",RetryScope::None),
        "HOST_WAITING_APPROVAL"=>("HOST_USER","HANDLE_ORIGINAL_HOST_APPROVAL",RetryScope::None),
        _=>("RUNTIME","WAIT_FOR_HOST_READINESS",RetryScope::SameHostFrameOnlyAfterProvenNotSent),
    }};
    Blocker{stage:"HOST_DISPATCH".into(),code:normalized.into(),certainty:if possibly_sent{"MAY_HAVE_BEEN_ACCEPTED"}else{"NOT_SENT"}.into(),observed_by:"RECIPIENT_RUNTIME".into(),reporting:"LOCAL_ONLY".into(),next_action:NextAction{actor:actor.into(),location:"RECIPIENT".into(),principal:principal.into(),action:action.into(),retry_scope:scope}}
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn unknown_is_not_erased_by_queue_full_or_a_reply(){let mut s=DeliveryState::default();s.stored(BodyReadiness::Available);s.begin_host().unwrap();s.host_unknown();s.block(host_blocker("HOST_INBOX_FULL","peer",false));s.replied();s.unblock();assert_eq!(s.host,HostEvidence::ResultUnknown);assert!(!s.can_inject());assert_eq!(s.response,ReplyEvidence::CorrelatedReplyObserved);}
    #[test]fn late_receipt_preserves_stopped_dispatch(){let mut s=DeliveryState::default();s.stored(BodyReadiness::Available);s.begin_host().unwrap();s.host_unknown();s.stop();s.host_confirmed(false,"original-host".into()).unwrap();assert_eq!(s.dispatch,Dispatch::Stopped);assert!(s.late);assert!(!s.can_inject());assert!(s.host_confirmed(false,"different".into()).is_err());}
    #[test]fn ciphertext_custody_is_not_body_or_host_acceptance(){let mut s=DeliveryState::default();s.stored(BodyReadiness::KeyRequired);assert!(!s.can_inject());assert_eq!(s.host,HostEvidence::NoConfirmedInvocation);s.replied();assert_eq!(s.host,HostEvidence::NoConfirmedInvocation);}
    #[test]fn queue_receipt_never_becomes_model_reply(){let mut s=DeliveryState::default();s.stored(BodyReadiness::Available);s.begin_host().unwrap();s.host_confirmed(true,"queue".into()).unwrap();assert_eq!(s.response,ReplyEvidence::NoneObserved);assert!(!s.can_inject());}
}
