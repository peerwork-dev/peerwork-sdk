//! Browser observers and older services retain the signed HTTP/SSE path.
use crate::{kernel_identity::KernelIdentity, transport::HttpTransport, KernelCancellationToken};
use ed25519_dalek::Signer;
use futures_util::{SinkExt, StreamExt};
use peerwork_core::{communication::{MailboxPins,MAX_FRAME_BYTES},crypto::{base64url,sha256}};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;
use tungstenite::{protocol::{Role,WebSocketConfig}, Message};

pub(crate) const FEATURE:&str="compact-native-receiving-v1";
const DELIVERY:u8=1;
const CHALLENGE:u8=2;
const RENEW:u8=3;
const RECEIPT:u8=4;
const ACCEPTED:u8=5;
const AUTHENTICATE:u8=6;

struct Request {
    wire:Vec<u8>,
    reply:oneshot::Sender<Option<Value>>,
}

#[derive(Clone)]
pub(crate) struct CompactChannel {
    scopes:Arc<Vec<MailboxPins>>,
    requests:mpsc::Sender<Request>,
}

impl CompactChannel {
    pub(crate) fn slot(&self,pin:&MailboxPins)->Option<u8>{
        self.scopes.iter().position(|scope|scope.workspace_id==pin.workspace_id&&scope.mailbox_id==pin.mailbox_id
            &&scope.receiver_id==pin.receiver_id&&scope.epoch==pin.epoch)
            .and_then(|slot|u8::try_from(slot).ok())
    }

    pub(crate) async fn renew(&self,slot:u8,issued:u64,body:&Value,cancel:&KernelCancellationToken)->Option<Value>{
        let p=&body["presence"];
        let stable=if p.is_null(){Value::Null}else{json!([p["mode"],p["host_ready"],p["host_execution"],
            p["key_state"],p["key_code"],p["key_id"],p["key_epoch"],p["ordered_ready"],p["destination_digest"]])};
        let tag=sha256(json!([body["ready"],body["execution_state"],stable]).to_string().as_bytes());
        let age=|field:&str|p[field].as_u64().unwrap_or(60000).min(60000) as u16;
        let mut wire=Vec::with_capacity(30);
        wire.extend_from_slice(&[RENEW,slot]);
        wire.extend_from_slice(&issued.to_be_bytes());
        wire.extend_from_slice(&age("host_age_ms").to_be_bytes());
        wire.extend_from_slice(&age("key_age_ms").to_be_bytes());
        wire.extend_from_slice(&tag[..16]);
        let (reply,rx)=oneshot::channel();
        self.requests.try_send(Request{wire,reply}).ok()?;
        tokio::select! {
            _=cancel.cancelled()=>None,
            result=tokio::time::timeout(Duration::from_millis(1250),rx)=>result.ok()?.ok()?,
        }
    }
}

fn decode_lease(wire:&[u8])->Option<Value>{
    if !matches!(wire.len(),22|62)||wire[10]!=1{return None;}
    let now=u64::from_be_bytes(wire[11..19].try_into().ok()?);
    let ttl=u16::from_be_bytes(wire[19..21].try_into().ok()?);
    if ttl==0||ttl>15000||now>9_007_199_254_725_991{return None;}
    let mut value=json!({"mailbox":{"lease_until":now+u64::from(ttl),"server_time":now}});
    value["mailbox"]["key_head"]=match(wire[21],wire.len()){
        (0,22)=>Value::Null,
        (1,22)=>json!({"key_id":null,"epoch":null,"usable":false}),
        (mode @ (2|3),62)=>json!({"key_id":base64url(&wire[30..]),"epoch":u64::from_be_bytes(wire[22..30].try_into().ok()?),"usable":mode==3}),
        _=>return None,
    };
    Some(value)
}

pub(crate) async fn connect(transport:&HttpTransport,token:&str,stream_id:&str,identity:&KernelIdentity,pins:Vec<MailboxPins>,
    cancel:KernelCancellationToken,deadline:tokio::time::Instant)->Option<(CompactChannel,mpsc::Receiver<Vec<u8>>)>{
    let establish=async{
        let socket=transport.mailbox_socket(token).await.ok()?;
        let config=WebSocketConfig::default().max_message_size(Some(MAX_FRAME_BYTES+64))
            .max_frame_size(Some(MAX_FRAME_BYTES+64));
        let mut socket=WebSocketStream::from_raw_socket(socket,Role::Client,Some(config)).await;
        let Message::Binary(challenge)=socket.next().await?.ok()? else{return None;};
        if challenge.len()!=33||challenge[0]!=CHALLENGE{return None;}
        let mut proof=b"peerwork.compact-receiving.v1\0".to_vec();
        proof.extend_from_slice(stream_id.as_bytes());
        proof.extend_from_slice(&challenge[1..]);
        let mut reply=vec![AUTHENTICATE];
        reply.extend_from_slice(&identity.signing_key().sign(&proof).to_bytes());
        socket.send(Message::Binary(reply.into())).await.ok()?;
        if socket.next().await?.ok()?!=Message::Binary(vec![ACCEPTED].into()){return None;}
        Some(socket)
    };
    let mut socket=tokio::select! {
        _=cancel.cancelled()=>return None,
        _=tokio::time::sleep_until(deadline)=>return None,
        result=tokio::time::timeout(Duration::from_secs(2),establish)=>result.ok()??,
    };
    let (requests,mut rx)=mpsc::channel::<Request>(8);
    let (delivery,frames)=mpsc::channel(8);
    tokio::task::spawn_local(async move{
        let mut pending=HashMap::<u8,([u8;8],oneshot::Sender<Option<Value>>)>::new();
        loop{
            tokio::select!{
                _=cancel.cancelled()=>break,
                _=tokio::time::sleep_until(deadline)=>break,
                request=rx.recv()=>{
                    let Some(request)=request else{break;};
                    if request.reply.is_closed(){continue;}
                    let slot=request.wire[1];
                    if pending.get(&slot).is_some_and(|(_,prior)|!prior.is_closed()){continue;}
                    let issued=request.wire[2..10].try_into().unwrap();
                    pending.insert(slot,(issued,request.reply));
                    let sent=tokio::select!{
                        _=cancel.cancelled()=>break,
                        _=tokio::time::sleep_until(deadline)=>break,
                        result=socket.send(Message::Binary(request.wire.into()))=>result,
                    };
                    if sent.is_err(){break;}
                },
                message=socket.next()=>match message{
                    Some(Ok(Message::Binary(data))) if data.first()==Some(&DELIVERY)=>{
                        if delivery.try_send(data[1..].to_vec()).is_err(){break;}
                    },
                    Some(Ok(Message::Binary(data))) if data.first()==Some(&RECEIPT)&&data.len()>=10=>{
                        let slot=data[1];
                        if pending.get(&slot).is_some_and(|(issued,_)|issued[..]==data[2..10]){
                            let (_,reply)=pending.remove(&slot).unwrap();
                            let _=reply.send(decode_lease(&data));
                        }
                    },
                    Some(Ok(Message::Pong(_)|Message::Ping(_)))=>{},
                    _=>break,
                },
            }
        }
    });
    Some((CompactChannel{scopes:Arc::new(pins),requests},frames))
}
