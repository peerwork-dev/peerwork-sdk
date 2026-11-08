'use strict';
// SPDX-License-Identifier: Apache-2.0
class DeliveryError extends Error {
  constructor(code,outcome) { super(code);this.name='DeliveryError';this.code=code;this.outcome=outcome; }
}
const accepted=out=>out?.state==='ACCEPTED'||out?.state==='COMPLETED';
function result(out) {if(!accepted(out))throw new DeliveryError(out?.code??out?.result?.structure?.error?.code??'DELIVERY_PENDING',out);return out.result.structure;}
function createDeliveryClient(kernel,binding,{session,snapshot,fetch:fetcher=globalThis.fetch}){
 const pinned=session(kernel,binding);binding=pinned.binding;const scope=()=>({workspace_id:pinned.binding.workspace_id,instance_id:pinned.binding.instance_id,protocol_digest:pinned.binding.protocol_digest});
 const call=(action,body,options={})=>{
  if(kernel.actor_id!==binding.expected_actor||kernel.origin.replace(/\/$/,'')!==binding.expected_origin.replace(/\/$/,''))throw new DeliveryError('DELIVERY_BINDING_MISMATCH');
  return kernel.executeStructureIntent({action:'structure.delivery.'+action,...scope(),body:snapshot(body),...(options.operation_id?{idempotency_key:options.operation_id}:{})},options);
 };
 return Object.freeze({
  binding:Object.freeze(pinned.binding),
  claim:(selection,options={})=>call('route.claim',{...selection,package_digest:pinned.binding.package_digest,role:pinned.binding.role},options),
  close:(fence,options={})=>call('route.close',fence,options),
  get:(route_id,options={})=>call('route.get',{route_id},options),
  routes:(selection={},options={})=>call('routes.read',selection,options),
  receipt:(route_id,sequence,options={})=>call('receipt.get',{route_id,sequence},options),
  pulse:(selection,options={})=>call('pulse',selection,options),
  ack:(selection,options={})=>call('ack',selection,options),
  inbox:(selection,options={})=>call('inbox.read',selection,options),
  async *wakes(fence,{signal}={}) {
   const stream=result(await call('stream.get',fence,{signal})).stream;
   if(stream.path!=='/api/workspace/v1/structure/delivery/stream'||typeof stream.token!=='string')throw new DeliveryError('DELIVERY_STREAM_INVALID');
   const url=new URL(stream.path,pinned.binding.expected_origin);
   if(url.origin!==new URL(pinned.binding.expected_origin).origin)throw new DeliveryError('DELIVERY_BINDING_MISMATCH');
   const response=await fetcher(url,{headers:{Authorization:'Bearer '+stream.token,Accept:'text/event-stream'},redirect:'error',signal});
   if(!response.ok||!response.headers.get('content-type')?.startsWith('text/event-stream')||!response.body)throw new DeliveryError('DELIVERY_STREAM_UNAVAILABLE');
   const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='';
   try{
    while(true){const chunk=await reader.read();if(chunk.done)break;buffer+=decoder.decode(chunk.value,{stream:true});if(buffer.length>4096)throw new DeliveryError('DELIVERY_STREAM_INVALID');
     let end;while((end=buffer.indexOf('\n\n'))>=0){const frame=buffer.slice(0,end);buffer=buffer.slice(end+2);const event=/^event: (ready|wake)$/m.exec(frame)?.[1];if(event)yield {event};}
    }
   }finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
  },
 });
}
module.exports={createDeliveryClient,DeliveryError,result};
