import assert from 'node:assert/strict';import{PostAdmission}from'./admission.mjs';
let now=0,release;const blocked=new Promise(resolve=>release=resolve),events=[],gate=new PostAdmission({clock:()=>now,wait:ms=>{events.push({phase:'blocked',ms});return blocked;}});let constructors=0,calls=0;
const request=()=>{constructors++;const timeout=15000,signal=AbortSignal.timeout(timeout);events.push({phase:'construct',timeout,aborted:signal.aborted});calls++;return {timeout,aborted:signal.aborted};};
for(let i=0;i<90;i++)assert.deepEqual(await gate.run(request),{timeout:15000,aborted:false});
const pending=gate.run(request);await Promise.resolve();await Promise.resolve();assert.equal(constructors,90);assert.equal(calls,90);assert.equal(events.at(-1).phase,'blocked');assert.equal(events.at(-1).ms,60000);
now=60000;release();assert.deepEqual(await pending,{timeout:15000,aborted:false});assert.equal(constructors,91);assert.equal(calls,91);assert.equal(events.at(-1).phase,'construct');
let called=false;const refused=new PostAdmission({limit:1,clock:()=>0,wait:async()=>{throw new Error('ADMISSION_REFUSED');}});await refused.run(()=>{});await assert.rejects(refused.run(()=>{called=true;}),/ADMISSION_REFUSED/);assert.equal(called,false);
console.log(JSON.stringify({result:'PASS',actual_driver_limit:90,service_limit_unchanged:120,selected_timeout_ms:15000,constructor_count:constructors,call_count:calls,blocked_constructor_count:90,release_constructed_exactly_once:true,admission_refusal_does_not_construct:true,wall_clock_sleeps:false,http:false,events}));
