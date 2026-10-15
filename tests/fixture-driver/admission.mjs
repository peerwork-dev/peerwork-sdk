/** Test-driver pacing belongs before public API invocation, never inside fetch. */
export class PostAdmission {
 constructor({limit=90,windowMs=60000,clock=Date.now,wait=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}) {
  if(!Number.isSafeInteger(limit)||limit<=0||limit>90||!Number.isSafeInteger(windowMs)||windowMs<=0)throw new Error('INVALID_DRIVER_ADMISSION');
  Object.assign(this,{limit,windowMs,clock,wait});this.window=-1;this.count=0;this.queue=Promise.resolve();this.waits=[];
 }
 async run(makePublicRequest) {
  const permit=this.queue.then(async()=>{for(;;){const now=this.clock(),window=Math.floor(now/this.windowMs);if(window!==this.window){this.window=window;this.count=0;}if(this.count<this.limit){this.count++;return;}const ms=(window+1)*this.windowMs-now;this.waits.push({milliseconds:ms});await this.wait(ms);}});
  this.queue=permit.catch(()=>{});await permit;
  return makePublicRequest(); // Public API constructs its proof and original timeout only now.
 }
}
