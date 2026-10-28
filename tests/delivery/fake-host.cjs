// Test-only protocol peer, not a real Agent or model.
const {createInterface}=require('node:readline');let active=null;
const emit=v=>process.stdout.write(JSON.stringify(v)+'\n');
createInterface({input:process.stdin}).on('line',line=>{
 const v=JSON.parse(line);
 if(v.event==='user'){emit({event:'init',conversation_id:'agy-1'});emit({event:'step_update',step_update:{conversation_id:'agy-1',step_type:'user_input',state:'DONE'}});setTimeout(()=>emit({event:'result',result:{conversation_id:'agy-1',status:'SUCCESS'}}),30);return;}
 const reply=result=>emit({jsonrpc:'2.0',id:v.id,result});
 switch(v.method){
  case 'initialize':reply({});break;
  case 'thread/resume':if(v.params.excludeTurns!==true){emit({jsonrpc:'2.0',id:v.id,error:{code:-32000}});break;}reply({thread:{id:v.params.threadId,status:{type:'idle'}}});break;
  case 'thread/read':reply({thread:{id:v.params.threadId,status:{type:active?'active':'idle'}}});break;
  case 'turn/start':active='turn-1';reply({turn:{id:active}});emit({method:'turn/started',params:{threadId:v.params.threadId,turn:{id:active}}});break;
  case 'turn/steer':if(v.params.expectedTurnId!==active)emit({jsonrpc:'2.0',id:v.id,error:{code:-32000}});else reply({turnId:active});break;
 }
});
