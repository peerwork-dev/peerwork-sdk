import {ApiError} from './errors.js';
// Validate syntax with the platform parser, then reject duplicate member names,
// including escaped equivalents, before any authorization or mutation consumes it.
export function parseJson(text:string):unknown {
 let value:unknown;
 try{value=JSON.parse(text);}catch{throw new ApiError('INVALID_JSON',400);}
 const stack:{object:boolean;key:boolean;names:Set<string>}[]=[];
 for(const token of text.match(/"(?:[^"\\]|\\.)*"|[{}\[\],:]|[^\s{}\[\],:]+/gs)??[]){
  if(token==='{'||token==='['){stack.push({object:token==='{',key:token==='{',names:new Set()});continue;}
  if(token==='}'||token===']'){stack.pop();continue;}
  const frame=stack.at(-1);if(!frame?.object)continue;
  if(token===','){frame.key=true;continue;}
  if(token===':'){frame.key=false;continue;}
  if(frame.key&&token.startsWith('"')){
   const name=JSON.parse(token) as string;
   if(frame.names.has(name))throw new ApiError('DUPLICATE_JSON_KEY',400);
   frame.names.add(name);frame.key=false;
  }
 }
 return value;
}
