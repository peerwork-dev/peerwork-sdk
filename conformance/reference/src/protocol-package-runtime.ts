/** Synchronous package primitives shared by Node and browsers; no host crypto or Buffer. */
import {sha256} from '@noble/hashes/sha2.js';
import {manifestCanonical} from './workspace-manifest.js';

const encoder=new TextEncoder();
const base64urlAlphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const base64urlValues=new Uint8Array(128);
for(let index=0;index<base64urlAlphabet.length;index++)base64urlValues[base64urlAlphabet.charCodeAt(index)]=index;
export function utf8Bytes(value:string):Uint8Array{return encoder.encode(value);}
export function utf8ByteLength(value:string){return utf8Bytes(value).byteLength;}
export function equalBytes(left:Uint8Array,right:Uint8Array){if(left.byteLength!==right.byteLength)return false;for(let i=0;i<left.byteLength;i++)if(left[i]!==right[i])return false;return true;}
export function hash(value:string|Uint8Array){const bytes=sha256(typeof value==='string'?utf8Bytes(value):value);let hex='';for(const byte of bytes)hex+=byte.toString(16).padStart(2,'0');return hex;}
export function manifestDigest(value:unknown){const result=manifestCanonical(value);return {...result,digest:hash(result.canonical)};}
export function encodeBase64url(bytes:Uint8Array){
 let encoded='';
 for(let i=0;i<bytes.byteLength;i+=3){
  const first=bytes[i]!,hasSecond=i+1<bytes.byteLength,hasThird=i+2<bytes.byteLength,second=hasSecond?bytes[i+1]!:0,third=hasThird?bytes[i+2]!:0;
  encoded+=base64urlAlphabet[first>>>2]!+base64urlAlphabet[((first&3)<<4)|(second>>>4)]!;
  if(hasSecond)encoded+=base64urlAlphabet[((second&15)<<2)|(third>>>6)]!;
  if(hasThird)encoded+=base64urlAlphabet[third&63]!;
 }
 return encoded;
}
export function decodeBase64url(value:string):Uint8Array{
 if(value.length%4===1||!/^[A-Za-z0-9_-]*$/.test(value))throw new Error('NONCANONICAL_BASE64URL');
 const bytes=new Uint8Array(Math.floor(value.length*3/4));let offset=0;
 for(let i=0;i<value.length;i+=4){
  const first=base64urlValues[value.charCodeAt(i)]!,second=base64urlValues[value.charCodeAt(i+1)]!,third=i+2<value.length?base64urlValues[value.charCodeAt(i+2)]!:0,fourth=i+3<value.length?base64urlValues[value.charCodeAt(i+3)]!:0;
  bytes[offset++]=(first<<2)|(second>>>4);
  if(i+2<value.length)bytes[offset++]=((second&15)<<4)|(third>>>2);
  if(i+3<value.length)bytes[offset++]=((third&3)<<6)|fourth;
 }
 if(encodeBase64url(bytes)!==value)throw new Error('NONCANONICAL_BASE64URL');
 return bytes;
}
export function hashBase64url(value:string|Uint8Array){return encodeBase64url(sha256(typeof value==='string'?utf8Bytes(value):value));}
