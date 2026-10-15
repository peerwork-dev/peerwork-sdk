// Task-only author overlay; unchanged public staging/install interruption logic.
import{readFileSync}from'node:fs';import{createHash}from'node:crypto';import{pathToFileURL}from'node:url';
const sdk=process.env.PEERWORK_TEST_SDK_ROOT;
let source=readFileSync(sdk+'/tests/legacy-owner-install-intent.mjs','utf8');
if(createHash('sha256').update(source).digest('hex')!=='2aad60bcb968470a433b2643f323eae582d55eac7c68e6c785db54bb3bb07fd1')throw Error('author source changed');
source=source.replace("'./legacy-owner-install-disclosure-material.mjs'",JSON.stringify(new URL('./material.mjs',import.meta.url).href));
for(const name of ['composition','object'])source=source.replace("'./legacy-owner-install-"+name+"-material.mjs'",JSON.stringify(pathToFileURL(sdk+'/tests/legacy-owner-install-'+name+'-material.mjs').href));
await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
