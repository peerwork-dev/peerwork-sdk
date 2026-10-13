// Browser readback for the exact workspace created by the installed native
// proposal → adoption → task acceptance test. It does not author actions.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';

const reference = process.env.PEERWORK_REFERENCE_ROOT;
const state = process.env.PEERWORK_TEST_STATE;
const workspaceId = process.env.PEERWORK_TEST_WORKSPACE;
const taskId = process.env.PEERWORK_TEST_TASK_RECORD;
const candidateId = process.env.PEERWORK_TEST_CANDIDATE_RECORD;
const output = process.env.PEERWORK_TEST_BROWSER_OUTPUT;
if (![reference,state,workspaceId,taskId,candidateId,output].every(Boolean))
  throw new Error('exact reference, state, workspace, record IDs and output are required');
for (const token of [workspaceId,taskId,candidateId])
  assert.match(token,/^[A-Za-z0-9_-]{43}$/);

const fromReference=createRequire(join(reference,'package.json'));
const {serve}=await import(pathToFileURL(fromReference.resolve('@hono/node-server')).href);
const {chromium}=fromReference('@playwright/test');
const at=async name=>import(pathToFileURL(join(reference,'dist-workspace/src',name)).href);
const {WorkspaceProjector,openPublicProjectionReadOnly}=await at('workspace-projector.js');
const {createWorkspacePublicApp}=await at('workspace-http.js');
const projection=join(state,'public-browser-projection.sqlite');
let projector,publicDb,server,browser;
try {
  projector=new WorkspaceProjector(join(state,'control.sqlite'),projection);
  projector.publish(1000);
  publicDb=openPublicProjectionReadOnly(projection);
  server=serve({fetch:createWorkspacePublicApp(publicDb).fetch,hostname:'127.0.0.1',port:0});
  await new Promise(resolve=>server.once('listening',resolve));
  const origin=`http://127.0.0.1:${server.address().port}`;
  browser=await chromium.launch({headless:true});
  const errors=[];
  mkdirSync(output,{recursive:true});
  for(const width of [390,1280]){
    const page=await browser.newPage({viewport:{width,height:844}});
    page.on('pageerror',error=>errors.push(error.message));
    await page.goto(`${origin}/workspaces/${workspaceId}/records/${taskId}`);
    await page.waitForFunction(()=>document.querySelector('[data-secure-public-workspace]')?.dataset.secureIntegrity==='verified',undefined,{timeout:20000});
    const task=page.locator(`[data-record-id="${taskId}"]`);
    await task.waitFor();
    assert.match(await task.innerText(),/Execute adopted proposal/);
    const source=task.locator(`a[data-relation-kind="tasks.based_on_candidate"][href$="/records/${candidateId}"]`);
    assert.equal(await source.count(),1);
    assert.equal(await source.getAttribute('data-target-revision'),'1');
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    await page.screenshot({path:join(output,`composed-task-record-${width}.png`),fullPage:true});
    await source.click();
    assert.equal(new URL(page.url()).pathname,`/workspaces/${workspaceId}/records/${candidateId}`);
    await page.waitForFunction(()=>document.querySelector('[data-secure-public-workspace]')?.dataset.secureIntegrity==='verified',undefined,{timeout:20000});
    const candidate=page.locator(`[data-record-id="${candidateId}"]`);
    await candidate.waitFor();
    assert.match(await candidate.innerText(),/Turn decision into task/);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    await page.close();
  }
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({task_record_verified:true,candidate_record_verified:true,
    task_source_link_clicked:true,target_revision:1,viewports:[390,1280],no_horizontal_overflow:true}));
} finally {
  await browser?.close();
  if(server){server.closeAllConnections?.();await new Promise(resolve=>server.close(resolve));}
  publicDb?.close();
  projector?.close();
}
