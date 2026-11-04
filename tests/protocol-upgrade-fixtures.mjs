// Reuse the product's normalized opt-in contract in isolated native tests.
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
const root=process.env.PEERWORK_STRUCTURE_REFERENCE_ROOT;
if(!root)throw Error('explicit product fixture root required');
const {upgradeBundleFixture,upgradeWriterSelection}=await import(pathToFileURL(join(root,'dist-workspace/tests/fixtures/workspace-protocol-upgrade-fixture.js')));
const {parseProtocolBundle}=await import(pathToFileURL(join(root,'dist-workspace/src/workspace-protocol-bundle.js')));
const v1=upgradeBundleFixture(),v2=upgradeBundleFixture('2',parseProtocolBundle(v1).protocolDigest);
console.log(JSON.stringify({v1,v2,role1:upgradeBundleFixture('1',undefined,'V1 revised role instructions.'),oldRole:upgradeBundleFixture('1',undefined,'V1 old-work instruction revision.'),writer1:upgradeWriterSelection(v1),writer2:upgradeWriterSelection(v2)}));
