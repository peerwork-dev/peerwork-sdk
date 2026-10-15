"""Offline analysis of supported public inventory and public fixture metadata only."""
import hashlib,json
from pathlib import Path
from urllib.parse import urlsplit
here=Path(__file__).resolve().parents[2];data=here/'.test-data/t061';inventory=json.loads((data/'inventory.stdout').read_text());assert len(inventory)==1
root=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/marker-sdk-t023-20261015/rootfs').resolve();fixture=json.loads((root/'work/t059-archive-service-env-fixed/fixture.json').read_text());origin=fixture['origin'];url=urlsplit(origin)
assert url.scheme=='http' and url.hostname=='127.0.0.1' and url.path=='' and not url.query and not url.fragment
assert inventory[0]['workspace_id']==fixture['workspace_id'] and inventory[0]['status']=='PREPARED'
sdk=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012');names=['crates/runtime/src/secure_owner_attach.rs','crates/runtime/src/secure_lifecycle.rs','crates/runtime/src/secure_owner_create.rs']
value=dict(result='PUBLIC_PREPARED_CONFIRMED; ORIGIN_VALIDATION_MISMATCH_SOURCE_INFERRED',attachment=inventory[0],configured_origin=origin,canonical_lifecycle_origin=origin+'/',lifecycle_origin_precondition_satisfied=False,failed_operation_observed=False,no_resume_or_new_attach_attempt=True,source_hashes={n:hashlib.sha256((sdk/n).read_bytes()).hexdigest() for n in names})
(data/'diagnosis.json').write_text(json.dumps(value,indent=2)+'\n');print(json.dumps(value))
