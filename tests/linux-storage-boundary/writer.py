import os,json,sys
from pathlib import Path
import peerwork
assert Path(peerwork.__file__).is_relative_to(Path(os.environ['PEERWORK_TEST_SDK_ROOT'])/'dist/python-consumer')
config=json.loads(Path(sys.argv[1]).read_text());owner=peerwork.SecureOwnerWorkspaceClient(config['origin'],config['state_dir'],allow_loopback_http=True)
result=owner.prepare('storage-'+sys.argv[2],'PRIVATE',structured=True)
print(json.dumps(result),flush=True)
