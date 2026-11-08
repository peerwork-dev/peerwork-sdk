"""Stage one source-bound integration executable. Does not run or publish it."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys

name,build_log,destination=sys.argv[1:]
assert name=='shared_conversation', 'unselected qualification target'
root=Path(__file__).resolve().parents[2]
outputs=[]
for line in Path(build_log).read_text().splitlines():
    row=json.loads(line)
    if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')==name and 'test' in row['target']['kind'] and row.get('executable'):
        outputs.append(Path(row['executable']))
assert len(outputs)==1, 'exactly one compiled selected target required'
binary=outputs[0].resolve();assert binary.is_relative_to((root/'target/release').resolve())
out=Path(destination);assert out.is_dir();target=out/(name+'-qualification')
shutil.copyfile(binary,target);target.chmod(0o755)
record={'format':'peerwork.public-api-test.v1','target':'linux-x64-gnu','test_target':name,'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'executable':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'bytes':target.stat().st_size,'run_id':os.environ.get('GITHUB_RUN_ID'),'executed':False,'publication':'NOT_A_RELEASE_ASSET','scope':'Run this binary only against explicitly selected synthetic local TEST fixtures.'}
(out/'public-api-test.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
