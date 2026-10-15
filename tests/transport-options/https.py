"""Fresh local synthetic TLS fixture; generated key files never leave runtime leaf."""
from pathlib import Path
import os,json,subprocess,ssl,threading,time,datetime
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
W=Path(__file__).resolve().parents[2];E=W/'.test-data/t086';leaf=E/'tls-runtime';leaf.mkdir(mode=0o700)
for args in [
 ['req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=SDK synthetic test CA'],
 ['req','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=localhost'],
 ['x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','1','-extfile','extension.cnf']]:
 if args[0]=='x509':(leaf/'extension.cnf').write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
 subprocess.run(['/usr/bin/openssl',*args],cwd=leaf,check=True,capture_output=True)
for p in leaf.iterdir():p.chmod(0o600)
requests=[]
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  requests.append(dict(method='GET',path=self.path));assert self.path=='/api/workspace/v1/discovery'
  if len(requests)==2:time.sleep(.3)
  body=b'{"ok":true}';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
  try:self.wfile.write(body)
  except (BrokenPipeError,ssl.SSLError):pass
 def do_POST(self):requests.append(dict(method='POST',path=self.path));self.send_error(405)
server=ThreadingHTTPServer(('127.0.0.1',0),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(leaf/'server.pem',leaf/'server.key');server.socket=context.wrap_socket(server.socket,server_side=True)
thread=threading.Thread(target=server.serve_forever);thread.start()
env=dict(os.environ,PEERWORK_TLS_ORIGIN=f'https://localhost:{server.server_port}',PEERWORK_TLS_CA=str(leaf/'ca.pem'))
env.pop('PEERWORK_HTTP_PROXY',None)
cmd=['/tmp/peerwork-rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin/cargo','test','--offline','--locked','-p','peerwork-runtime','--lib','local_https_preserves_validation_and_selected_deadline','--','--ignored','--nocapture']
start=time.monotonic();began=datetime.datetime.now(datetime.timezone.utc).isoformat()
try:
 with (E/'https.log').open('wb') as log:r=subprocess.run(cmd,cwd=W,env=env,stdout=log,stderr=subprocess.STDOUT)
finally:server.shutdown();server.server_close();thread.join()
result=dict(exit_code=r.returncode,started=began,ended=datetime.datetime.now(datetime.timezone.utc).isoformat(),seconds=time.monotonic()-start,requests=requests,post_count=sum(x['method']=='POST' for x in requests),closed=True,waited=True,synthetic_keys_logged=False)
(E/'https-terminal.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));assert r.returncode==0 and len(requests)==3 and result['post_count']==0
