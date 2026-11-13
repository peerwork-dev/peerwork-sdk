"""Synthetic qualification relay; log handshake facts, never tool arguments."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading

trace=Path(sys.argv[1]);child=subprocess.Popen(sys.argv[2:],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
lock=threading.Lock()
def note(direction,line):
    try:
        value=json.loads(line);params=value.get('params',{});result=value.get('result',{})
        row={'direction':direction,'id':value.get('id'),'method':value.get('method'),
             'requested':params.get('protocolVersion') or params.get('_meta',{}).get('io.modelcontextprotocol/protocolVersion'),
             'negotiated':result.get('protocolVersion'),'error_code':value.get('error',{}).get('code')}
        with lock:
            with trace.open('a') as out:out.write(json.dumps(row)+'\n')
    except (ValueError,AttributeError):pass

def forward():
    try:
        for line in sys.stdin.buffer:
            note('HOST_TO_SERVER',line);child.stdin.write(line);child.stdin.flush()
    except BrokenPipeError:pass
    finally:child.stdin.close()

threading.Thread(target=forward,daemon=True).start()
signal.signal(signal.SIGTERM,lambda *_:child.terminate())
for line in child.stdout:
    note('SERVER_TO_HOST',line);sys.stdout.buffer.write(line);sys.stdout.buffer.flush()
sys.exit(child.wait(timeout=10))
