"""Linux/x64 own-child syscall metadata barrier. Never reads write buffers."""
import ctypes,os,signal,struct,time
PTRACE_TRACEME=0;PTRACE_PEEKDATA=2;PTRACE_CONT=7;PTRACE_SYSCALL=24;PTRACE_SETOPTIONS=0x4200;PTRACE_GET_SYSCALL_INFO=0x420e
libc=ctypes.CDLL(None,use_errno=True);libc.ptrace.restype=ctypes.c_long;libc.ptrace.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
def call(req,pid,a=0,b=0):
 ctypes.set_errno(0);result=libc.ptrace(req,pid,a,b)
 if result==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),'own-child ptrace')
 return result
def path_string(pid,address):
 # Only rename pathname arguments are inspected. Payload/key/write buffers are never read.
 data=bytearray()
 for offset in range(0,4096,8):
  word=call(PTRACE_PEEKDATA,pid,address+offset,0)&((1<<64)-1);chunk=word.to_bytes(8,'little')
  if b'\0'in chunk:return os.fsdecode(bytes(data)+chunk.split(b'\0')[0])
  data+=chunk
 raise ValueError('rename path exceeds bounded metadata limit')
def traced_writer(argv,env,target,phase,stdout,stderr,boundary):
 assert phase in ['entry-kill','exit-kill','release'] and os.path.isabs(target)
 out=open(stdout,'wb');err=open(stderr,'wb');pid=os.fork()
 if pid==0:
  os.dup2(out.fileno(),1);os.dup2(err.fileno(),2)
  try:
   call(PTRACE_TRACEME,0);os.kill(os.getpid(),signal.SIGSTOP);os.execve(argv[0],argv,env)
  except BaseException:os._exit(111)
 out.close();err.close();events=[];hit=False;pending=None;last_fsync=False;started=time.monotonic()
 def alarm(*_):raise TimeoutError('own public writer did not reach requested rename boundary')
 previous=signal.signal(signal.SIGALRM,alarm);signal.alarm(90)
 try:
  got,status=os.waitpid(pid,0);assert got==pid and os.WIFSTOPPED(status),(pid,status)
  call(PTRACE_SETOPTIONS,pid,0,0x1|0x100000)
  while True:
   call(PTRACE_SYSCALL,pid)
   got,status=os.waitpid(pid,0);assert got==pid
   if os.WIFEXITED(status):return dict(pid=pid,exit_code=os.WEXITSTATUS(status),killed=False,boundary_reached=hit,events=events,duration_seconds=time.monotonic()-started)
   if os.WIFSIGNALED(status):raise AssertionError(('writer terminated before requested result',os.WTERMSIG(status)))
   sig=os.WSTOPSIG(status)
   if sig!=(signal.SIGTRAP|0x80):continue
   buf=ctypes.create_string_buffer(128);size=call(PTRACE_GET_SYSCALL_INFO,pid,128,ctypes.addressof(buf));raw=buf.raw
   op=raw[0]
   if op==1:
    nr=struct.unpack_from('<Q',raw,24)[0];args=struct.unpack_from('<6Q',raw,32)
    pending=('fsync',)if nr==74 else None
    if nr in [82,264,316]:
     old=path_string(pid,args[0]if nr==82 else args[1]);new=path_string(pid,args[1]if nr==82 else args[3])
     if new==target:
      assert not hit and os.path.isabs(old) and os.path.dirname(old)==os.path.dirname(target)
      assert os.path.basename(old).startswith('.peerwork-state-') and os.stat(old).st_mode&0o077==0
      assert last_fsync,'expected successful tempfile fsync before same-parent rename'
      pending=('target',nr)
      if phase in ['entry-kill','release']:
       hit=True;record=dict(phase='rename-entry',syscall=nr,same_parent_private_temp=True,prior_fsync_success=True)
       record.update(boundary(pid,record));events.append(record)
       if phase=='entry-kill':
        os.kill(pid,signal.SIGKILL);got,status=os.waitpid(pid,0);assert os.WIFSIGNALED(status)and os.WTERMSIG(status)==signal.SIGKILL
        return dict(pid=pid,exit_code=-9,killed=True,boundary_reached=True,events=events,duration_seconds=time.monotonic()-started)
   elif op==2:
    result=struct.unpack_from('<q',raw,24)[0]
    if pending and pending[0]=='fsync':last_fsync=result==0
    if pending and pending[0]=='target' and phase=='exit-kill':
     assert result==0;hit=True;record=dict(phase='rename-exit',syscall=pending[1],rename_result=0,before_next_syscall=True,prior_fsync_success=True)
     record.update(boundary(pid,record));events.append(record)
     os.kill(pid,signal.SIGKILL);got,status=os.waitpid(pid,0);assert os.WIFSIGNALED(status)and os.WTERMSIG(status)==signal.SIGKILL
     return dict(pid=pid,exit_code=-9,killed=True,boundary_reached=True,events=events,duration_seconds=time.monotonic()-started)
    pending=None
 finally:
  signal.alarm(0);signal.signal(signal.SIGALRM,previous)
  try:os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
  except(ProcessLookupError,ChildProcessError):pass
