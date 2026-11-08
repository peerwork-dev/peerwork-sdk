import os,sys
backup,wal,mode=sys.argv[1:]
fd=os.open(wal,os.O_CREAT|os.O_RDWR|os.O_TRUNC,0o600)
try:
 if mode=='prearm-headers':
  os.pwrite(fd,b'H'*32,0);os.pwrite(fd,b'F'*24,32)
 if mode!='missing-close':
  f=os.open(backup,os.O_RDONLY);os.close(f)
 if mode!='prearm-headers':
  os.pwrite(fd,b'H'*32,0);os.pwrite(fd,b'F'*24,32)
 os.pwrite(fd,b'P'*(511 if mode=='short-payload' else 512),56)
finally:os.close(fd)
