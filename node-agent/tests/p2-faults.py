"""Reuse the nine durable crash boundaries with schema4 local OUTPUT enabled."""
from pathlib import Path
source=Path('/tests/p1-faults.py').read_text()
source=source.replace("'schemaVersion':3", "'schemaVersion':4")
source=source.replace("'bandwidth':{'upBitsPerSecond':10000000,'downBitsPerSecond':10000000}", "'traffic':{'localOutput':True,'sourceMode':'preserve','returnPathConfirmed':True}")
source=source.replace("probe()", "(probe() and run(ns('router','python3','-c',\"import socket;s=socket.create_connection(('10.205.1.1',18000),timeout=2);s.sendall(b'journal');assert s.recv(1024)==b'journal';s.close();print('ok')\"))=='ok')")
source=source.replace('advanced multi-target/shaping baseline', 'schema4 multi-target/local OUTPUT baseline').replace('advanced crash recovery', 'schema4 local-path crash recovery')
source=source.replace('p1-fault-result.json','p2-fault-result.json')
exec(compile(source,'/tests/p1-faults.py','exec'))
