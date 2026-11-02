"""Check the exact GOST binary against WS/WSS plus HTTPS initial reporting.
Only loopback in a --network none container; certificates are disposable.
"""
import base64,datetime,hashlib,http.server,json,os,pathlib,ssl,struct,subprocess,threading,time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress
OUT=pathlib.Path('/evidence');OUT.mkdir(exist_ok=True)
assert not any('default' in line for line in subprocess.check_output(['ip','route'],text=True).splitlines())
key=rsa.generate_private_key(public_exponent=65537,key_size=2048);subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'isolated-gost-test')]);now=datetime.datetime.utcnow()
cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.IPv4Address('127.0.0.1'))]),critical=False).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256())
pathlib.Path('/tmp/compat-cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM));pathlib.Path('/tmp/compat-key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
class H(http.server.BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1';connected=False;reported=False
 def log_message(self,*args):pass
 def do_POST(self):
  self.rfile.read(int(self.headers.get('Content-Length','0')))
  if self.path.startswith('/flow/config'):type(self).reported=True
  self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
 def do_GET(self):
  if self.headers.get('Upgrade','').lower()!='websocket':self.send_error(404);return
  accept=base64.b64encode(hashlib.sha1((self.headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode();self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade');self.send_header('Sec-WebSocket-Accept',accept);self.end_headers();type(self).connected=True;self.close_connection=True
  try:
   while self.rfile.read(1):pass
  except OSError:pass
result={'arch':os.uname().machine,'sha256':hashlib.sha256(pathlib.Path('/build/gost').read_bytes()).hexdigest(),'ws':False,'wss':False}
for scheme in ['ws','wss']:
 class Handler(H):connected=False;reported=False
 server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
 if scheme=='wss':context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('/tmp/compat-cert.pem','/tmp/compat-key.pem');server.socket=context.wrap_socket(server.socket,server_side=True)
 threading.Thread(target=server.serve_forever,daemon=True).start();directory=pathlib.Path('/tmp/compat-'+scheme);directory.mkdir();(directory/'config.json').write_text(json.dumps({'addr':scheme+'://localhost:'+str(server.server_port),'secret':'isolated-gost-compat-only'}));(directory/'gost.json').write_text('{}')
 env=os.environ.copy();env['SSL_CERT_FILE']='/tmp/compat-cert.pem'
 with (OUT/(scheme+'.log')).open('w') as log:
  p=subprocess.Popen(['/build/gost'],cwd=directory,stdout=log,stderr=subprocess.STDOUT,env=env)
  end=time.monotonic()+20
  try:
   while time.monotonic()<end and p.poll() is None and not(Handler.connected and Handler.reported):time.sleep(.1)
   assert Handler.connected and Handler.reported,(scheme,'handshake',Handler.connected,'initial-config',Handler.reported)
   result[scheme]=True;print('PASS',scheme,'WebSocket registration and initial config reporting',flush=True)
  finally:
   p.terminate()
   try:p.wait(timeout=4)
   except subprocess.TimeoutExpired:p.kill();p.wait()
 server.shutdown();server.server_close()
(OUT/'gost-compat.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
