"""Local WebAuthn relying party that verifies registration and assertion signatures."""

import json
import secrets
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer

from fido2.server import Fido2Server

HTML = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FIDO2 local test</title><style>
body{background:#10181a;color:#edf3ee;font:17px system-ui;margin:0;display:grid;
place-content:center;min-height:100vh}main{max-width:640px;padding:32px}
h1{font-size:44px;letter-spacing:-2px;margin-bottom:12px}
p{color:#becdc5;line-height:1.7}button{padding:14px 22px;font:inherit;border:0;
border-radius:6px;background:#c7e89c;color:#142217;cursor:pointer;margin:8px 8px 8px 0}
button:disabled{opacity:.45}pre{white-space:pre-wrap;color:#c7e89c;line-height:1.6}
</style><main><small>LOCAL WEBAUTHN TEST / USB AUTHENTICATOR</small>
<h1>Meet your virtual key.</h1><p>Plug in the emulator. Register a credential, then
sign in. Choose <b>Security key</b> in the Windows prompt and approve
<b>Touch key</b> in the emulator panel. Both responses are verified by this local server.</p>
<label><input type="checkbox" id="uv"> Require PIN verification</label><br>
<button id="register">1. Register key</button><button id="login">2. Sign in</button>
<pre id="result" role="status">Ready. Credentials for this demo live until its server stops.</pre>
<script>
const result=document.querySelector('#result');
function decode(s){return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),
c=>c.charCodeAt(0));}
function encode(b){return btoa(String.fromCharCode(...new Uint8Array(b)))
.replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}
async function post(path,data={}){const response=await fetch(path,{method:'POST',
headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
const body=await response.json();if(!response.ok)throw Error(body.error);return body;}
async function perform(kind){document.querySelectorAll('button').forEach(b=>b.disabled=true);
try{result.textContent='Waiting for Windows and your key…';
let options=await post('/'+kind+'/begin',{uv:document.querySelector('#uv').checked});
let pk=options.publicKey;pk.challenge=decode(pk.challenge);
for(const list of ['excludeCredentials','allowCredentials'])
if(pk[list])pk[list]=pk[list].map(c=>({...c,id:decode(c.id)}));
if(pk.user)pk.user.id=decode(pk.user.id);
const credential=kind==='register'?await navigator.credentials.create({publicKey:pk}):
await navigator.credentials.get({publicKey:pk});
const response={clientDataJSON:encode(credential.response.clientDataJSON)};
for(const field of ['attestationObject','authenticatorData','signature','userHandle'])
if(credential.response[field])response[field]=encode(credential.response[field]);
const verified=await post('/'+kind+'/complete',{id:credential.id,rawId:encode(credential.rawId),
type:credential.type,response,clientExtensionResults:credential.getClientExtensionResults()});
result.textContent=verified.message;
}catch(error){result.textContent=error.name+': '+error.message;}
finally{document.querySelectorAll('button').forEach(b=>b.disabled=false);}}
document.querySelector('#register').onclick=()=>perform('register');
document.querySelector('#login').onclick=()=>perform('login');
</script></main></html>"""


def make_handler():
    server = Fido2Server(
        {"id": "localhost", "name": "Local FIDO2 Test"},
        verify_origin=lambda origin: origin == "http://localhost:8765",
    )
    credentials = []
    sessions = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def send_json(self, status, data):
            payload = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def valid_host(self):
            return self.headers.get("Host") == "localhost:8765"

        def do_GET(self):
            if not self.valid_host() or self.path != "/":
                self.send_error(404)
                return
            session = secrets.token_urlsafe(32)
            # Bounded in-memory demo sessions; no persistent browser account data.
            if len(sessions) >= 128:
                sessions.pop(next(iter(sessions)))
            sessions[session] = {}
            payload = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Set-Cookie", f"session={session}; HttpOnly; SameSite=Strict; Path=/")
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            if not self.valid_host() or self.headers.get("Origin") != "http://localhost:8765":
                self.send_json(403, {"error": "Invalid local origin"})
                return
            try:
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
                session = sessions[cookie["session"].value]
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 65536:
                    raise ValueError("Invalid request length")
                request = json.loads(self.rfile.read(size))
                if self.path == "/register/begin":
                    options, state = server.register_begin(
                        {"id": b"lab-user", "name": "lab-user", "displayName": "Lab User"},
                        credentials=credentials,
                        user_verification="required" if request.get("uv") else "discouraged",
                        authenticator_attachment="cross-platform",
                    )
                    session["register"] = state
                    self.send_json(200, dict(options))
                elif self.path == "/register/complete":
                    result = server.register_complete(session.pop("register"), request)
                    credentials.append(result.credential_data)
                    self.send_json(200, {"message": "Registration verified. Now sign in."})
                elif self.path == "/login/begin":
                    if not credentials:
                        raise ValueError("Register a key first.")
                    options, state = server.authenticate_begin(
                        credentials,
                        user_verification="required" if request.get("uv") else "discouraged",
                    )
                    session["login"] = state
                    self.send_json(200, dict(options))
                elif self.path == "/login/complete":
                    server.authenticate_complete(session.pop("login"), credentials, request)
                    self.send_json(
                        200,
                        {"message": "Sign-in verified: challenge, origin, RP, touch, signature."},
                    )
                else:
                    self.send_json(404, {"error": "Unknown endpoint"})
            except (ValueError, KeyError, TypeError) as error:
                self.send_json(400, {"error": str(error)})

    return Handler


def run_demo():
    with HTTPServer(("127.0.0.1", 8765), make_handler()) as http:
        http.timeout = 5
        print("Local test: http://localhost:8765 (Ctrl+C to stop)")
        webbrowser.open("http://localhost:8765")
        http.serve_forever()
