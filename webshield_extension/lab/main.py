from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/data':
            payload = json.dumps({"secret_demo": "dato-de-prueba", "ok": True}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        html = '''<!doctype html>
<html><head><meta charset="utf-8"><title>WebShield Lab</title></head>
<body>
<h1>Laboratorio WebShield</h1>
<p>Esta página contiene un caso CORS de laboratorio y recursos de terceros simulados.</p>
<script src="https://cdn.example.invalid/library.js"></script>
<script src="/local.js" integrity="sha256-demo"></script>
<script>fetch('/api/data').then(r=>r.json()).then(console.log)</script>
</body></html>'''.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def log_message(self, fmt, *args):
        print(fmt % args)

HTTPServer(('127.0.0.1', 8080), Handler).serve_forever()
