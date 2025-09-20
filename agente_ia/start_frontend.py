#!/usr/bin/env python3

import http.server
import socketserver
import os
import sys

# Configura o diretório do frontend
frontend_dir = os.path.join(os.path.dirname(__file__), 'frontend')
os.chdir(frontend_dir)

# Configura porta
port = int(os.getenv('FRONTEND_PORT', 3000))

# Configura handler
Handler = http.server.SimpleHTTPRequestHandler

try:
    with socketserver.TCPServer(("", port), Handler) as httpd:
        print(f"🎨 Frontend servindo em http://localhost:{port}")
        print("📁 Diretório:", os.getcwd())
        httpd.serve_forever()
except KeyboardInterrupt:
    print("\n🛑 Frontend finalizado")
except Exception as e:
    print(f"❌ Erro no frontend: {e}")
    sys.exit(1) 