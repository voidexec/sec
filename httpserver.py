#!/usr/bin/env python3
from http.server import SimpleHTTPRequestHandler, HTTPServer
import cgi, os, argparse

class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'}
        )

        if "file" not in form:
            self.send_response(400); self.end_headers()
            self.wfile.write(b"No file")
            return

        fileitem = form["file"]
        filename = os.path.basename(fileitem.filename)

        with open(filename, "wb") as f:
            f.write(fileitem.file.read())

        self.send_response(200); self.end_headers()
        self.wfile.write(b"OK")

    def list_directory(self, path):
        files = os.listdir(path)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        self.wfile.write(b"<form method=POST enctype=multipart/form-data>")
        self.wfile.write(b"<input type=file name=file>")
        self.wfile.write(b"<input type=submit value=Upload></form><hr><ul>")
        for f in files:
            self.wfile.write(f"<li><a href='/{f}'>{f}</a></li>".encode())
        self.wfile.write(b"</ul>")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple HTTP Server for Upload/Download")
    parser.add_argument("-p", "--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), Handler)
    print(f"[+] HTTP file server started on 0.0.0.0:{args.port}")
    server.serve_forever()
