import os
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import cgi

class CustomHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>File Upload and Download</h1>')
            self.wfile.write(b'<form enctype="multipart/form-data" method="post">')
            self.wfile.write(b'<input type="file" name="file"><input type="submit" value="Upload"></form>')
            self.wfile.write(b'<hr>')
            self.wfile.write(b'<h2>Files:</h2><ul>')
            for filename in os.listdir('.'):
                if os.path.isfile(filename):
                    self.wfile.write(f'<li><a href="/download/{filename}">{filename}</a></li>'.encode())
            self.wfile.write(b'</ul></body></html>')
        elif self.path.startswith('/download/'):
            filename = self.path[len('/download/'):]
            if os.path.isfile(filename):
                self.send_response(200)
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.end_headers()
                with open(filename, 'rb') as file:
                    self.wfile.write(file.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'File not found')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')

    def do_POST(self):
        content_type, _ = cgi.parse_header(self.headers.get('Content-Type'))
        if content_type == 'multipart/form-data':
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'})
            file_item = form['file']
            if file_item.filename:
                with open(file_item.filename, 'wb') as output_file:
                    output_file.write(file_item.file.read())
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<html><body><h2>File uploaded successfully</h2><a href="/">Back</a></body></html>')
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'No file uploaded')
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Bad request')

def run_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, CustomHTTPRequestHandler)
    print(f'Server running on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple HTTP server for file upload and download')
    parser.add_argument('-p', '--port', type=int, default=8000, help='Port number (default: 8000)')
    args = parser.parse_args()
    run_server(args.port)

