import ssl
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

HTTP_PORT = 8080
HTTPS_PORT = 8443

class MyRequestHandler(BaseHTTPRequestHandler):
    message = "hello\n"

    def my_send_response(self, content):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(content.encode(encoding='utf-8'))

    def do_GET(self):
        print("Headers: ", self.headers)
        self.my_send_response(self.message)

def start_http_server(http_host, http_port):
    print(f'Serving on port {http_port} (HTTP) ...')
    HTTPServer((http_host, http_port), MyRequestHandler).serve_forever()

def start_https_server(http_host, http_port):
    # 创建 SSL/TLS 上下文
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # 加载证书和密钥
    context.load_cert_chain(certfile='test/test.crt', keyfile="test/test.key")

    # 创建 HTTP 服务器，并使用 wrap_socket() 方法包装 socket
    httpd = HTTPServer((http_host, http_port), MyRequestHandler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    # 启动服务器
    print(f'Serving on port {http_port} (HTTPS) ...')
    httpd.serve_forever()


if __name__ == '__main__':
    # 启动HTTP服务
    http_thread = threading.Thread(target=start_http_server, args=('localhost', HTTP_PORT))
    http_thread.start()

    # 启动HTTPS服务
    https_thread = threading.Thread(target=start_https_server, args=('localhost', HTTPS_PORT))
    https_thread.start()
