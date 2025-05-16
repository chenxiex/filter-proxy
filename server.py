import socket
import threading
import select
from urllib.parse import urlparse
import json
import time
import http.server
import socketserver
from urllib.parse import parse_qs, urlparse
import re
import os
import signal  # 添加signal模块导入

# 配置文件路径
CONFIG_FILE = os.getenv('CONFIG_FILE', 'config.json')
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'

# 代理服务器配置
PROXY_HOST = '0.0.0.0'  # 监听所有网络接口
PROXY_PORT = 22223      # 默认监听端口
RPC_HOST = '0.0.0.0'  # RPC监听所有网络接口
RPC_PORT = 22224      # RPC端口
MAX_CONNECTIONS = 1024 # 最大连接数

# 代理控制变量
FILTER_ENABLED = False
FILTER_UNTIL = 0  # 0表示永久，其他值表示时间戳

# 过滤规则配置
# 每个规则包含：type(deny/allow), host_pattern, port, priority
# type: 'deny' - 丢弃匹配的请求, 'allow' - 允许匹配的请求通过
# host_pattern: 主机名匹配模式，支持正则表达式
# port: 端口匹配，0表示匹配所有端口
# priority: 优先级，数字越大优先级越高
FILTER_RULES = [
    # 默认规则：允许访问RPC服务器
    {"type": "allow", "host_pattern": r"(localhost|127\.0\.0\.1)", "port": RPC_PORT, "priority": 100},
    # 默认规则：当过滤开启时，丢弃所有其它请求
    {"type": "deny", "host_pattern": r".*", "port": 0, "priority": 0}
]

# 用于调试的日志函数
def debug_log(message):
    """只在DEBUG模式下打印日志"""
    if DEBUG:
        print(f"[DEBUG] {message}")

def info_log(message):
    """始终打印的重要信息"""
    print(f"[INFO] {message}")

# 读取配置文件
def load_config():
    global CONFIG_FILE, PROXY_HOST, PROXY_PORT, RPC_HOST, RPC_PORT, FILTER_RULES
    try:
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)
            # 加载代理服务器配置
            PROXY_HOST = config.get('proxy_host', PROXY_HOST)
            PROXY_PORT = config.get('proxy_port', PROXY_PORT)
            RPC_HOST = config.get('rpc_host', RPC_HOST)
            RPC_PORT = config.get('rpc_port', RPC_PORT)
            MAX_CONNECTIONS = config.get('max_connections', MAX_CONNECTIONS)
            
            # 加载过滤规则
            if 'filter_rules' in config and isinstance(config['filter_rules'], list):
                loaded_rules = []
                for rule in config['filter_rules']:
                    # 验证规则格式是否正确
                    if all(key in rule for key in ['type', 'host_pattern', 'port', 'priority']):
                        # 确保类型正确
                        if rule['type'] in ['allow', 'deny']:
                            try:
                                # 验证正则表达式
                                re.compile(rule['host_pattern'])
                                # 确保端口和优先级是整数
                                rule['port'] = int(rule['port'])
                                rule['priority'] = int(rule['priority'])
                                loaded_rules.append(rule)
                            except (re.error, ValueError) as e:
                                debug_log(f"Invalid rule in config: {rule}, error: {str(e)}")
                
                if loaded_rules:
                    info_log(f"Loaded {len(loaded_rules)} filter rules from config file")
                    # 替换默认规则，但确保RPC服务器始终可访问
                    FILTER_RULES = loaded_rules
    except Exception as e:
        info_log(f"Unexpected error loading config: {e}. Using default settings.")

# 缓冲区大小
BUFFER_SIZE = 8192

# 检测回环请求的函数
def is_loopback_request(host, port):
    """检查请求是否是回环请求(访问代理服务器自身)"""
    if host == 'localhost' or host == '127.0.0.1' or host == PROXY_HOST:
        if port == PROXY_PORT:
            return True
    return False

# 检查请求是否符合过滤规则
def should_filter_request(host, port):
    """检查请求是否应该被过滤（丢弃）"""
    global FILTER_ENABLED, FILTER_UNTIL, FILTER_RULES
    
    # 如果过滤功能未启用，不过滤任何请求
    if not FILTER_ENABLED:
        return False
        
    # 如果设置了结束时间，检查是否已经到期
    if FILTER_UNTIL > 0 and time.time() > FILTER_UNTIL:
        FILTER_ENABLED = False
        FILTER_UNTIL = 0
        info_log("Packet filtering has expired. Resuming normal operation.")
        return False
    
    # 应用过滤规则，按优先级排序
    sorted_rules = sorted(FILTER_RULES, key=lambda r: r["priority"], reverse=True)
    
    for rule in sorted_rules:
        host_pattern = rule["host_pattern"]
        rule_port = rule["port"]
        rule_type = rule["type"]
        
        # 检查主机名是否匹配
        if re.match(host_pattern, host):
            # 检查端口是否匹配（0表示匹配所有端口）
            if rule_port == 0 or rule_port == port:
                # 根据规则类型决定是否过滤
                if rule_type == "deny":
                    return True  # 应该丢弃
                elif rule_type == "allow":
                    return False  # 不应丢弃
    
    # 默认行为：不丢弃
    return False

# 处理HTTP请求
def handle_http(client_socket, request, address):
    # 解析第一行
    first_line = request.split(b'\n')[0].decode('utf-8', errors='ignore')
    method, url, _ = first_line.split(' ', 2)

    if method == 'CONNECT':
        # 处理HTTPS请求
        host = url.split(':', 1)[0]
        port = int(url.split(':', 1)[1]) if ':' in url else 443
    else:
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        
        # 如果没有指定端口，根据协议设置默认端口
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = 80
    
    # 检查是否应该过滤（丢弃）该请求
    if should_filter_request(host, port):
        debug_log(f"Filtering request from {address} to {host}:{port}")
        client_socket.close()
        return

    debug_log(f"Received {method} request for {url} from {address}, forwarding to {host}:{port}")
     
    # 检查是否为回环请求
    if is_loopback_request(host, port):
        error_msg = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nLoopback request detected and blocked."
        client_socket.send(error_msg)
        client_socket.close()
        return
    
    target_socket = None
        
    try:
        # 创建到目标服务器的连接
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((host, port))
        
        # 转发请求到目标服务器
        if method == 'CONNECT':  # HTTPS请求
            # 告诉客户端连接已经建立
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # 双向转发数据
            forward_data(client_socket, target_socket, host, port)
        else:  # HTTP请求
            # 替换请求中的绝对URL为相对URL
            parsed_url = urlparse(url)
            request = request.replace(url.encode(), parsed_url.path.encode() or b'/')
            
            # 转发修改后的请求
            target_socket.send(request)
            
            # 从目标服务器读取响应并转发给客户端
            while True:
                response = target_socket.recv(BUFFER_SIZE)
                if len(response) == 0:
                    break
                client_socket.send(response)
                
            target_socket.close()
            client_socket.close()
            
    except Exception as e:
        try:
            error_msg = f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nError: {str(e)}"
            debug_log(f"Error: {str(e)}")
            client_socket.send(error_msg.encode())
        except:
            pass
        finally:
            client_socket.close()
            if target_socket is not None:
                target_socket.close()

# 双向转发数据
def forward_data(client_socket, target_socket, host=None, port=None):
    """在客户端和目标服务器之间双向转发数据"""
    client_socket.setblocking(False)
    target_socket.setblocking(False)
    
    while True:
        # 检查是否应该过滤（丢弃）该连接
        if host and port and should_filter_request(host, port):
            client_socket.close()
            target_socket.close()
            return
            
        # 等待直到有套接字可读
        read_sockets, _, error_sockets = select.select([client_socket, target_socket], [], [client_socket, target_socket], 30)
        
        if error_sockets:
            break
            
        if not read_sockets:  # 超时
            continue
            
        for sock in read_sockets:
            try:
                data = sock.recv(BUFFER_SIZE)
                
                if not data:  # 连接关闭
                    return
                    
                # 确定目标套接字
                if sock is client_socket:
                    target_socket.send(data)
                else:
                    client_socket.send(data)
            except:
                return
                
    # 关闭套接字
    client_socket.close()
    target_socket.close()

# 处理客户端连接
def handle_client(client_socket, address):
    try:
        # 读取客户端请求
        request = client_socket.recv(BUFFER_SIZE)
        
        if not request:
            client_socket.close()
            return
            
        # 处理HTTP/HTTPS请求
        handle_http(client_socket, request, address)
        
    except Exception:
        client_socket.close()

# 定义HTTP RPC服务器处理程序
class RPCHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global FILTER_ENABLED, FILTER_UNTIL, FILTER_RULES
        
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)
        
        if path == '/filter':
            seconds = 0
            if 'seconds' in query:
                try:
                    seconds = int(query['seconds'][0])
                except ValueError:
                    pass
                    
            FILTER_ENABLED = True
            if seconds > 0:
                FILTER_UNTIL = time.time() + seconds
                message = f"Filtering packets according to rules for {seconds} seconds"
            else:
                FILTER_UNTIL = 0
                message = "Filtering packets according to rules permanently"
                
            info_log(message)
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(message.encode())
            return
            
        elif path == '/resume':
            FILTER_ENABLED = False
            FILTER_UNTIL = 0
            message = "Resumed normal proxy operation"
            info_log(message)
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(message.encode())
            return
            
        elif path == '/status':
            if FILTER_ENABLED:
                if FILTER_UNTIL > 0:
                    remaining = max(0, FILTER_UNTIL - time.time())
                    message = f"Filtering active. {remaining:.1f} seconds remaining.\n"
                else:
                    message = "Filtering active permanently.\n"
                
                message += "Active filter rules:\n"
                for rule in sorted(FILTER_RULES, key=lambda r: r["priority"], reverse=True):
                    message += f"  {rule['type'].upper()} - Pattern: {rule['host_pattern']}, "
                    message += f"Port: {rule['port'] if rule['port'] != 0 else 'ALL'}, "
                    message += f"Priority: {rule['priority']}\n"
            else:
                message = "Normal operation. Packets are being forwarded."
                
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(message.encode())
            return
            
        elif path == '/rules':
            # 获取当前所有规则
            message = "Current filter rules:\n"
            for i, rule in enumerate(FILTER_RULES):
                message += f"{i}: {rule['type'].upper()} - Pattern: {rule['host_pattern']}, "
                message += f"Port: {rule['port'] if rule['port'] != 0 else 'ALL'}, "
                message += f"Priority: {rule['priority']}\n"
                
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(message.encode())
            return
            
        elif path == '/add_rule':
            # 添加新规则
            try:
                rule_type = query.get('type', ['deny'])[0]
                host_pattern = query.get('host', ['.*'])[0]
                port = int(query.get('port', ['0'])[0])
                priority = int(query.get('priority', ['10'])[0])
                
                if rule_type not in ['allow', 'deny']:
                    rule_type = 'deny'  # 默认拒绝
                
                new_rule = {
                    "type": rule_type,
                    "host_pattern": host_pattern,
                    "port": port,
                    "priority": priority
                }
                
                # 验证规则
                try:
                    re.compile(host_pattern)
                except re.error:
                    message = f"Error: Invalid host pattern '{host_pattern}'"
                    self.send_response(400)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(message.encode())
                    return
                
                FILTER_RULES.append(new_rule)
                
                message = f"Added new rule: {rule_type.upper()} - Pattern: {host_pattern}, "
                message += f"Port: {port if port != 0 else 'ALL'}, Priority: {priority}"
                
                info_log(message)
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(message.encode())
                return
            except Exception as e:
                message = f"Error adding rule: {str(e)}"
                self.send_response(400)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(message.encode())
                return
                
        elif path == '/remove_rule':
            # 删除规则
            try:
                # 支持通过索引删除
                if 'index' in query:
                    index = int(query['index'][0])
                    if 0 <= index < len(FILTER_RULES):
                        removed_rule = FILTER_RULES.pop(index)
                        message = f"Removed rule by index {index}: {removed_rule['type'].upper()} - Pattern: {removed_rule['host_pattern']}"
                        self.send_response(200)
                    else:
                        message = f"Error: Index {index} out of range"
                        self.send_response(400)
                # 支持通过规则属性删除
                elif 'type' in query or 'host' in query or 'port' in query or 'priority' in query:
                    # 获取查询参数
                    rule_type = query.get('type', [None])[0]
                    host_pattern = query.get('host', [None])[0]
                    port_str = query.get('port', [None])[0]
                    priority_str = query.get('priority', [None])[0]
                    
                    # 转换数字参数
                    port = int(port_str) if port_str is not None else None
                    priority = int(priority_str) if priority_str is not None else None
                    
                    # 查找匹配的规则
                    removed = False
                    to_remove = []
                    
                    for i, rule in enumerate(FILTER_RULES):
                        match = True
                        
                        # 检查每个指定的参数是否匹配
                        if rule_type is not None and rule['type'] != rule_type:
                            match = False
                        if host_pattern is not None and rule['host_pattern'] != host_pattern:
                            match = False
                        if port is not None and rule['port'] != port:
                            match = False
                        if priority is not None and rule['priority'] != priority:
                            match = False
                            
                        if match:
                            to_remove.append(i)
                    
                    # 从后向前删除，避免索引变化问题
                    to_remove.sort(reverse=True)
                    for i in to_remove:
                        removed_rule = FILTER_RULES.pop(i)
                        removed = True
                        
                    if removed:
                        message = f"Removed {len(to_remove)} matching rules"
                        self.send_response(200)
                    else:
                        message = "No matching rules found"
                        self.send_response(404)
                else:
                    message = "Error: Missing parameters. Use index or rule attributes (type, host, port, priority)"
                    self.send_response(400)
                    
                info_log(message)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(message.encode())
                return
            except Exception as e:
                message = f"Error removing rule: {str(e)}"
                self.send_response(400)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(message.encode())
                return
            
        # 默认路径返回帮助信息
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        help_text = (
            "Proxy Control API:\n"
            "/filter?seconds=X - Filter packets according to rules for X seconds (0 for permanent)\n"
            "/resume - Resume normal proxy operation\n"
            "/status - Show current proxy status and active filter rules\n"
            "/rules - List all filter rules\n"
            "/add_rule?type=deny|allow&host=PATTERN&port=PORT&priority=PRIORITY - Add a new filter rule\n"
            "/remove_rule?index=INDEX - Remove rule by index\n"
            "/remove_rule?type=TYPE&host=PATTERN&port=PORT&priority=PRIORITY - Remove rules matching attributes\n"
        )
        self.wfile.write(help_text.encode())
        
    def log_message(self, format, *args):
        # 使用自定义日志格式
        debug_log(f"RPC: {self.client_address[0]} - {format % args}")

# 启动RPC服务器
def start_rpc_server():
    try:
        rpc_server = socketserver.ThreadingTCPServer((RPC_HOST, RPC_PORT), RPCHandler)
        info_log(f"RPC server started on {RPC_HOST}:{RPC_PORT}")
        rpc_server.serve_forever()
    except Exception as e:
        info_log(f"Error starting RPC server: {e}")

def main():
    server_socket = None
    load_config()  # 加载配置文件
    
    # 添加信号处理
    def handle_sigterm(signum, frame):
        info_log("Received SIGTERM signal. Server is shutting down...")
        if server_socket is not None:
            server_socket.close()
        os._exit(0)
    
    # 注册SIGTERM信号处理程序
    signal.signal(signal.SIGTERM, handle_sigterm)
    
    try:
        # 启动RPC服务器线程
        rpc_thread = threading.Thread(target=start_rpc_server)
        rpc_thread.daemon = True
        rpc_thread.start()
        
        # 创建服务器套接字
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((PROXY_HOST, PROXY_PORT))
        server_socket.listen(MAX_CONNECTIONS)
        
        info_log(f"Proxy server started on {PROXY_HOST}:{PROXY_PORT}")
        
        # 接受并处理客户端连接
        while True:
            client_socket, address = server_socket.accept()
            
            # 为每个客户端创建一个新线程
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        info_log("Server is shutting down...")
    except Exception:
        pass
    finally:
        if server_socket is not None:
            server_socket.close()

if __name__ == "__main__":
    main()
