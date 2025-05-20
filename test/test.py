import unittest
import requests

PROXY_PORT = 22223
RPC_PORT = 22224
HTTP_PORT = 8080
HTTPS_PORT = 8443

proxies = {
            "http": f"http://localhost:{PROXY_PORT}",
            "https": f"http://localhost:{PROXY_PORT}",
        }

class proxy_act:
    def send_request(self, url:str, proxies:dict = {}) -> requests.Response:
        response = requests.get(url, proxies=proxies, verify=False, timeout=5)
        return response

class rpc_act:
    def add_rule(self, rule:dict) -> requests.Response:
        rpc_url = f"http://localhost:{RPC_PORT}/add_rule?type={rule['type']}&host={rule['host_pattern']}&port={rule['port']}&priority={rule['priority']}"
        response = requests.get(rpc_url)
        return response

    def remove_rule(self, rule:dict) -> requests.Response:
        rpc_url = f"http://localhost:{RPC_PORT}/remove_rule?type={rule['type']}&host={rule['host_pattern']}&port={rule['port']}&priority={rule['priority']}"
        response = requests.get(rpc_url)
        return response
    
    def active_filter(self, seconds:int) -> requests.Response:
        rpc_url = f"http://localhost:{RPC_PORT}/filter?seconds={seconds}"
        response = requests.get(rpc_url)
        return response
    
    def resume(self) -> requests.Response:
        rpc_url = f"http://localhost:{RPC_PORT}/resume"
        response = requests.get(rpc_url)
        return response

class TestProxy(unittest.TestCase):

    def test_http_proxy(self):
        # Test the proxy server
        http_url = f"http://localhost:{HTTP_PORT}"

        response = proxy_act().send_request(http_url, proxies)
        self.assertEqual(response.status_code, 200)
    
    def test_https_proxy(self):
        # Test the proxy server
        https_url = f"https://localhost:{HTTPS_PORT}"

        response = proxy_act().send_request(https_url, proxies)
        self.assertEqual(response.status_code, 200)
    
class TestRPC(unittest.TestCase):
    rule = {
            "type": "deny",
            "host_pattern": "example\.com", # type: ignore
            "port": 80,
            "priority": 10
    }

    def check_status(self, text:str=""):
        rpc_url = f"http://localhost:{RPC_PORT}/status"
        response = requests.get(rpc_url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(text, response.text)

    def check_rules(self, rule:dict = rule, exists:bool = True):
        rpc_url = f"http://localhost:{RPC_PORT}/rules"
        response = requests.get(rpc_url)
        self.assertEqual(response.status_code, 200)
        message = f"{rule['type'].upper()} - Pattern: {rule['host_pattern']}, "
        message += f"Port: {rule['port'] if rule['port'] != 0 else 'ALL'}, "
        message += f"Priority: {rule['priority']}\n"
        if exists:
            self.assertIn(message, response.text)
        else:
            self.assertNotIn(message, response.text)

    def test_rules(self):
        self.check_status()
    
    def test_filter(self):
        response = rpc_act().active_filter(10)
        self.assertEqual(response.status_code, 200)
        self.check_status("Filtering active")
    
    def test_resume(self):
        response = rpc_act().resume()
        self.assertEqual(response.status_code, 200)
        self.check_status("Normal operation. Packets are being forwarded.")
    
    def test_rules_list(self):
        rpc_url = f"http://localhost:{RPC_PORT}/rules"
        response = requests.get(rpc_url)
        self.assertEqual(response.status_code, 200)

    def test_add_rule(self):
        response = rpc_act().add_rule(self.rule)
        self.assertEqual(response.status_code, 200)
        self.check_rules(self.rule, True)
    
    def test_remove_rule(self):
        response = rpc_act().remove_rule(self.rule)
        self.assertEqual(response.status_code, 200)
        self.check_rules(self.rule, False)

class TestFilter(unittest.TestCase):
    def test_http_filter(self):
        rpc = rpc_act()
        rule1 = {
            "type": "deny",
            "host_pattern": "localhost",
            "port": HTTP_PORT,
            "priority": 20
        }
        rpc.add_rule(rule1)
        rule2 = {
            "type": "allow",
            "host_pattern": ".*",
            "port": 0,
            "priority": 10
        }
        rpc.add_rule(rule2)

        rpc.active_filter(60)

        http_url = f"http://localhost:{HTTP_PORT}"
        with self.assertRaises(requests.exceptions.RequestException):
            response = proxy_act().send_request(http_url, proxies)

        rpc.remove_rule(rule1)

        response = proxy_act().send_request(http_url, proxies)
        self.assertEqual(response.status_code, 200)

        rpc.remove_rule(rule2)
        rpc.resume()
    
    def test_https_filter(self):
        rpc = rpc_act()
        rule1 = {
            "type": "deny",
            "host_pattern": "localhost",
            "port": HTTPS_PORT,
            "priority": 20
        }
        rpc.add_rule(rule1)
        rule2 = {
            "type": "allow",
            "host_pattern": ".*",
            "port": 0,
            "priority": 10
        }
        rpc.add_rule(rule2)

        rpc.active_filter(60)

        https_url = f"https://localhost:{HTTPS_PORT}"
        with self.assertRaises(requests.exceptions.RequestException):
            response = proxy_act().send_request(https_url, proxies)

        rpc.remove_rule(rule1)

        response = proxy_act().send_request(https_url, proxies)
        self.assertEqual(response.status_code, 200)

        rpc.remove_rule(rule2)
        rpc.resume()

if __name__ == "__main__":
    unittest.main()