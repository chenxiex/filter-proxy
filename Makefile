.PHONY = install-all-packages run-test clean

CERTIFICATE_FILE = test/test.crt test/test.key

install-all-packages:
	@echo "Installing all packages..."
	@pip install -r requirements.txt
	@pip install -r test/requirements.txt

$(CERTIFICATE_FILE):
	@echo "Generating test certificate..."
	@yes "" | openssl req -newkey rsa:2048 -nodes -keyout test/test.key -x509 -days 365 -out test/test.crt > /dev/null 2>&1
	@echo "Test certificate generated"

run-test: $(CERTIFICATE_FILE)
	@echo "Running tests..."
	- @CONFIG_FILE=test/config.json DEBUG=true python server.py > server.log 2>&1 & echo $$! > server.pid
	- @python test/simple_http_server.py > simple_http_server.log 2>&1 & echo $$! > simple_http_server.pid
	@sleep 5  # 等待服务器启动
	- @python test/test.py; echo $$? > test_exit_code.tmp
	@echo "Stopping servers..."
	- @kill `cat server.pid` && rm server.pid
	- @kill `cat simple_http_server.pid` && rm simple_http_server.pid
	@echo "Test completed"
	@EXIT_CODE=`cat test_exit_code.tmp`; rm test_exit_code.tmp; exit $$EXIT_CODE

clean:
	@echo "Cleaning up..."
	@rm -f server.log simple_http_server.log
	@rm -f $(CERTIFICATE_FILE)
	@rm -f server.pid simple_http_server.pid
	@echo "Cleaned up"