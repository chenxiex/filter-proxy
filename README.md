# HTTP/HTTPS过滤代理

这是一个功能强大的HTTP/HTTPS代理服务器，具有灵活的过滤功能，可以根据规则选择性地丢弃或允许特定请求。

## 功能特点

- 支持HTTP和HTTPS协议代理
- 灵活的过滤规则系统，基于主机名匹配和端口
- 通过REST API实时控制代理行为
- 支持基于正则表达式的主机名匹配
- 可配置的临时或永久过滤
- 从配置文件加载默认规则
- 防止回环请求（避免代理自身循环）

## 安装与运行

### 前置条件

- Python 3

在 Python 3.12 上测试通过。

### 快速开始

1. 克隆仓库：
   ```
   git clone https://github.com/yourusername/filter-proxy.git
   cd filter-proxy
   ```

2. 创建配置文件（可选）：
   参考`config.json.example`，创建`config.json`文件，配置代理和过滤规则。如果不存在，将使用默认配置。

3. 运行代理服务器：
   ```
   python server.py
   ```

4. 设置环境变量（可选）：
   ```
   # 启用调试输出
   DEBUG=true python3 server.py
   
   # 指定不同的配置文件
   CONFIG_FILE=custom_config.json python3 server.py
   ```

## 过滤规则说明

每条规则包含以下属性：

- `type`: 规则类型，可以是 `"allow"` 或 `"deny"`
- `host_pattern`: 主机名匹配模式，使用正则表达式
- `port`: 端口号，0表示匹配所有端口
- `priority`: 优先级，数字越大优先级越高
- `description`: 规则描述（可选）

规则匹配时会按优先级降序排列，第一条匹配的规则决定了请求是被允许还是丢弃。

## API接口

代理服务器提供以下HTTP API用于控制和监控：

### 启用过滤功能
```
GET /filter?seconds=X
```
启用过滤功能，持续X秒（0表示永久）

### 恢复正常代理
```
GET /resume
```
停止过滤，恢复正常代理操作

### 查看当前状态
```
GET /status
```
显示当前代理状态和活动的过滤规则

### 查看所有规则
```
GET /rules
```
列出所有当前的过滤规则

### 添加规则
```
GET /add_rule?type=deny|allow&host=PATTERN&port=PORT&priority=PRIORITY
```
添加一条新的过滤规则

### 按索引删除规则
```
GET /remove_rule?index=INDEX
```
按索引号删除规则

### 按属性删除规则
```
GET /remove_rule?type=TYPE&host=PATTERN&port=PORT&priority=PRIORITY
```
删除所有匹配指定属性的规则

## 使用示例

### 设置浏览器代理

将浏览器代理设置为：
- 主机：127.0.0.1
- 端口：22223

### 控制代理行为

1. 启动30秒的过滤模式：
   ```
   curl http://localhost:22224/filter?seconds=30
   ```

2. 添加规则允许访问Google：
   ```
   curl "http://localhost:22224/add_rule?type=allow&host=.*\.google\.com&port=0&priority=50"
   ```

3. 阻止访问Facebook：
   ```
   curl "http://localhost:22224/add_rule?type=deny&host=.*\.facebook\.com&port=0&priority=60"
   ```

4. 查看当前规则：
   ```
   curl http://localhost:22224/rules
   ```

5. 恢复正常代理：
   ```
   curl http://localhost:22224/resume
   ```

## 注意事项

- 建议允许访问RPC端口（默认22224），否则在启用过滤后将无法控制代理
- 小心使用高优先级的deny规则，它们可能会意外阻止重要连接
- 在生产环境中，建议设置RPC服务器的访问控制，以防止未授权访问
