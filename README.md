# reqlog
```
REQLog是一款DNS和HTTP请求日志记录的工具
WEB: Flask
DB: SQLite3
```
### 安装第三方包
```
pip install flask
pip install dnslib
```

### 配置
```
修改config.py
# 主域名
DOMAIN = 'log.app'
# 面板域名
ADMIN_DOMAIN = 'www.log.app'
DOMAIN_COUNT = DOMAIN.count('.')
# 服务器IP
SERVER_IP = '127.0.0.1'
# 解析服务器IP
NAMESERVER_IP = '127.0.0.1'
# 数据库文件
DATABASE = './test.db'

一般服务器IP和NAMESERVER IP设置为一样 
```

### 启动
```
python web.py
python dnslog.py
```