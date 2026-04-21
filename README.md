# 项目说明文档

## 1. 项目是否完成

当前项目已经完成，并且已经做过本地联调验证，结果如下：

- 已成功抓取 10 个满足条件的 HTTP 响应包
- 已完成 HTTP 响应筛选：`tcp src port 80`
- 已完成 `Content-Type` 白名单过滤：
  - `image/png`
  - `text/plain`
- 已解析并存储以下字段：
  - 源 IP
  - 目的 IP
  - 源端口
  - 目的端口
  - Content-Type
  - Payload 长度
- 已将原始载荷和解析信息写入单文件 `data/payload.log`
- 已写入 MySQL 两张表：`feature`、`payload`
- 已完成 Web 展示
- Web 层现已切换为真正的 Laminas MVC（Zend Framework II 后继框架）运行方式，并使用 Adapter + TableGateway 风格访问数据库

已验证通过的结果：
- 数据库中 `feature = 10`
- 数据库中 `payload = 10`
- 页面可展示 10 条记录和 10 段载荷内容

---

## 2. 项目目录结构

```text
sniffex/
├── data/
│   └── payload.log                  # 统一保存载荷与解析信息
├── Makefile                         # C 程序编译入口
├── myprompt.md                      # 原始需求与设计文档
├── schema.sql                       # MySQL 建表脚本
├── sniffex                          # 编译后的抓包程序
├── sniffex.c                        # libpcap 抓包与写库主程序
└── web/
    ├── composer.json                # Laminas 依赖配置
    ├── composer.lock
    ├── vendor/                      # Composer 安装的依赖
    ├── config/
    │   ├── application.config.php   # Laminas 应用入口配置
    │   └── autoload/
    │       ├── global.php           # 全局数据库配置
    │       └── local.php            # 本地密码等私有配置
    ├── module/
    │   ├── Application/
    │   │   └── view/
    │   │       ├── error/
    │   │       └── layout/
    │   └── Packet/
    │       ├── Module.php
    │       ├── config/module.config.php
    │       ├── src/Packet/
    │       │   ├── Controller/IndexController.php
    │       │   ├── Model/FeatureTable.php
    │       │   ├── Model/FeatureTableGateway.php
    │       │   ├── Model/PayloadTable.php
    │       │   ├── Model/PayloadTableGateway.php
    │       │   └── Service/PayloadReader.php
    │       └── view/packet/index/index.phtml
    └── public/
        └── index.php                # Web 入口
```

---

## 3. 整体工作流程

整个系统的数据流如下：

```text
HTTP 响应
   ↓
sniffex.c 抓包
   ↓
解析 IP/TCP/HTTP 头
   ↓
筛选 Content-Type
   ↓
写入 MySQL(feature/payload)
   ↓
写入 data/payload.log
   ↓
Laminas MVC 读取数据库与 payload.log
   ↓
页面展示
```

---

## 4. C 端代码阅读顺序

建议按下面顺序阅读 [sniffex.c](sniffex.c)：

### 4.1 程序入口
看 [sniffex.c](sniffex.c) 中的 `main()`：
- 选择网卡
- 连接数据库
- 打开 `data/payload.log`
- 设置 BPF 过滤器：`tcp src port 80`
- 调用 `pcap_loop()` 持续抓包

### 4.2 核心抓包回调
看 `got_packet()`：
- 每当抓到一个 TCP 包时执行
- 判断是否是符合条件的 HTTP 响应
- 如果符合：
  1. 插入 `feature`
  2. 写 `payload.log`
  3. 插入 `payload`
- 合格包数到 10 时调用 `pcap_breakloop()` 停止

### 4.3 HTTP 解析逻辑
重点看：
- `parse_packet_record()`
- `extract_content_type()`
- `is_allowed_content_type()`

这几部分负责：
- 校验 IP/TCP 头长度
- 提取 payload
- 判断是否为 `HTTP/1.` 响应
- 提取 `Content-Type`
- 做白名单过滤

### 4.4 文件写入逻辑
看：
- `append_payload_block()`
- `rewind_payload_log()`

作用：
- 将每条报文写成一个完整分块
- 记录文件偏移 `file_offset`
- 如果数据库写失败，可回滚文件尾部内容

### 4.5 MySQL 写入逻辑
看：
- `open_database()`
- `insert_feature()`
- `insert_payload()`

作用：
- 建立 MySQL 连接
- 先写特征表，再写载荷索引表
- 使用事务保证数据库和文件尽量一致

---

## 5. 数据库设计说明

数据库脚本在 [schema.sql](schema.sql)。

### 5.1 feature 表
保存结构化特征：
- `id`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `content_type`
- `payload_size`

### 5.2 payload 表
保存载荷索引：
- `id`
- `file_path`
- `file_offset`
- `data_type`
- `feature_id`

设计思路：
- 真正的载荷不进数据库
- 数据库只存元信息和文件定位信息
- 页面展示时按 `file_path + file_offset` 反查 `payload.log`

---

## 6. Web 层代码阅读顺序

### 6.1 应用入口
先看 [web/public/index.php](web/public/index.php)：
- 加载 Composer 自动加载
- 读取 Laminas 配置
- 启动 `Laminas\Mvc\Application`

### 6.2 模块配置
看 [web/module/Packet/config/module.config.php](web/module/Packet/config/module.config.php)：
- 定义路由 `/`
- 注册控制器工厂
- 注册 Adapter / TableGateway / Service
- 配置视图模板

### 6.3 控制器
看 [web/module/Packet/src/Packet/Controller/IndexController.php](web/module/Packet/src/Packet/Controller/IndexController.php)：
- 调用 `FeatureTable` 取全部记录
- 调用 `PayloadReader` 读取对应载荷
- 将数据传给视图

### 6.4 数据访问层
重点看：
- [web/module/Packet/src/Packet/Model/FeatureTable.php](web/module/Packet/src/Packet/Model/FeatureTable.php)
- [web/module/Packet/src/Packet/Model/FeatureTableGateway.php](web/module/Packet/src/Packet/Model/FeatureTableGateway.php)
- [web/module/Packet/src/Packet/Model/PayloadTable.php](web/module/Packet/src/Packet/Model/PayloadTable.php)
- [web/module/Packet/src/Packet/Model/PayloadTableGateway.php](web/module/Packet/src/Packet/Model/PayloadTableGateway.php)

其中：
- `FeatureTableGateway` / `PayloadTableGateway` 是 TableGateway 封装
- `FeatureTable` 用 Laminas Db SQL 拼接 `feature + payload` 联表查询

### 6.5 载荷读取服务
看 [web/module/Packet/src/Packet/Service/PayloadReader.php](web/module/Packet/src/Packet/Service/PayloadReader.php)：
- 通过 `file_offset` 定位到 `payload.log` 对应块
- 读取直到 `=== End Packet N ===`

### 6.6 页面模板
看 [web/module/Packet/view/packet/index/index.phtml](web/module/Packet/view/packet/index/index.phtml)：
- 上半部分展示特征表格
- 下半部分展示每条记录对应的载荷块

---

## 7. 运行步骤

### 7.1 初始化数据库
在项目根目录执行：

```bash
mysql -u root -p < schema.sql
```

---

### 7.2 编译抓包程序
在项目根目录执行：

```bash
make
```

生成可执行文件：
- `./sniffex`

---

### 7.3 准备本地 HTTP 测试文件
如果你继续使用环回网卡 `lo`，可先准备一个纯文本文件：

```bash
echo 'loopback capture test' | sudo tee /var/www/html/sniffex-test.txt
curl -I http://127.0.0.1/sniffex-test.txt
```

预期响应头中应该看到：

```text
Content-Type: text/plain
```

---

### 7.4 启动抓包
因为抓包通常需要更高权限，执行：

```bash
sudo ./sniffex lo
```

如果想指定其他网卡，例如 `ens33`：

```bash
sudo ./sniffex ens33
```

---

### 7.5 制造 10 次 HTTP 响应
另开一个终端执行：

```bash
for i in $(seq 1 5); do curl -s http://127.0.0.1/sniffex-test.txt >/dev/null; done
for i in $(seq 1 5); do curl -s http://127.0.0.1/test.png >/dev/null; done
```

程序在成功抓到 10 个合格包后会自动停止。

---

### 7.6 检查数据库结果
```bash
mysql -h 127.0.0.1 -u root -p123456 -e "USE packet_capture; SELECT COUNT(*) AS feature_count FROM feature; SELECT COUNT(*) AS payload_count FROM payload;"
```

预期：
- `feature_count = 10`
- `payload_count = 10`

查看具体数据：

```bash
mysql -h 127.0.0.1 -u root -p123456 -e "USE packet_capture; SELECT f.id, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.content_type, f.payload_size, p.file_offset FROM feature f JOIN payload p ON p.feature_id = f.id ORDER BY f.id;"
```

---

### 7.7 检查 payload 文件
```bash
ls -l data/payload.log
head -40 data/payload.log
```

你应该能看到类似：
- `=== Packet 1 ===`
- `Content-Type: text/plain`
- `--- RAW DATA ---`
- `--- PARSED INFO ---`

---

### 7.8 启动 Web 页面
进入 `web/` 目录后启动 PHP 内置服务器：

```bash
cd web
php -S 127.0.0.1:8081 -t public
```

浏览器访问：

```text
http://127.0.0.1:8081/
```

如果数据库密码不是默认值，需要修改：
- [web/config/autoload/local.php](web/config/autoload/local.php)

---

## 8. 关键配置说明

### 8.1 C 程序数据库默认配置
在 [sniffex.c](sniffex.c) 中：
- `DEFAULT_DB_HOST`
- `DEFAULT_DB_USER`
- `DEFAULT_DB_PASS`
- `DEFAULT_DB_NAME`

也支持环境变量覆盖：
- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASS`
- `DB_NAME`

例如：

```bash
DB_USER=root DB_PASS=123456 sudo ./sniffex lo
```

### 8.2 Web 数据库配置
Web 层配置在：
- [web/config/autoload/global.php](web/config/autoload/global.php)
- [web/config/autoload/local.php](web/config/autoload/local.php)

建议：
- 通用配置写 `global.php`
- 密码写 `local.php`

---

## 9. 已完成的实际验证

本项目已经完成以下真实验证：

1. 在 `lo` 网卡抓取本地 HTTP 响应
2. 成功抓到 10 个 `text/plain` 响应
3. 成功写入 MySQL：10 条 `feature`、10 条 `payload`
4. 成功写入 `data/payload.log`
5. 成功通过 Web 页面展示 10 条记录和对应载荷
6. 已将 Web 层切换到 Laminas MVC 启动方式

---

## 10. 当前实现与作业要求的对应关系

### 已满足
- 抓取 10 个 HTTP 响应包
- 过滤 `tcp src port 80`
- 只处理包含 `Content-Type` 且类型在白名单内的响应
- 解析网络层和传输层字段
- 解析 `Content-Type` 与 `payload length`
- 所有载荷写入同一个文件
- 数据库存储结构化字段和文件索引
- MVC 展示全部数据
- 使用 Adapter / TableGateway 风格访问数据库
- Web 页面可以展示载荷内容

### 当前说明
- Web 层使用的是 Laminas MVC。它是 Zend Framework 的后继项目，结构、用法和组件体系是一脉相承的。
- 在现代 PHP 环境下，比直接安装旧版 Zend Framework II 更容易落地和运行。

---

## 11. 你阅读代码的建议顺序

建议按这个顺序看：

1. [myprompt.md](myprompt.md)
2. [schema.sql](schema.sql)
3. [sniffex.c](sniffex.c)
4. [web/public/index.php](web/public/index.php)
5. [web/module/Packet/config/module.config.php](web/module/Packet/config/module.config.php)
6. [web/module/Packet/src/Packet/Controller/IndexController.php](web/module/Packet/src/Packet/Controller/IndexController.php)
7. [web/module/Packet/src/Packet/Model/FeatureTable.php](web/module/Packet/src/Packet/Model/FeatureTable.php)
8. [web/module/Packet/src/Packet/Service/PayloadReader.php](web/module/Packet/src/Packet/Service/PayloadReader.php)
9. [web/module/Packet/view/packet/index/index.phtml](web/module/Packet/view/packet/index/index.phtml)

这样最容易建立“抓包 -> 入库 -> 读文件 -> 页面展示”的完整理解。
