# 一、Prompt

## 项目目标

实现一个基于数据包捕获与解析的网络管理系统，完成从**数据采集 → 数据解析 → 数据存储 → Web 展示（MVC）**的完整流程。

---

## 一、数据采集（sniffex.c 修改）

### 1. 捕获要求

在 Ubuntu 虚拟机中修改 `sniffex.c`，实现以下功能：

* 捕获 **10 个 HTTP 响应报文**
* 过滤条件：

  * `tcp src port 80`
* 抓包协议层次：

  * IP 层
  * TCP 层

---

### 2. 报文筛选规则

仅处理满足以下条件的 HTTP 响应报文：

* 必须包含 `Content-Type`
* 且属于以下类型之一：

  * `image/png`
  * `image/gif`
  * `text/plain`

---

### 3. 报文解析内容

对每个符合条件的报文，提取以下字段：

#### （1）网络层 / 传输层信息

* 源 IP
* 目的 IP
* 源端口
* 目的端口

#### （2）应用层信息

* Content-Type
* 载荷大小（payload length）

---

### 4. 载荷处理

* 所有报文载荷统一写入 **一个文件**
* 对于每个报文，文件中必须包含：

  1. 原始载荷（Raw Data）
  2. 解析后的结构信息（如 Content-Type、长度等）

建议格式（示例）：

```
=== Packet 1 ===
Source IP: xxx
Dest IP: xxx
Content-Type: image/png
Payload Length: xxx

--- RAW DATA ---
(binary / hex)

--- PARSED INFO ---
...
```

---

## 二、数据存储（MySQL）

### 1. 数据库要求

使用 MySQL 存储解析结果。

### 2. 数据表设计（可在 schema.sql 基础上优化）

建议至少包含：

#### 表1：packet_info（报文特征表）

* id（主键）
* src_ip
* dst_ip
* src_port
* dst_port
* content_type
* payload_size

#### 表2：payload_info（载荷索引表）

* id（主键）
* packet_id（外键）
* file_offset（在文件中的位置或标识）

> 注意：实际载荷不存数据库，只存文件路径或偏移

---

## 三、Web 系统（Zend Framework II + MVC）

### 1. 技术要求

* 使用 Zend Framework II
* 实现 MVC 架构
* 必须包含：

  * Adapter（数据库连接）
  * ORM 或 TableGateway 数据访问

---

### 2. 页面功能

实现一个页面，展示所有数据：

#### 页面内容：

* 报文特征值（表格展示）：

  * 源IP
  * 目的IP
  * 源端口
  * 目的端口
  * Content-Type
  * Payload大小

* 同时展示：

  * 对应载荷内容（从文件读取）

---

### 3. 页面要求

* 单页面展示所有数据
* 不需要分页 / 搜索
* 可选：点击查看某条报文的详细载荷

---

## 四、整体流程

1. 抓包（sniffex.c）
2. 筛选 HTTP 响应
3. 解析字段
4. 写入：

   * MySQL（结构数据）
   * 文件（载荷数据）
5. Web 展示（ZF2）

---

# 二、设计文档

## 1. 系统总体设计

本系统分为三个模块：

1. 数据采集模块（Packet Capture）
2. 数据处理与存储模块（Parser + DB）
3. Web 展示模块（MVC）

系统架构如下：

```
sniffex.c → 数据解析 → MySQL + 文件 → Zend Framework II → 页面展示
```

---

## 2. 数据采集模块设计

### 2.1 抓包机制

基于 libpcap，对网络接口进行监听，设置过滤规则：

```
tcp src port 80
```

用于捕获 HTTP 响应报文。

---

### 2.2 报文解析流程

每个数据包按以下顺序解析：

1. 解析 IP 头 → 获取源/目的 IP
2. 解析 TCP 头 → 获取端口
3. 定位 HTTP Payload
4. 判断是否为 HTTP 响应：

   * 检查是否包含 `HTTP/1.1`
5. 提取 Content-Type
6. 判断是否属于目标类型（png/gif/text）

---

## 3. 数据存储设计

### 3.1 数据库存储策略

采用“结构化数据 + 文件存储”方式：

* 数据库存储：索引 + 元信息
* 文件存储：真实载荷

优点：

* 避免数据库存储大对象（BLOB）
* 提高查询效率

---

### 3.2 表结构设计

#### packet_info 表

| 字段           | 含义   |
| ------------ | ---- |
| id           | 主键   |
| src_ip       | 源IP  |
| dst_ip       | 目的IP |
| src_port     | 源端口  |
| dst_port     | 目的端口 |
| content_type | 内容类型 |
| payload_size | 载荷大小 |

---

#### payload_info 表

| 字段          | 含义      |
| ----------- | ------- |
| id          | 主键      |
| packet_id   | 外键      |
| file_offset | 文件偏移或标识 |

---

### 3.3 文件设计

采用单文件存储：

* 文件名：`payload.log`
* 内容按报文分块组织
* 每块包含：

  * 报文编号
  * 特征信息
  * 原始载荷

---

## 4. Web 模块设计（ZF2）

### 4.1 MVC 结构

* Model：

  * TableGateway 或 ORM
* View：

  * 展示数据表 + 载荷内容
* Controller：

  * 查询数据库
  * 读取文件内容

---

### 4.2 数据访问

使用 Zend DB Adapter：

* 配置 MySQL 连接
* 查询 packet_info
* 关联 payload_info

---

### 4.3 页面设计

页面分为两部分：

#### 上半部分：特征值表格

* 每行对应一个报文

#### 下半部分：载荷内容

* 展示文件中对应数据

---

## 5. 关键设计点

### 5.1 HTTP 解析难点

* TCP 可能分片（本实验可忽略复杂重组）
* 简化为：

  * 直接在 payload 中查找 Content-Type

---

### 5.2 数据一致性

* packet_info.id ↔ payload_info.packet_id

---

### 5.3 性能考虑

* 仅捕获 10 个包，性能不是重点
* 优先保证正确性

---

## 6. 可扩展性（可写在报告加分）

* 支持更多 Content-Type
* 支持 HTTPS（需解密）
* 增加分页 / 搜索
* 多文件存储

---

