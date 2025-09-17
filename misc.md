# misc
## [陇剑杯 2021]webshell（问1）
>题目url：https://www.nssctf.cn/problem/278

打开题目下载好压缩包直接放进wireshark
Ctrl+F搜索passwaord
![alt text](image.png)
得到username=test
    passward=Admin123!@#
密码就是flag
## [陇剑杯 2021]jwt（问1）
> 题目url：https://www.nssctf.cn/problem/272

注意题目所问：
```
昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：
该网站使用了______认证方式。（如有字母请全部使用小写）。得到的flag请使用NSSCTF{}格式提交。
```

下载好插件直接放在wieershak

Token是服务端生成的一串字符串，以客户端进行请求的一个令牌，当第一次登录后，服务器生成一个Token便将此Token返回给客户端，以后客户端只需要带上这个Token青睐请求数据即可，无需再次带上用户名和密码

Ctrl+f搜索token，然后显示分组字节流，是一段bsae64代码
![alt text](image-1.png)
解码之后，说明使用的认证方式为jwt
所以提交的flag为NSSCTF{jwt}


## [陇剑杯 2021]jwt（问2）
>题目url：https://www.nssctf.cn/problem/273


问题：
```
黑客绕过验证使用的jwt中，id和username是______。（中间使用#号隔开，例如1#admin）。得到的flag请使用NSSCTF{}格式提交。
```

在上面的解码里已经知道了
```
{"alg":"HS256","typ":"JWT"}{"id":10086,"MapClaims":{"aud":"admin","username":"admin"}}
```
这样直接提交是错的
使用命令
```
http contains "whoami"
```
![alt text](image-2.png)
在post请求那一栏显示分组字节流
![](image-4.png)
就可以得到flag


## [陇剑杯 2021]jwt（问3）
>题目url：https://www.nssctf.cn/problem/274

问题：
```
单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：
黑客获取webshell之后，权限是______？
```
同样输入命令 
`
http contains whoami
`
然后追踪tcp流，可以看到alert：root
![alt text](image-5.png)
即权限为root

## [陇剑杯 2021]jwt（问4）
>题目url：https://www.nssctf.cn/problem/275

可以直接找到有一个1.c的文件交上去就是答案

## [SWPU 2019]神奇的二维码
>https://www.nssctf.cn/problem/39

下载好图片之后放进QR检查一下
![alt text](image-6.png)
类似有个flag，但不正确
拖到kail里面用binwalk找到四个压缩包
![alt text](image-7.png)
-e将其分离出来
分离后拖出来
![alt text](image-8.png)
在18394.rar里找到一个音频
所以想办法解压这个压缩包
先看一下encode.txt这个文件
![alt text](image-9.png)
在线解码一下
![alt text](image-10.png)
这个是没用的密码，用来解压新出来的一张图片的
在看一下flag.doc，打开是一段超长的base64代码
在在线解码网站里解码了20次得到
![alt text](image-11.png)
估计这就是密码
`
comEON_YOuAreSOSoS0great
`
把密码输进去解压成功了
![alt text](image-12.png)
然后把音频放入audisity
![alt text](image-13.png)
看别人的wp说这是一段摩斯密码
将音频的粗细用- .代替后就是摩斯密码
`
-- --- .-. ... . .. ... ...- . .-. -.-- ...- . .-. -.-- . .- ... -.--
`

然后去解码
![alt text](image-14.png)
这就是flag，提交的时候改为小写