# XSS_lab通关
## 部署
直接将下载的xsslab文件上传到服务器上，即可访问。
![alt text](image.png)

### 第一关
![alt text](image-1.png)
直在浏览器中输入`<script>alert('jk')</script>`，即可触发xss攻击,参数是name。

### 第二关
![alt text](image-2.png)
这里直接输入js代码没用
![alt text](image-3.png)
看一下源码
![alt text](image-4.png)
看源码这里，需要先将引号给闭合掉再输入js代码，这种情况下js代码被当作value属性的值，而不是可执行的代码
`"><script>alert('xss')</script><"`这样闭合就可以触发xss攻击
![alt text](image-5.png)

### 第三关
![alt text](image-7.png)
看源代码，这里需要单引号闭合

![alt text](image-6.png)


