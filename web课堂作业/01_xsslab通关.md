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
![alt text](image-8.png)
直接单引号没用
![alt text](image-9.png)
看源码这里< >被html实体化了，所以换一种方式
onfocus 是 HTML 原生事件属性，当标签获得焦点（被点击 / 选中）时，执行后面的代码
`' onfocus=javascript:alert(/xss/) '`
![alt text](image-10.png)

### 第四关
看源码这里还是先试一下闭合双引号
![alt text](image-11.png)
![alt text](image-12.png)
看源码这里还是>被过滤了，还是和上一题一样用onfocus事件属性，只不过改成双引号
`" onfocus=javascript:alert(/xss/) "`
![alt text](image-13.png)

### 第五关
![alt text](image-14.png)
还是直接看源码，先将双引号给闭合掉再输入js代码
![alt text](image-15.png)
结果果然是没用的
![alt text](image-16.png)
这里估计是把script用空代替了，试一下双写绕过
![alt text](image-17.png)
还是没用，换一种标签
`"><a href=javascript:alert(/xss/)>a-alert</a><"`
![alt text](image-18.png)

### 第六关
看源码这里是要先把双引号给闭合掉，再输入js代码
直接输入js代码没用，先试一下双写绕过可不可以
![alt text](image-19.png)
没用，再试一下大小写绕过
`"/><ScRipt>alert('xss')</ScriPt>`
![alt text](image-20.png)s