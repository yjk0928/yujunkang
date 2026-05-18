# pikachu
## CSRF
### CSRF(get)
点击一下旁边的那个点击一下提示
![alt text](image-380.png)
然后就看到了一下账号密码
在修改信息那里将性别修改为girl，打开bp抓包然后点击submit
![alt text](image-381.png)

`
?sex=girl&phonenum=15988767673&add=nba+lakes&email=kobe%40pikachu.com&submit=submit
`
对这一行参数改动就可以修改kobe的信息，比如我把手机号修改为12333
```payload
?sex=girl&phonenum=12333&add=nba+lakes&email=kobe%40pikachu.com&submit=submit
```
![alt text](image-382.png)

### CSRF(post)
还是登入上kobe的账号抓包
![alt text](image-385.png)
这里是post传参
用bp生成poc
![alt text](image-386.png)
![alt text](image-387.png)
稍加修改一下
![alt text](image-388.png)
然后在登入了kobe的情况下访问，结果没用
打开看了一下源码
```php
if(isset($_POST['submit'])){          // ① 外层：检查 POST
    if($_GET['sex']!=null && ...){    // ② 内层：检查 GET  ← BUG！应该是 $_POST
        $getdata=escape($link, $_POST); // ③ 实际用 POST 数据更新
```
这里源码显示的还是要用get方法带上参数，在post中修改
![alt text](image-389.png)
然后访问
![alt text](image-390.png)
再点击之后信息就被修改了
![alt text](image-391.png)

### CSRF(token)
打开kobe的账号抓包，在csrf token tracker里可以看到token
![alt text](image-392.png)
然后在重发器里修改信息，比如修改性别为girl
![alt text](image-393.png)