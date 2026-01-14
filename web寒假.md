# web--寒假

## [HNCTF 2022 Week1]easy_upload
>题目url:https://www.nssctf.cn/problem/2901
>知识点：文件上传

直接上传一个一句话木马然后直接连接
![alt text](image-232.png)


## [SWPUCTF 2022 新生赛]ez_rce
>url:https://www.nssctf.cn/problem/2826
>RCE

打开什么东西都没有，有dirsearch扫一下
![alt text](image-233.png)

看到有一个flag.php,但是访问不了
那就访问一下/.gitignore
![alt text](image-234.png)
没有东西，然后再看一下robots.txt
![alt text](image-235.png)
访问一下这个目录
