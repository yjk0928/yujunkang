# 动态调试

## 1.当出现未调用的函数

### [BJDCTF 2020]Easy
>题目url：https://www.nssctf.cn/problem/702

查壳，无壳，32位
![alt text](image-77.png)
丢进ida
找到一个_ques函数未调用
![alt text](image-80.png)
这个时候基本是动态分析
方法一：在IDA中通过修改eip来使其跳转到ques函数
先记下ques的引用地址，此处为0x00401520
![alt text](image-81.png)
之后主主函数运行的途中随便下一个断点
![alt text](image-82.png)
选择调试器后进行动调，然后将对应的EIP修改成ques函数的地址即可：
![alt text](image-83.png)
将此处的eip修改为0x00401520
![alt text](image-84.png)
修改完之后继续进程
![alt text](image-85.png)
得到flag
![alt text](image-86.png)

