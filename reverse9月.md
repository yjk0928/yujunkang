## [NSSRound#3 Team]jump_by_jump
>题目url：https://www.nssctf.cn/problem/2313

下载好插件之后查壳
![alt text](image-31.png)
无壳，且是32伟，丢进idea
![alt text](image-32.png)
shift+F12，找到一个flag
直接就提交成功了，不知道和花指令有什么关系
下面用花指令的方法解一下
找到标红的一段代码
![alt text](image-33.png)，注意有jz和jnz，这就是有关花指令
找到loc_41188c函数，按u，变成一个函数
![alt text](image-34.png)
把这个新生成的函数全选出来再按c，选择分析
![alt text](image-35.png)
再调用插件将0e8h给nop掉
![alt text](image-36.png)
变成1这样就是已经nop了，在按c变回汇编语言
![alt text](image-37.png)
再fn+f5查看伪代码
这样就可以找到flag

## [LitCTF 2023]ez_XOR
> url:https://www.nssctf.cn/problem/3860

先查壳
![alt text](image-38.png)
无壳，32位，丢进idea
发现两串可疑字符串
![alt text](image-39.png)
跟进去
![alt text](image-40.png)
查看伪代码
没看出什么东西，直接看main函数吧
![alt text](image-41.png)
main函数里面
`
XOR(&Str1, 3);
`
这一句就是异或运算，将flag的asci码与3进行异或运算
#include <stdio.h>
#include <string.h>

```c
int main()
{
    int a2 = 3;
    char str2[] = "E`}J]OrQF[V8zV:hzpV}fVF[t";
    int l, i, result;
    l = strlen(str2);
    for (i = 0; ; ++i)
    {
        result = l;
        if (i >= result)
            break;
        str2[i] ^= 3 * a2;
    }
    puts(str2);

    return 0;
}

```
得到falg