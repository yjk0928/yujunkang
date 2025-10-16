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

## 技巧二：获取进程内容数据
当发现题目中涉及到的程序内部值无法查看和获取时，可以通过动调获取内容数值。
### [HUBUCTF 2022 新生赛]help
> url:https://www.nssctf.cn/problem/2594

依旧先查壳，无壳,64位
![alt text](image-87.png)
放进ida
![alt text](image-88.png)
分析main函数
```c
  puts("I got lost in the maze,help me figure it out and I'll tell you a secret!");
  ```
  这句话提示需要解决迷宫问题
  这段代码的核心逻辑是：让用户输入一个长度为 54 的路径字符串，验证该路径是否能走出CreateMap()创建的迷宫（通过check函数）。若验证通过，flag 为该路径的 MD5 哈希值（格式NSSCTF{哈希值}）。用户需要找到满足条件的path才能得到 flag。
  ![alt text](image-95.png)
  正常找map找不到，基本就是动态分析
  给CreateMap函数下一个断点
  ![alt text](image-89.png)
  运行之后先随便输
  ![alt text](image-90.png)
然后按Tab回到伪代码
F7单步调试，进入CreateMap函数
![alt text](image-91.png)
再一直按F7单步调试，直到地图全部出现，自动跳到最开始的main函数页面，点OK

双击进入CreateMap函数，再双击map，再双击map

1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1,0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0,1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1,1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1,1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0,1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1,1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1,1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1



![alt text](image-92.png)
修改为16个一组
1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1,
1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 
1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 
1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1,
1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 
1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 
1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 
1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 
1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 
1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 
1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 
1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 
1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
![alt text](image-93.png)
根据check函数找到，路径
![alt text](2685364-20231015211207813-1154359728.png)
path：wwdddwwwaaawwwwwwwwwddddssssdddssdsssssssdddwwwwddsssd
md5加密
![alt text](image-94.png)

## 技巧三：匹配绕过
当发现有if判断比对时，可通过动调加载获取匹配值
### [HNCTF 2022 Week1]CrackMe
>url:https://www.nssctf.cn/problem/2908

题目的提示是：得到CreakMe的注册码，动态下断点
![alt text](image-96.png)
32位，无壳

在 ExitProcess(0); 处下断点的核心目的是捕获程序 “正常结束” 的关键节点，便于分析程序退出前的状态，尤其是在逆向工程或调试验证逻辑时非常有用。具体原因包括：

    确认程序是否进入 “成功路径”

从代码逻辑看，ExitProcess(0); 仅在 “序列号验证成功” 后被调用（if (lstrcmpA(String1, String2) == 0) 时）。在这里下断点，可直观判断程序是否通过了验证（若断点触发，说明验证成功）。
获取关键数据（如正确的序列号）
程序在退出前，内存中可能还保留着关键数据（例如代码中生成的正确序列号 String2）。在 ExitProcess 处中断后，可通过调试器查看内存或寄存器，直接获取这些数据（比如逆向时想得到 “正确的序列号”，这是常用技巧）。
分析退出前的资源状态
若程序在退出前有未完成的操作（如写入文件、释放资源等），断点可暂停进程，检查此时的资源状态（如句柄、内存分配情况），排查潜在的异常或逻辑问题。

![alt text](image-97.png)

![alt text](image-98.png)
输入之后，回到伪代码，双击string2，按r变为字符，提取出来就是flag
![alt text](image-99.png)
注意将大写字母改为小写

### [Week1] 8086ASM

下载插件得到一个8086.asm文件，放在kali里先转化为8086.o
![alt text](image-115.png)


## [BJDCTF 2020]JustRE
>url: https://www.nssctf.cn/problem/703

![alt text](image-116.png)
无壳，32位
![alt text](image-117.png)
查找字符串发现一个类似flag的字符串
找到对应伪代码
![alt text](image-118.png)
意思是点击19999下将字符串里的两个%d用19999，和0代替
所以得到flag

## [LitCTF 2023]enbase64
>url:https://www.nssctf.cn/problem/3846

![alt text](image-119.png)
无壳32位
main函数里找到提示
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[61]; // [esp+1Fh] [ebp-81Dh] BYREF
  char v5[4]; // [esp+5Ch] [ebp-7E0h] BYREF
  char v6[4]; // [esp+60h] [ebp-7DCh] BYREF
  char v7[996]; // [esp+64h] [ebp-7D8h] BYREF
  char Str[4]; // [esp+448h] [ebp-3F4h] BYREF
  char v9[996]; // [esp+44Ch] [ebp-3F0h] BYREF

  __main();
  *(_DWORD *)Str = 0;
  memset(v9, 0, sizeof(v9));
  *(_DWORD *)v6 = 0;
  memset(v7, 0, sizeof(v7));
  *(_DWORD *)v4 = *(_DWORD *)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  strcpy(v5, "9+/");
  qmemcpy(&v4[1], &aAbcdefghijklmn[-(v4 - &v4[1])], 4 * (((v4 - &v4[1] + 65) & 0xFFFFFFFC) >> 2));
  puts("Please input flag:");
  gets(Str);
  if ( strlen(Str) == 33 )
  {
    base64(v4, Str, v6);
    basecheck(v6);
  }
  return 0;
}
```

1. __*(_DWORD *)Str__ 
    就是 “把 Str 开头的 4 个字节当作一个 32 位整数 来访问”。这种写法在反编译代码中很常见，目的是高效操作连续的多字节内存。
    在上述代码中的运用
    *(_DWORD *)Str = 0;：将Str的前 4 字节清零（初始化输入缓冲区）。
    *(_DWORD *)v4 = *(_DWORD *)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"：
    将标准 Base64 编码表的前 4 个字符（"ABCD"）存入v4的前 4 字节。
2. __memset 函数:__
    原型：
    void *memset(void *ptr, int value, size_t num);
    功能是：
    将 ptr 指向的内存区域的前 num 个字节，全部设置为 value（取低 8 位，即一个字节的值）。
    在代码中的作用：
    这行代码会将 v9 数组的 全部 996 个字节 都设置为 0，相当于对数组进行 “清零初始化”。
3.  strcpy(v5, "9+/");：将字符串 "9+/" 复制到v5（可能是对编码的  补充或修改）。

4. __void qmemcpy(void *dest, const void *src, size_t n);__
    即从 src 指向的内存复制 n 个字节到 dest 指向的内存。
    在代码中的作用：
    qmemcpy(&v4[1], &aAbcdefghijklmn[-(v4 - &v4[1])], 4 * (((v4 - &v4[1] + 65) & 0xFFFFFFFC) >> 2));
    分析这三个参数：
    1. 目标地址：&v4[1]
    2. 源地址：&aAbcdefghijklmn[-(v4 - &v4[1])]
        先算 v4 - &v4[1]：v4 是数组首地址（&v4[0]），&v4[1] 是首地址 + 1（因为 v4 是 char 类型，每个元素占 1 字节）。
        因此 v4 - &v4[1] = &v4[0] - (&v4[0] + 1) = -1。
        再算 - (v4 - &v4[1])：
        即 -(-1) = 1。
        最终源地址：&aAbcdefghijklmn[1]
    3. 复制长度：4 * (((v4 - &v4[1] + 65) & 0xFFFFFFFC) >> 2)
        代入 v4 - &v4[1] = -1，先算括号内：-1 + 65 = 64
        64 & 0xFFFFFFFC：0xFFFFFFFC 是一个掩码（二进制最后两位为 0），作用是 “取 4 的整数倍”（因为 Base64 编码表长度是 64，正好是 4 的倍数）。64 & 0xFFFFFFFC 的结果还是 64。
        \>> 2转化为2进制再右移两位，相当于除以4，所以复制长度是4*16=64
5. __base64(v4, Str, v6);：__
    调用自定义的base64函数，使用v4作为编码表，对输入的Str（flag）进行 Base64 编码，结果存入v6
 这里变化前后v4没变化，明显不可能，所以在题目中要找到其他变化base表的代码
6. basecheck(v6);：调用basecheck函数验证编码后的结果v6是否符合预期（推测此函数会检查编码结果是否为预设的正确值，若正确则可能输出 "正确" 等信息）。

整体代码理解：这段代码是通过*(_DWORD *)Str和qmemcpy(&v4[1], &aAbcdefghijklmn[-(v4 - &v4[1])], 4 * (((v4 - &v4[1] + 65) & 0xFFFFFFFC) >> 2));得到一段新的base64码，用它和输入的flag进行base编码，将得到编码放入basecheck函数验证，点进该函数可以得到v6
![alt text](image-121.png)
修改一下在运alt text行得到新的编码
![alt text](image-124.png)
找到一个basechange函数是他变换了base编码

![alt text](image-120.png)

然后用base64换表脚本运行一下
![alt text](image-125.png)
得到falg

## [NISACTF 2022]string
>https://www.nssctf.cn/problem/2042
> 知识点：动态调试
![alt text](image-136.png)

```c
char *__fastcall flag(char *a1)
{
  char *v1; // rax
  char *v2; // rax
  char *v3; // rax
  int v4; // eax
  char *v6; // [rsp+8h] [rbp-38h]
  int i; // [rsp+1Ch] [rbp-24h]
  int j; // [rsp+20h] [rbp-20h]
  int k; // [rsp+20h] [rbp-20h]
  int v10; // [rsp+24h] [rbp-1Ch]
  int m; // [rsp+28h] [rbp-18h]
  int v12; // [rsp+2Ch] [rbp-14h]
  int v13; // [rsp+34h] [rbp-Ch]

  v6 = a1;
  v12 = (_DWORD)a1 + 1;
  if ( (_DWORD)a1 << 30 )
  {
    while ( 1 )
    {
      v1 = v6++;
      if ( !*v1 )
        break;
      if ( !((_DWORD)v6 << 30) )
        goto LABEL_4;
    }
  }
  else
  {
LABEL_4:
    for ( i = (int)v6; ((i - 16843009) & ~i & 0x80808080) == 0; i = v13 )
    {
      v13 = v6[1];
      v6 += 4;
    }
    v2 = v6++;
    for ( j = *v2; j; j = *v3 )
      v3 = v6++;
  }
  puts("This a magic!");
  v10 = (_DWORD)v6 - v12;
  for ( k = 0; (int)v6 - v12 > k; ++k )
    v10 ^= 0x1Au;
  if ( v10 != 13 )
  {
    puts("error!");
    exit(0);
  }
  puts("The length of flag is 13");
  srand(seed);
  printf("NSSCTF{");
  for ( m = 0; m < 13; ++m )
  {
    v4 = rand();
    printf("%d", (unsigned int)(v4 % 8 + 1));
  }
  putchar(125);
  return &v6[-v12];
}
```
这段代码中v4是flag里面的内容
可这里需要先知道flag的内容是不会变的
所以为了使内容不变，seed应该不变，所以要先找到seed
![alt text](image-137.png)
将seed改为10进制数
![alt text](image-138.png)
然后可以写代码了
```c
#include<stdio.h>
#include<stdlib.h>
int main() {
	printf("NSSCTF{");
	srand(10084);
	
	for (int i = 0; i < 13; i++) {
		int v4 = rand();
		printf("%d", (v4%8+1));

	}
	printf("}");
	return 0;
}
```
![alt text](image-140.png)
但是提交失败，看wp说要在linux下运行
得到flag
NSSCTF{5353316611126}

## [CISCN 2022 东北]easycpp
>url: https://www.nssctf.cn/problem/2402
>知识点：动态调试
无壳，64位
 ![alt text](image-141.png)









