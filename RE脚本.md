## base64换表解密
>你需要：
>①在题目中找到换掉的base64表，赋值给s2
> ②将密文赋值给en_text
>③运行后即可获得明文
```py
import base64 #导入base64模块用于解密
s1 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' #标准表
s2 = 'qvEJAfHmUYjBac+u8Ph5n9Od17FrICL/X0gVtM4Qk6T2z3wNSsyoebilxWKGZpRD' #base64换表
en_text = '5Mc58bPHLiAx7J8ocJIlaVUxaJvMcoYMaoPMaOfg15c475tscHfM/8==' #密文
 
map = str.maketrans(s2, s1) #用str类中的maketrans建立映射，注意第一个参数是需要映射的字符串，第二个参数是映射的目标
map_text = en_text.translate(map) #映射实现替换密文，替换前是base64换表加密，替换后则是base64标准表加密
print(map_text) #可以先看看标准表加密的原base64密文
print(base64.b64decode(map_text)) #直接使用提供的base64解密函数解密
```