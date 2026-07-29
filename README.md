# unidbg-libnep
一个http服务器，通过unidbg导出libnep.so方法然后暴露给http业务。

该项目目前也包含了一份大神的apk，基本上也算开箱即用了（？

code w/ gpt-5.6-sol

## 编译
> [!note]
> 需要准备好 JDK 25 以及 Maven。
1. clone仓库
```bash
git clone https://github.com/littlekan233/unidbg-libnep.git
```
2. 构建
```bash
cd unidbg-libnep
mvn package
# 重新构建请用 mvn clean package
``` 
3. 复制到一个你喜欢的文件夹
```bash
mkdir -p /path/to/new-folder
cp godlike target/unidbg-libnep-*.jar /path/to/new-folder
```
4. 给姆斯大头！
```
cd /path/to/new-folder
java -jar <jar文件名>
```

## 使用方法
服务默认在 `127.0.0.1:20304` 上启动。
【wip】
- 测试
- 签名 GET 请求
