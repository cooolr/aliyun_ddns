## aliyun_ddns --基于阿里云解析的动态域名解析

### 前提条件
1. 确保自己拥有外网ip
2. 使用阿里云解析，申请access_key -> https://ak-console.aliyun.com
3. 首先在阿里云解析中新增域名的解析记录 (重要！！！因为本脚本只是修改，所以前提得有可修改的解析记录！！！)

### 实现方法
定时检测自家外网ip地址，有变化就调用阿里云解析的api修改域名解析。

### 脚本依赖
1. python3环境 (安装python3, 不支持python2)
2. pip3 install requests

### 使用说明
1. 修改aliyun_settings.json中的access_key、access_secret为自己申请的accesskey
2. 修改aliyun_settings.json中的domain为自己要解析的域名，比如 "map.baidu.com''
3. 定时执行 python3 aliyun_ddns.py   (windows和linux环境下的定时任务就不提了)
4. 最新的ip会保存在同级目录的ip.txt中，方便查看
5. 脚本的执行步骤有日志，如有问题，先分析下输出内容

### 注意
修改完解析记录后并不会马上生效，因为dns服务都有缓存，所以得等，阿里云的解析ttl可以设置的最小值为10分钟，所以有时候得等一会才能生效。
如果迟迟不生效，首先登录阿里云控制台查看解析记录是否成功修改，如果已经修改，那么就是dns服务的缓存问题了，这个基本就是死等。。。
