# GMPKI

#### 介绍
符合国密规范的PKI数字证书认证服务.

#### 软件架构

KM-SERVER 密钥生成服务,生成SM2密钥对；

CA-SERVER 数字证书签发服务，签发数字证书；

CA-CLIENT CA服务测试客户端，向CA发起数字证书申请请求；

采用springboot作为基础框架，服务之间使用netty作为通讯框架，支持服务之间的心跳、断线重连机制。

服务之间数据协议遵从国密规范，包含CA-KM、CMP协议。

密码算法只支持SM2、SM3、SM4。

主要参考国密规范：

0014《数字证书认证系统密码协议规范》

《GB-T 19714-2005 信息技术 安全技术 公钥基础设施 证书管理协议》


#### 安装教程



#### 使用说明
1.  通过KM-SERVER中Application类中的main，启动服务
2.  通过CA-SERVER中Application类中的main，启动服务
3.  通过CA-CLIENT中Application类中的main，发起证书申请请求

目前只实现了数字证书的申请流程。更新、撤销等相关流程暂未实现。

平常空闲时间断断续续写一点，错误难免纰漏。

VX:buhuilayun

#### 参与贡献




#### 特技

