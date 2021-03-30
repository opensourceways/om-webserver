# om-webserver

#### 介绍

om-webserver是用来对外提供接口数据服务的框架。

#### 软件架构
* SpringBoot

* elasticsearch


#### 安装教程

1.  克隆工程
    > git clone https://gitee.com/opensourceway/om-webserver.git
2.  打包方式
    * 用Docker打包（到webserver目录中， 执行Dockerfile文件： docker build -t om-webserver . ）

3. 启动应用
    * Docker run -d -v /home/config.properties:/var/lib/om-webserver/config.properties 容器名称


#### 使用说明

接口功能描述[https://gitee.com/opensourceway/om-docs/blob/master/docs/om-webserver-interface/%E6%8E%A5%E5%8F%A3%E8%AF%B4%E6%98%8E.md](https://gitee.com/opensourceway/om-docs/blob/master/docs/om-webserver-interface/%E6%8E%A5%E5%8F%A3%E8%AF%B4%E6%98%8E.md)
