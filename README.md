# om-webserver

#### 介绍

om-webserver是用来对外提供账号管理功能的服务。

#### 软件架构

* SpringBoot
* redis
* obs


#### 安装教程

##### 基本安装

1. 克隆工程
    > git clone https://github.com/opensourceways/om-webserver.git

2. 打包方式
    > mvn clean install package -Dmaven.test.skip

3. 启动应用
    > java -jar target/om-webserver.jar

*ps：启动应用需使用对应application.properties配置文件。*

##### 容器安装

1. 克隆工程
    > git clone https://github.com/opensourceways/om-webserver.git

2. 打包方式
    * 用Docker打包（到webserver目录中， 执行Dockerfile文件： docker build -t om-webserver . ）
    * 注意：DcokerFile中"RUN git clone https://${NEW_YEAR_USER}@gitee.com/lixianlin01/new-year.git"仅用于元数据获取，自己本地打镜像时可删除

3. 启动应用
    * Docker run -d -v /home/config.properties:/var/lib/om-webserver/config.properties 容器名称

#### 使用说明

接口功能描述[https://gitee.com/opensourceway/om-docs/blob/master/docs/om-webserver-interface/%E6%8E%A5%E5%8F%A3%E8%AF%B4%E6%98%8E.md](https://gitee.com/opensourceway/om-docs/blob/master/docs/om-webserver-interface/%E6%8E%A5%E5%8F%A3%E8%AF%B4%E6%98%8E.md)
