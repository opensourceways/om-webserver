FROM openeuler/openeuler:22.03

ARG BRANCH

MAINTAINER zhongjun <jun.zhongjun2@gmail.com>

RUN mkdir -p /var/lib/om-webserver
WORKDIR /var/lib/om-webserver

RUN yum install -y wget \
    && wget https://mirrors.tuna.tsinghua.edu.cn/Adoptium/8/jdk/x64/linux/OpenJDK8U-jdk_x64_linux_hotspot_8u392b08.tar.gz \
    && tar -zxvf OpenJDK8U-jdk_x64_linux_hotspot_8u392b08.tar.gz \
    && wget https://mirrors.tuna.tsinghua.edu.cn/apache/maven/maven-3/3.8.8/binaries/apache-maven-3.8.8-bin.tar.gz \
    && tar -xzvf apache-maven-3.8.8-bin.tar.gz \
    && yum install -y git

ENV JAVA_HOME=/var/lib/om-webserver/jdk8u392-b08
ENV PATH=${JAVA_HOME}/bin:$PATH

ENV MAVEN_HOEM=/var/lib/om-webserver/apache-maven-3.8.8
ENV PATH=$MAVEN_HOEM/bin:$PATH

RUN git clone -b ${BRANCH} https://gitee.com/opensourceway/om-webserver.git

RUN cd om-webserver && \
        mvn clean install package -Dmaven.test.skip && \
        mv ./target/om-webserver-0.0.1-SNAPSHOT.jar ../om-webserver.jar
 

CMD java -jar om-webserver.jar --spring.config.location=${APPLICATION_PATH}