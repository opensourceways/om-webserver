FROM gplane/pnpm as Builder

ARG BRANCH

MAINTAINER zhongjun <jun.zhongjun2@gmail.com>

WORKDIR /

RUN apt-get update \
    && wget https://download.oracle.com/java/17/archive/jdk-17.0.7_linux-x64_bin.tar.gz \
    && tar -zxvf jdk-17.0.7_linux-x64_bin.tar.gz \
    && wget https://repo.huaweicloud.com/apache/maven/maven-3/3.8.1/binaries/apache-maven-3.8.1-bin.tar.gz \
    && tar -zxvf apache-maven-3.8.1-bin.tar.gz \
    && npm i pnpm -g

ENV JAVA_HOME=/jdk-17.0.7
ENV PATH=${JAVA_HOME}/bin:$PATH

ENV MAVEN_HOME=/apache-maven-3.8.1
ENV PATH=${MAVEN_HOME}/bin:$PATH

RUN git clone -b ${BRANCH} https://gitee.com/opensourceway/om-webserver.git

RUN cd om-webserver \
    && mvn clean install package -Dmaven.test.skip \
    && mv ./target/om-webserver-0.0.1-SNAPSHOT.jar ./target/om-webserver.jar

FROM openeuler/openeuler:22.03
RUN sed -i "s|repo.openeuler.org|mirrors.pku.edu.cn/openeuler|g" /etc/yum.repos.d/openEuler.repo \
    && yum update -y \
    && yum install -y shadow \
    && groupadd -g 1001 om-webserver \
    && useradd -u 1001 -g om-webserver -s /bin/bash -m om-webserver \
    && yum install -y fontconfig glibc-all-langpacks

ENV LANG=zh_CN.UTF-8
ENV WORKSPACE=/home/om-webserver
ENV SOURCE=${WORKSPACE}/file/source
ENV TARGET=${WORKSPACE}/file/target

WORKDIR ${WORKSPACE}

COPY --chown=om-webserver --from=Builder /om-webserver/target ${WORKSPACE}/target

RUN dnf install -y wget \
    && wget https://download.bell-sw.com/java/17.0.9+11/bellsoft-jre17.0.9+11-linux-amd64.tar.gz -O jre-17.0.9.tar.gz \
    && tar -zxvf jre-17.0.9.tar.gz 
ENV JAVA_HOME=${WORKSPACE}/jre-17.0.9
ENV PATH=${JAVA_HOME}/bin:$PATH

EXPOSE 8080

USER om-webserver

CMD java --add-opens java.base/java.util=ALL-UNNAMED \
         --add-opens java.base/java.lang=ALL-UNNAMED \
         --add-opens java.base/java.lang.reflect=ALL-UNNAMED \
         -jar ${WORKSPACE}/target/om-webserver.jar --spring.config.location=${APPLICATION_PATH}