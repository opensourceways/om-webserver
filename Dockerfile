FROM openjdk:8-jdk

ARG NEW_YEAR_USER
ARG BRANCH

MAINTAINER zhongjun <jun.zhongjun2@gmail.com>

RUN mkdir -p /var/lib/om-webserver
WORKDIR /var/lib/om-webserver

# Install basic software support
RUN apt-get update && \
    apt-get install --yes software-properties-common

RUN wget https://dlcdn.apache.org/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.tar.gz && \
        tar -xzvf apache-maven-3.6.3-bin.tar.gz
ENV MAVEN_HOEM=/var/lib/om-webserver/apache-maven-3.6.3
ENV PATH=$MAVEN_HOEM/bin:$PATH

RUN git clone -b ${BRANCH} https://gitee.com/opensourceway/om-webserver.git && \
        cd om-webserver && \
        mvn clean install package -Dmaven.test.skip && \
        mv ./target/om-webserver-0.0.1-SNAPSHOT.jar ../om-webserver.jar

RUN git clone https://${NEW_YEAR_USER}@gitee.com/lixianlin01/new-year.git

CMD java -jar om-webserver.jar