FROM python:3.7

MAINTAINER zhongjun <jun.zhongjun2@gmail.com>

RUN mkdir -p /var/lib/om-webserver
WORKDIR /var/lib/om-webserver

# Install basic software support
RUN apt-get update && \
    apt-get install --yes software-properties-common

# Add the JDK 8 and accept licenses (mandatory)
RUN add-apt-repository ppa:webupd8team/java && \
    echo debconf shared/accepted-oracle-license-v1-1 select true | debconf-set-selections && \
    echo debconf shared/accepted-oracle-license-v1-1 seen true | debconf-set-selections

# Install Java 8
RUN apt-get update && \
    apt-get --yes --no-install-recommends install oracle-java8-installer

#RUN wget https://mirror-hk.koddos.net/apache/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.tar.gz && \
#	tar -xzvf apache-maven-3.6.3-bin.tar.gz
#ENV MAVEN_HOEM=/var/lib/om-webserver/apache-maven-3.6.3
#ENV PATH=$MAVEN_HOEM/bin:$PATH
#RUN git clone https://gitee.com/opensourceway/om-webserver.git && \
#	cd om-webserver && \
#	mvn clean install package -Dmaven.test.skip && \
#	mv ./target/om-webserver-0.0.1-SNAPSHOT.jar ../om-webserver.jar

#CMD java -jar om-webserver.jar
