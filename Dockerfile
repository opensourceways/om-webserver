# FROM openeuler/openeuler:22.03 as Builder
FROM openeuler/openeuler:22.03-lts-sp1 as BUILDER

RUN sed -i "s|repo.openeuler.org|mirrors.nju.edu.cn/openeuler|g" /etc/yum.repos.d/openEuler.repo \
    && sed -i '/metalink/d' /etc/yum.repos.d/openEuler.repo \
    && sed -i '/metadata_expire/d' /etc/yum.repos.d/openEuler.repo

WORKDIR /

RUN cd / \
    && yum install -y wget


# 使用香港或亚洲地区的镜像源下载 JDK 和 Maven
RUN wget https://github.com/adoptium/temurin18-binaries/releases/download/jdk-18.0.2.1%2B1/OpenJDK18U-jdk_x64_linux_hotspot_18.0.2.1_1.tar.gz \
    && tar -zxvf OpenJDK18U-jdk_x64_linux_hotspot_18.0.2.1_1.tar.gz \
    && wget https://mirrors.cloud.tencent.com/apache/maven/maven-3/3.8.8/binaries/apache-maven-3.8.8-bin.tar.gz \
    && tar -zxvf apache-maven-3.8.8-bin.tar.gz

ENV JAVA_HOME=/jdk-18.0.2.1+1
ENV PATH=${JAVA_HOME}/bin:$PATH

ENV MAVEN_HOME=/apache-maven-3.8.8
ENV PATH=${MAVEN_HOME}/bin:$PATH

COPY . /om-webserver

RUN cd om-webserver \
    && mvn clean install package -Dmaven.test.skip \
    && mv ./target/om-webserver-0.0.1-SNAPSHOT.jar ./target/om-webserver.jar

FROM openeuler/openeuler:22.03-lts-sp1

RUN sed -i "s|repo.openeuler.org|mirrors.nju.edu.cn/openeuler|g" /etc/yum.repos.d/openEuler.repo \
    && sed -i '/metalink/d' /etc/yum.repos.d/openEuler.repo \
    && sed -i '/metadata_expire/d' /etc/yum.repos.d/openEuler.repo

RUN yum update -y \
    && yum install -y shadow passwd \
    && groupadd -g 1001 om-webserver \
    && useradd -u 1001 -g om-webserver -s /bin/bash -m om-webserver \
    && yum install -y fontconfig glibc-all-langpacks

ENV LANG=zh_CN.UTF-8
ENV WORKSPACE=/home/om-webserver
ENV SOURCE=${WORKSPACE}/file/source
ENV TARGET=${WORKSPACE}/file/target

WORKDIR ${WORKSPACE}

COPY --chown=om-webserver --from=Builder /om-webserver/target/om-webserver.jar ${WORKSPACE}/target/om-webserver.jar

RUN echo "umask 027" >> /home/om-webserver/.bashrc \
    && echo "umask 027" >> /root/.bashrc \
    && source /home/om-webserver/.bashrc \
    && echo "set +o history" >> /etc/bashrc \
    && echo "set +o history" >> /home/om-webserver/.bashrc \
    && sed -i "s|HISTSIZE=1000|HISTSIZE=0|" /etc/profile \
    && sed -i "s|PASS_MAX_DAYS[ \t]*99999|PASS_MAX_DAYS 30|" /etc/login.defs \
    && sed -i '4,6d' /home/om-webserver/.bashrc

RUN passwd -l om-webserver \
    && usermod -s /sbin/nologin sync \
    && usermod -s /sbin/nologin shutdown \
    && usermod -s /sbin/nologin halt \
    && usermod -s /sbin/nologin om-webserver \
    && echo "export TMOUT=1800 readonly TMOUT" >> /etc/profile

RUN dnf install -y wget \
    && wget https://mirrors.tuna.tsinghua.edu.cn/Adoptium/18/jre/x64/linux/OpenJDK18U-jre_x64_linux_hotspot_18.0.2.1_1.tar.gz -O jre-18.0.2.tar.gz \
    && tar -zxvf jre-18.0.2.tar.gz \
    && rm jre-18.0.2.tar.gz \
    && chown -R om-webserver:om-webserver jdk-18.0.2.1+1-jre

RUN rm -rf `find / -iname "*tcpdump*"` \
    && rm -rf `find / -iname "*sniffer*"` \
    && rm -rf `find / -iname "*wireshark*"` \
    && rm -rf `find / -iname "*Netcat*"` \
    && rm -rf `find / -iname "*gdb*"` \
    && rm -rf `find / -iname "*strace*"` \
    && rm -rf `find / -iname "*readelf*"` \
    && rm -rf `find / -iname "*cpp*"` \
    && rm -rf `find / -iname "*gcc*"` \
    && rm -rf `find / -iname "*dexdump*"` \
    && rm -rf `find / -iname "*mirror*"` \
    && rm -rf `find / -iname "*JDK*"` \
    && rm -rf /root/.m2/repository/* \
    && rm -rf /tmp/*

RUN rm -rf /usr/bin/gdb* \
    && rm -rf /usr/share/gdb \
    && rm -rf /usr/share/gcc-10.3.1 \
	&& yum remove gdb-gdbserver findutils passwd shadow -y \
    && yum clean all \
    && chmod 600 -R /home/om-webserver/ \
    && chmod 700 /home/om-webserver \
    && chmod 500 -R /home/om-webserver/jdk-18.0.2.1+1-jre \
    && chmod 500 -R /home/om-webserver/target

ENV JAVA_HOME=${WORKSPACE}/jdk-18.0.2.1+1-jre
ENV PATH=${JAVA_HOME}/bin:$PATH
ENV MALLOC_ARENA_MAX=4

EXPOSE 8080

ENV SOURCE= \
    TARGET=

USER om-webserver

CMD java --add-opens java.base/java.util=ALL-UNNAMED \
         --add-opens java.base/java.lang=ALL-UNNAMED \
         --add-opens java.base/java.lang.reflect=ALL-UNNAMED \
         --add-opens java.base/java.io=ALL-UNNAMED \
         -jar ${WORKSPACE}/target/om-webserver.jar --spring.config.location=${APPLICATION_PATH}