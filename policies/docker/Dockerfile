FROM ubuntu

VOLUME /tmp
ARG DEPENDENCY=target/dependency
COPY ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY ${DEPENDENCY}/META-INF /app/META-INF
COPY ${DEPENDENCY}/BOOT-INF/classes /app

RUN apt get update
RUN apt install python3 python3-pip && pip3 install awscli==1.18.1

ENTRYPOINT ["java","-cp","app:app/lib/*","hello.Application"]
