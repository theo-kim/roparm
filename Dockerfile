FROM ubuntu:18.04
COPY . /app
RUN apt-get update
RUN apt-get install -y build-essential lsb-core
# RUN apt-get install -y capstone
WORKDIR /app
RUN ls
RUN make clean
RUN make
ENTRYPOINT ["./dist/roparm"]