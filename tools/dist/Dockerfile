# kubos/kubos-dev:1.14.0

FROM phusion/baseimage:0.9.22

MAINTAINER catherine@kubos.com, ryan@kubos.com

RUN apt-get update -y

RUN apt-get upgrade -y python3.5
RUN apt-get install -y pkg-config
RUN apt-get install -y build-essential 
RUN apt-get install -y python-setuptools build-essential 
RUN apt-get install -y git
RUN apt-get install -y cmake
RUN apt-get install -y unzip wget
RUN apt-get install -y sqlite3 libsqlite3-dev
RUN apt-get install -y libssl-dev

#do the pip setup and installation things
RUN easy_install pip

# Set up pip for Python3.5
RUN apt-get install -y python3-pip

#Kubos Linux setup
RUN echo "Installing Kubos Linux Toolchain"

RUN wget https://s3.amazonaws.com/kubos-world-readable-assets/iobc_toolchain.tar.gz
RUN tar -xf ./iobc_toolchain.tar.gz -C /usr/bin
RUN rm ./iobc_toolchain.tar.gz

RUN wget https://s3.amazonaws.com/kubos-world-readable-assets/bbb_toolchain.tar.gz
RUN tar -xf ./bbb_toolchain.tar.gz -C /usr/bin
RUN rm ./bbb_toolchain.tar.gz

# Setup Python package dependencies
RUN pip3 install toml
RUN pip3 install mock
RUN pip3 install responses

# Setup rust stuff
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH "$PATH:/root/.cargo/bin"
RUN rustup default 1.32.0
RUN rustup target install arm-unknown-linux-gnueabihf
RUN rustup target install armv5te-unknown-linux-gnueabi
RUN rustup component add clippy
RUN rustup component add rustfmt
RUN /root/.cargo/bin/cargo install --git https://github.com/kubos/cargo-kubos
COPY cargo_config /root/.cargo/config

#Tools to generate docs
RUN apt-get install -y doxygen graphviz plantuml
RUN pip install Sphinx==1.5.6
RUN pip install breathe
RUN pip install sphinx-rtd-theme==0.2.4
RUN pip install sphinxcontrib-plantuml sphinxcontrib-versioning
RUN pip install sphinx-jsondomain

ENV PATH "$PATH:/usr/bin/iobc_toolchain/usr/bin:/usr/bin/bbb_toolchain/usr/bin"