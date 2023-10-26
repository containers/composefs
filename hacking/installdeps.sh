#!/bin/bash
set -xeuo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get install -y automake libtool autoconf autotools-dev git make gcc libssl-dev libfsverity-dev pkg-config libfuse3-dev python3 libcap2-bin
