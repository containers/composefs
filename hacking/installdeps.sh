#!/bin/bash
set -xeuo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get install -y automake libtool autoconf autotools-dev git make gcc libyajl-dev libssl-dev libfsverity-dev pkg-config
