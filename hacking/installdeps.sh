#!/bin/bash
set -xeuo pipefail
export DEBIAN_FRONTEND=noninteractive

PACKAGES=" \
    automake \
    libtool \
    autoconf \
    autotools-dev \
    git \
    make \
    gcc \
    libssl-dev \
    libfsverity-dev \
    pkg-config \
    libfuse3-dev \
    python3 \
    libcap2-bin \
    meson \
    libseccomp-dev \
    libcap-dev \
"

# Split required and optional packages based on input variable ALLOW_MISSING:
PACKAGES_REQUIRED=""
PACKAGES_OPTIONAL=""

for pkg in $PACKAGES; do
    if [[ " ${ALLOW_MISSING:-} " == *" ${pkg} "* ]]; then
	PACKAGES_OPTIONAL+=" ${pkg}"
    else
	PACKAGES_REQUIRED+=" ${pkg}"
    fi
done

# Install packages:
if [ -n "${PACKAGES_REQUIRED}" ]; then
    apt-get install -y $PACKAGES_REQUIRED
fi

if [ -n "${PACKAGES_OPTIONAL}" ]; then
    apt-get install -y --ignore-missing $PACKAGES_OPTIONAL || true
fi
