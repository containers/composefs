#!/bin/bash
set -xeuo pipefail

# Handle Fedora derivatives or others that have composefs
# shipped already.

if test -x /usr/bin/dnf; then
    . /etc/os-release
    case "${ID_LIKE:-}" in
        *rhel*) dnf config-manager --set-enabled crb ;; 
    esac
    dnf -y install dnf-utils tar git meson;
    dnf -y builddep composefs
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive

PACKAGES=" \
    automake \
    libtool \
    autoconf \
    autotools-dev \
    git \
    make \
    tar \
    gcc \
    libssl-dev \
    libfsverity-dev \
    pkg-config \
    libfuse3-dev \
    python3 \
    libcap2-bin \
    meson \
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
    apt -y update
    apt-get install -y $PACKAGES_REQUIRED
fi

if [ -n "${PACKAGES_OPTIONAL}" ]; then
    apt -y update
    apt-get install -y --ignore-missing $PACKAGES_OPTIONAL || true
fi
