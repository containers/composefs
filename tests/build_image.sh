#!/bin/bash

CURRENT_UIDGID="$(id -u):$(id -g)"
mkdir -p _build

set -ex

osbuild-mpp composefs.mpp.yml _build/composefs.json
sudo osbuild --store _build/osbuild_store --output-directory _build/output --export qcow2 _build/composefs.json

sudo chown -R $CURRENT_UIDGID _build/output/qcow2
mv _build/output/qcow2/disk.qcow2 composefs.qcow2
