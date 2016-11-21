#!/bin/sh

export DEBIAN_FRONTEND=noninteractive
apt-get -y install unzip

#replace this with a git clone
cd /tmp/
wget -O vpnspeedtest.zip https://github.com/vpnspeedtest/speedtests-scripts/archive/master.zip
unzip -o vpnspeedtest.zip
cp -R speedtests-scripts-master/* ~

#setup working folders
cd ~
mkdir -p torrents
mkdir -p logs
mkdir -p vpn_auth

#setup environment
chmod 700 scripts/*
./scripts/vultr-debian-setup.sh

#update the path to use the new curl we just built from source
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

python vpnspeedtest.py --help
