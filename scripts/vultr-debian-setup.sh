export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade

#install openvpn stuff
apt-get -y install openvpn resolvconf

#install python + tools
apt-get -y install python-pip build-essential libssl-dev libffi-dev python-dev python-netifaces aria2 zip unzip

#install remaining python libraries
pip install pycparser==2.13 #There is a bug with PyCParser 2.14
pip install pysftp

#install and build Curl to test DNS speeds via tun0 interface
#we need Curl  compiled with ares support
cd /tmp
wget https://c-ares.haxx.se/download/c-ares-1.12.0.tar.gz
tar xvzf c-ares-1.12.0.tar.gz
cd c-ares-1.12.0/
./configure
make
make install
cd /tmp
wget http://curl.haxx.se/download/curl-7.50.0.tar.gz
tar xvzf curl-7.50.0.tar.gz
cd curl-7.50.0
./configure --enable-ares --disable-shared
make
make install
ldconfig

#this is for the vpn-up.sh and vpn-down.sh scripts
echo 200 vpntunnel >> /etc/iproute2/rt_tables
