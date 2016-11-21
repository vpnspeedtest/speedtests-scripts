#!/usr/bin/env sh
# script should be called by the `--down` option.

rt_table="vpntunnel"

ip rule delete from "$ifconfig_local" table "$rt_table"
ip route flush table "$rt_table"

/etc/openvpn/update-resolv-conf $1 $2 $3 $4 $5 $6 $7
