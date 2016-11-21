#!/usr/bin/env sh
# This script should be called by the `--up` option.
rt_table="vpntunnel"

ip rule add from "$ifconfig_local" table "$rt_table"
ip route add table "$rt_table" default via "$route_vpn_gateway"

if [ ! "$ifconfig_remote" ]; then
    ip route add table "$rt_table" "128.0.0.1" via "$route_vpn_gateway" dev "$dev"
else
    ip route add table "$rt_table" "$route_vpn_gateway" via "$ifconfig_local" dev "$dev"
fi

/etc/openvpn/update-resolv-conf $1 $2 $3 $4 $5 $6 $7
