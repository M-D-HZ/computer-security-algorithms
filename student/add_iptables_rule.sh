#!/bin/sh

iptables-legacy -t nat -A PREROUTING -i eth0 -p tcp --dport '80' -j REDIRECT --to-port '8080'
