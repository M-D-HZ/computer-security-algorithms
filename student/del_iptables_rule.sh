#!/bin/sh

iptables-legacy -t nat -D PREROUTING 1
