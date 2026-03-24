#!/bin/bash

echo "=== CIS CHECKS START ==="

# Firewall
echo "Firewall Status:"
ufw status

# Root Login via SSH
echo "Root Login Status:"
grep PermitRootLogin /etc/ssh/sshd_config

# Password Policy
echo "Password Policy:"
grep PASS_MIN_LEN /etc/login.defs

# Last Update
echo "Last Update:"
stat /var/log/apt/history.log

echo "=== CIS CHECKS END ==="