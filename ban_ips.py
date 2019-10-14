#!/usr/bin/env python3

import sys

# grep "Failed password" /var/log/auth.log
with open('/var/log/auth.log', 'r') as f:
    content = f.readlines()
ips = {}
for line in content:
    if "Failed password" not in line:
        continue
    ip = line.split(' from ')
    if len(ip) < 2:
        continue
    ip = ip[1].split(' port ')
    if len(ip) < 2:
        continue
    ip = ip[0]
    if ip in ips:
        ips[ip] += 1
    else:
        ips[ip] = 1
v = []
for ip in ips:
    v.append([ip, ips[ip]])
v.sort(key=lambda x: x[1], reverse=True)
for x in v:
    if x[1] > 79:
        print('sshd: {}'.format(x[0]))
i = input('Do you want to add them to the banned list? [Y/n] ').strip().lower()
if len(i) != 0 and i != 'n':
    print('Ok, leaving!')
    sys.exit(0)
print('Saving new banned users!')
print('First, reading /etc/hosts.deny...')
with open('/etc/hosts.deny', 'r+') as f:
    content = f.readlines()
saved_ips = {}
for line in content:
    if not line.startswith('sshd:'):
        continue
    ip = line.split(':')[1].strip()
    saved_ips[ip] = True
print('Done, there is currently {} banned IPs'.format(len(saved_ips)))
wrote_ips = 0
with open('/etc/hosts.deny', 'a') as f:
    for x in v:
        if x[1] < 79 or x[0] in saved_ips:
            continue
        wrote_ips += 1
        f.write('sshd: {}\n'.format(x[0]))
print('Added {} new IPs to the /etc/hosts.deny file'.format(wrote_ips))
