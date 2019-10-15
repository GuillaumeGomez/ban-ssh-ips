#!/usr/bin/env python3

import os
import subprocess


def convert_to_string(s):
    if s.__class__.__name__ == 'bytes':
        return s.decode('utf-8')
    return s


def is_successful_login(line):
    return ": Accepted password " in line


def is_failed_login(line):
    return ": Failed password " in line or " Invalid user " in line


# grep "Failed password" /var/log/auth.log
def get_failed_ips(current_ssh_ip):
    print('Getting failed IPs from /var/log/auth.log...')
    with open('/var/log/auth.log', 'r') as f:
        content = f.readlines()
    ips = {}
    success_logins = {}
    for line in content:
        is_success = is_successful_login(line)
        is_failure = is_failed_login(line)
        if is_success is False and is_failure is False:
            continue
        ip = line.split(' from ')
        if len(ip) < 2:
            continue
        ip = ip[1].split(' port ')
        if len(ip) < 2:
            continue
        ip = ip[0]
        if ip == current_ssh_ip:
            if is_failure:
                print('=> Found a failed login attempt for the current ssh session IP!')
            continue
        if is_failure:
            if ip in success_logins:
                continue
            if ip not in ips:
                ips[ip] = 0
            ips[ip] += 1
        else:
            ips.pop(ip, None)
            if ip not in success_logins:
                success_logins[ip] = 0
            success_logins[ip] += 1
    v = []
    for ip in ips:
        if ips[ip] > 79:
            v.append([ip, ips[ip]])
    v.sort(key=lambda x: x[1], reverse=True)
    print('Done!')
    if len(success_logins) > 0:
        i = input('Do you want to see the list of successful login IPs? [y/N] ').strip().lower()
        if i == 'y':
            for ip in success_logins:
                print(ip)
    else:
        print('No successful logins available in the logs...')
    return v


def get_banned_ips():
    print('First, reading /etc/hosts.deny...')
    with open('/etc/hosts.deny', 'r') as f:
        content = f.readlines()
    saved_ips = {}
    for line in content:
        if not line.startswith('sshd:'):
            continue
        ip = line.split(':')[1].strip()
        saved_ips[ip] = True
    print('Done, there is currently {} banned IPs'.format(len(saved_ips)))
    return saved_ips


def save_new_banned_users(failed_ips, banned_ips):
    wrote_ips = 0
    command = "echo '"
    for x in failed_ips:
        if x[0] in banned_ips:
            continue
        if x[0].startswith('192.168.'):
            i = input('{} seems to be a local address... Do you still want to ban it? [y/N] '
                      .format(x[0]))
            i = i.strip().lower()
            if i != 'y':
                print('Ignoring it then!')
                continue
        command += 'sshd: {}\n'.format(x[0])
        wrote_ips += 1
    if wrote_ips > 0:
        command = command[:-1] # remove last useless backline
    command += "' >> /etc/hosts.deny"
    if wrote_ips == 0:
        print('Nothing left to write after deduplication, aborting...')
        return
    out = subprocess.run(['sudo', 'bash', '-c', command],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    stdout = convert_to_string(out.stdout)
    print(stdout)
    if out.returncode != 0:
        print('Command failed... If you want to run yourself:')
        print('sudo bash -c {}'.format(command))
        return
    print('Added {} new IPs to the /etc/hosts.deny file'.format(wrote_ips))


def get_ssh_connection_ip():
    print('Trying to get current ssh session IP...')
    print("Let's start with SSH_CLIENT environment variable!")
    ip = os.environ.get('SSH_CLIENT')
    if ip is not None and len(ip) > 0:
        ip = ip.split(' ')[0]
        print("Found it! It's {}".format(ip))
        return ip
    print('Nothing there...')
    print("Let's try with SSH_CONNECTION environment variable!")
    ip = os.environ.get('SSH_CONNECTION')
    if ip is not None and len(ip) > 0:
        ip = ip.split(' ')[0]
        print("Found it! It's {}".format(ip))
    print("Nothing there either... Maybe it's not an ssh session?")
    return None


def main():
    if os.geteuid() == 0:
        print("It'd be better to start this script not being root (it allows to keep the \
                session variables)")
        i = input('Do you still want to continue? [y/N] ').strip().lower()
        if i != 'y':
            print('Aborting')
            return
    failed_ips = get_failed_ips(get_ssh_connection_ip())
    if len(failed_ips) == 0:
        print('No failed attempts detected, leaving...')
        return
    i = input('Do you want to add the {} IPs to the banned list? [Y/n] '.format(len(failed_ips)))
    i = i.strip().lower()
    if len(i) != 0 and i != 'y':
        print('Ok, just printing the failed IPs then!')
        for x in failed_ips:
            print('sshd: {}'.format(x[0]))
        return
    print('Saving new banned users!')
    banned_ips = get_banned_ips()
    save_new_banned_users(failed_ips, banned_ips)


if __name__ == "__main__":
    main()
else:
    print("Shouldn't be imported but run as executable!")
