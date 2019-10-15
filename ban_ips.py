#!/usr/bin/env python3


def is_successful_login(line):
    return ": Accepted password " in line


def is_failed_login(line):
    return ": Failed password " in line or " Invalid user " in line


# grep "Failed password" /var/log/auth.log
def get_failed_ips():
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
    with open('/etc/hosts.deny', 'r+') as f:
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
    with open('/etc/hosts.deny', 'a') as f:
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
            f.write('sshd: {}\n'.format(x[0]))
            wrote_ips += 1
    print('Added {} new IPs to the /etc/hosts.deny file'.format(wrote_ips))


def main():
    failed_ips = get_failed_ips()
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
