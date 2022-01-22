# coding=utf-8
import os
import sys
import time
import argparse
import getpass
import paramiko
import logging
from logging import debug, info, warning, error
from tabulate import tabulate

from gpu_monitor import run_nvidiasmi_remote, get_gpu_infos, run_command
from gpu_monitor import run_ps_remote, get_users_by_pid
from gpu_monitor import SSH_CMD

# Default timeout in seconds after which SSH stops trying to connect
DEFAULT_SSH_TIMEOUT = 3

# Default timeout in seconds after which remote commands are interrupted
DEFAULT_CMD_TIMEOUT = 10

# Default server file
DEFAULT_SERVER_FILE = 'servers.txt'
SERVER_FILE_PATH = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])),
                                DEFAULT_SERVER_FILE)

PROC_EXE_CMD = "sudo ls -l /proc/{pid}/exe"
SHOW_USER_CMD = "sudo ls -l '{exe}' | awk '{{print $3}}'"
HELP_CWD = "'{exe}' -h | grep -i miner"

table_header = ['server', 'user', 'pid', 'path']
table_data = []


parser = argparse.ArgumentParser(description='Check state of GPU servers')
parser.add_argument('-v', '--verbose', action='store_true',
                    help='Be verbose')
parser.add_argument('-l', '--list', action='store_true', help='Show used GPUs')
parser.add_argument('-f', '--finger', action='store_true',
                    help='Attempt to resolve user names to real names')
parser.add_argument('-m', '--me', action='store_true',
                    help='Show only GPUs used by current user')
parser.add_argument('-u', '--user', help='Shows only GPUs used by a user')
parser.add_argument('-s', '--ssh-user', default=None,
                    help='Username to use to connect with SSH')
parser.add_argument('--ssh-timeout', default=DEFAULT_SSH_TIMEOUT,
                    help='Timeout in seconds after which SSH stops to connect')
parser.add_argument('--cmd-timeout', default=DEFAULT_CMD_TIMEOUT,
                    help=('Timeout in seconds after which nvidia-smi '
                          'is interrupted'))
parser.add_argument('--server-file', default=SERVER_FILE_PATH,
                    help='File with addresses of servers to check')
parser.add_argument('servers', nargs='*', default=[],
                    help='Servers to probe')


def run_ssh_command(hostname, username, password, cmd):
    info(cmd)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=hostname, username=username, password=password)
    sudo = 'sudo' in cmd
    stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=sudo)
    if sudo:
        stdin.write(password + '\n')
        time.sleep(1)
    res = stdout.read().decode()
    ssh.close()
    return res


def run_proc_exe_remote(hostname, pid, password, username):
    cmd = PROC_EXE_CMD.format(pid=pid)
    res = run_ssh_command(hostname=hostname, username=username, password=password, cmd=cmd)
    return res

def run_show_user_remote(hostname, exe, password, username):
    cmd = SHOW_USER_CMD.format(exe=exe)
    res = run_ssh_command(hostname=hostname, username=username, password=password, cmd=cmd)
    return res

def run_help_remote(hostname, exe, password, username):
    cmd = HELP_CWD.format(exe=exe)
    res = run_ssh_command(hostname=hostname, username=username, password=password, cmd=cmd)
    return res

def check_miner(server, gpu_infos, password, username):
    if '@' in server:
        hostname = server.split('@')[1]
    else:
        hostname = server
    warning("check {}".format(hostname))
    pids = [pid for gpu_info in gpu_infos for pid in gpu_info['pids']]
    pids = set(pids)
    for pid in pids:
        debug(pid)
        ls_info = run_proc_exe_remote(hostname=hostname, pid=pid, password=password, username=username)
        target_exe = ls_info.strip().split('->')[-1].strip()
        info(target_exe)
        user_info = run_show_user_remote(hostname=hostname, exe=target_exe, password=password, username=username)
        user_info = user_info.strip().split('\n')[-1]
        info(user_info)
        grep_res = run_help_remote(hostname, exe=target_exe, password=password, username=username).strip()
        info(grep_res)
        if len(grep_res) > 0:
            log_info = 'FOUND! server={}, path={}, pid={}, user={}'.format(hostname, user_info, pid, target_exe)
            warning(log_info)
            table_data.append((hostname, user_info, pid, target_exe))

def main(argv):
    args = parser.parse_args(argv)

    logging.basicConfig(format='%(message)s',
                        level=logging.INFO if args.verbose else logging.WARN)

    if len(args.servers) == 0:
        try:
            debug('Using server file {}'.format(args.server_file))
            with open(args.server_file, 'r') as f:
                servers = (s.strip() for s in f.readlines())
                args.servers = [s for s in servers if s != '']
        except OSError as e:
            error('Could not open server file {}'.format(args.server_file))
            return

    pwd = getpass.getpass(prompt='Input sudo password:')

    if len(args.servers) == 0:
        error(('No GPU servers to connect to specified.\nPut addresses in '
               'the server file or specify them manually as an argument'))
        return

    if args.ssh_user is not None:
        args.servers = ['{}@{}'.format(args.ssh_user, server)
                        for server in args.servers]
    if args.me:
        if args.ssh_user is not None:
            args.user = args.ssh_user
        else:
            args.user = pwd.getpwuid(os.getuid()).pw_name
    if args.user or args.finger:
        args.list = True

    for server in args.servers:
        gpu_infos = run_nvidiasmi_remote(server=server, ssh_timeout=args.ssh_timeout, cmd_timeout=args.cmd_timeout)
        check_miner(server=server, gpu_infos=get_gpu_infos(gpu_infos), password=pwd, username=args.ssh_user)

    if len(table_data) > 0:
        warning(tabulate(table_data, headers=table_header, tablefmt='grid'))
    else:
        warning("all safe")


if __name__ == "__main__":
    main(sys.argv[1:])