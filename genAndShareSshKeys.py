#!/usr/bin python3

import os
import argparse
import ipaddress
import sys

argParser = argparse.ArgumentParser(description="Generate and Share SSH keys between diffrent hosts.")
argParser.add_argument('-i','--identity', metavar='identityFile', help="Identity file is the file to be used in order to be able to connect via ssh.")
argParser.add_argument('-pk','--pubkey', metavar='pubkey', help="Pub key file is the file to be transer in the remote host(s).")
argParser.add_argument('-u','--user', metavar='remoteUser', required=True, help="The remote username.")
argParser.add_argument('-H',"--ips", nargs="+", required=True, help="A list of IPs/Hosts used to transfer SSH keys.")
args = argParser.parse_args()

def is_ipv4(string):
    '''function that checks if provided ip is in valid IPv4 form'''
    try:
        ipaddress.IPv4Network(string)
        return True
    except ValueError:
        return False

def set_ssh_config(host, user):
    '''function that appends/creates an entry on ~/.ssh/config.'''
    if os.path.exists("/home/scripter/.ssh/config"):
        append_write = 'a' # append if already exists
    else:
        append_write = 'w' # make a new file if not

    with open("/home/scripter/.ssh/config", append_write) as f:
        f.write("\nHost "+host+"\n\tUser\t"+user+"\n\tIdentityFile\t~/.ssh/id_rsa_"+user)

def key_gen_or_check_and_load(pubkey):
    '''function that generates a key pair if not already provided by -pk flag.'''
    if pubkey is None:
        os.system('ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa_'+args.user)
        return "~/.ssh/id_rsa_"+args.user+".pub"
    elif(open(pubkey).read().startswith("-----BEGIN ")):
        print("\nThe given file under -pk flag is a private key not a public.")
        sys.exit()

def add_ip_to_known_hosts(remoteIP):
    '''function that adds IP to ~/.ssh/known_hosts.'''
    os.system("ssh-keyscan -H "+remoteIP+" >> ~/.ssh/known_hosts")

def transfering_pub_key(remoteIP):
    '''function that is adding the pub key to remote ~/.ssh/authorized_keys.'''
    if args.identity is not None:
        os.system('cat '+pubkey+' | ssh -i '+args.identity+' '+args.user+'@'+remoteIP+' "mkdir ~/.ssh; cat >> ~/.ssh/authorized_keys"')
    else:
        os.system('cat '+pubkey+' | ssh '+args.user+'@'+remoteIP+' "mkdir ~/.ssh; cat >> ~/.ssh/authorized_keys"')

columns = os.get_terminal_size(0)[0]
pubkey = key_gen_or_check_and_load(args.pubkey)

for remoteIP in args.ips: 
    print("_"*columns)
    if(is_ipv4(remoteIP)):
        print("\nAdding ip to known hosts")
        add_ip_to_known_hosts(remoteIP)

        print("\nTransfering the pub key to "+remoteIP)
        transfering_pub_key(remoteIP)

        print("\nAdding records to ~/.ssh/config")
        set_ssh_config(remoteIP, args.user)
        
        print('The key transfered successfully!\n\n To connect use either of:')
        print('\n 1. ssh -i ~/.ssh/id_rsa_'+args.user+' '+args.user+'@'+remoteIP)
        print('\n 2. ssh '+remoteIP)
    else:
        print("\n\nThe remoteIP '"+remoteIP+"' is not an IP.")

