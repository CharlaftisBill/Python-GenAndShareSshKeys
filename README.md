# Python-GenAndShareSshKeys

This script is generating SSH key pairs or/and transfering the public keys to a list of other Linux machines. 

> ### <ins>__Prerequisites:__</ins>
>__Debian/Ubuntu:__ The script is created and tested on <b>Ubuntu 20.04</b> server and doesn't supports not Debian Linux os. 
>
> __Python 3:__ The script is writen on python3. Make sure that python is intalled before you run it.
>
> __OpenSSH:__ The script is using some bash commands that are part os OpenSSH. Make sure that OpenSSH is installed properly before you start.
>
> __Same User to all machines:__ This version of the script is excpecting that all machine have the same user specified with -u flag. 

## How to use:

The simpliest format of the command is:

```bash
python3 genAndShareSshKeys.py -u theUsername --ips 123.456.789.1 123.456.789.2 ... 123.456.789.n
```
Note: that the script will ask you about the "theUsername" password of each machine during  the execution.

## Use an existing identity file to connect:

If you already have a public key that you are using to connect to your nodes (maybe there are Vms provided by some cloud provider) you can add one more using:

```bash
python3 genAndShareSshKeys.py -i path/to/id/file -u theUsername --ips 123.456.789.1 123.456.789.2 ... 123.456.789.n
```

## Use an already created public key:

If you have an already created public key and you want to just share it to connect beteween all nodes, use:

```bash
python3 genAndShareSshKeys.py -u theUsername -pk path/to/pub/key --ips 123.456.789.1 123.456.789.2 ... 123.456.789.n
```
Or
```bash
python3 genAndShareSshKeys.py -i path/to/id/file -u theUsername -pk path/to/pub/key --ips 123.456.789.1 123.456.789.2 ... 123.456.789.n
```

if you have an identiy file.

#

## List all flags:

You can use help -h flag to see all the flags supported by the script:
```bash
python3 genAndShareSshKeys.py -h
```
```bash
usage: genAndShareSshKeys.py [-h] [-i identityFile] [-pk pubkey] -u remoteUser -H IPS [IPS ...]

Generate and Share SSH keys between diffrent hosts.

optional arguments:
  -h, --help            show this help message and exit
  -i identityFile, --identity identityFile
                        Identity file is the file to be used in order to be able to connect via ssh.
  -pk pubkey, --pubkey pubkey
                        Pub key file is the file to be transer in the remote host(s).
  -u remoteUser, --user remoteUser
                        The remote username.
  -H IPS [IPS ...], --ips IPS [IPS ...]
                        A list of IPs/Hosts used to transfer SSH keys.
```

