import select, socket, sys
from hw2_util import Room, Hall, Player
import hw2_util
import getpass

READ_BUFFER = 4096

if len(sys.argv) < 2:
    print("Usage: Python3 client.py [hostname]", file = sys.stderr)
    sys.exit(1)
else:
    server_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_connection.connect((sys.argv[1], hw2_util.PORT))

def prompt():
    print('>', end=' ', flush = True)

print("Connected to server\n")
msg_prefix = ''
pswd=''
socket_list = [sys.stdin, server_connection]
'error_pass'
while True:
    read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])
    for s in read_sockets:
        if s is server_connection: # incoming message 
            msg = s.recv(READ_BUFFER)
            if not msg:
                print("Server down!")
                sys.exit(2)
            else:
                if msg == hw2_util.QUIT_STRING.encode():
                    sys.stdout.write('Bye\n')
                    sys.exit(2)
                elif msg == 'error_pass'.encode():
                    sys.stdout.write('error_pass\n')
                    sys.exit(2)
                elif msg == 'The account is login now.'.encode():
                    sys.stdout.write('The account is login now.\n')
                    sys.exit(2)
                else:
                    sys.stdout.write(msg.decode())
                    if 'Please tell us your name' in msg.decode():
                        msg_prefix = 'name: ' # identifier for name
                    else:
                        #pswd = getpass.getpass('Password:')
                        msg_prefix = ''
                    prompt()
                    #print('>')
                    #if msg_prefix == 'name: ':
                        #pswd = getpass.getpass('Password:')

        else:
            #sys.stdout.write('input\n')
            if msg_prefix == 'name: ':
                msg = msg_prefix + sys.stdin.readline()
                pswd = getpass.getpass('Password:')
                msg=msg+pswd
            else:
                msg = msg_prefix + sys.stdin.readline()
            server_connection.sendall(msg.encode())
