import socket, pdb

MAX_CLIENTS = 30
PORT = 1068
QUIT_STRING = '<$quit$>'
account={'man1':'man1','man2':'man2','man3':'man3','man4':'man4','man5':'man5'}
account_type={'man1':0,'man2':0,'man3':0,'man4':0,'man5':0}
account_off_message={'man1':'','man2':'','man3':'','man4':'','man5':''}
account_name=['man1','man2','man3','man4','man5']

def create_socket(address):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(0)
    s.bind(address)
    s.listen(MAX_CLIENTS)
    print("Now listening at ", address)
    return s

class Hall:
    def __init__(self):
        self.rooms = {} # {room_name: Room}
        self.room_player_map = {} # {playerName: roomName}
        self.players = [] # a list of sockets

    def welcome_new(self, new_player):
        new_player.socket.sendall(b'Welcome to pychat.\nPlease tell us your name:\n')

    def list_rooms(self, player):
        msg = ""
        for pl in self.players:
            msg += str(pl.name)+'\n' 	
        if len(self.rooms) == 0:
            msg =msg + 'No active rooms currently. Create your own!\n' \
                + 'Use [<join> room_name] to create a room.\n'
            player.socket.sendall(msg.encode())
        else:
            msg = msg + 'Listing current rooms...\n'
            for room in self.rooms:
                msg+=room+": "
                for play in self.rooms[room].players:
                    msg +=str(play.name)+"  "
                msg +="\n"
            player.socket.sendall(msg.encode())

    def broadcast(self, from_player, msg):
        msg = from_player.name.encode() + b":" + msg
        for player in self.players:
            player.socket.sendall(msg)

    def handle_msg(self, player, msg):
        
        instructions = b'Instructions:\n'\
            + b'[list] to list all rooms\n'\
            + b'[broadcast message] to send message to every one\n' \
            + b'[send name message] to send message for name\n' \
            + b'[join room_name] to join/create/switch to a room\n' \
            + b'[manual] to show instructions\n' \
            + b'[quit] to quit\n' \
            + b'\n'

        print(player.name + " says: " + msg)
        if "name:" in msg:
            name = msg.split()[1]
            pas = msg.split()[2]
            if pas==account[name]:
                if account_type[name]==0:
                    account_type[name]=1
                    player.name = name
                    print("New connection from:", player.name)
                    self.players.append(player)
                    player.socket.sendall(instructions)
                    player.socket.sendall(account_off_message[name].encode())
                    account_off_message[name]=''
                else:
                    player.socket.sendall(b'The account is login now.')
            else:
                player.socket.sendall(b'error_pass')

        elif "broadcast" in msg:
            b_msg=''
            if len(msg.split())>=2:
                for i in range(1,len(msg.split())):
                    b_msg+=msg.split()[i]+' '
                b_msg+='\n'
                self.broadcast(player,b_msg.encode())
            else:
                player.socket.sendall(instructions)
        elif "send" in msg:
            re_msg=''
            flag='N'
            if len(msg.split()) >=2:
                talkname = msg.split()[1]
                if talkname in account_name:
                    if account_type[talkname]==1:
                        for tkname in self.players:
                            if talkname == tkname.name:
                                re_msg+=player.name+" give you a message: "
                                for i in range(2,len(msg.split())):
                                    re_msg+=msg.split()[i]+' '
                                re_msg+="\n"
                                tkname.socket.sendall(re_msg.encode())
                                player.socket.sendall('send successfully.\n'.encode())
                                flag='Y'
                                break
                        if flag == 'N':
                            player.socket.sendall('no this people.\n'.encode())
                    else:
                        re_msg+=player.name+" give you a message: "
                        for i in range(2,len(msg.split())):
                            re_msg+=msg.split()[i]+' '
                        re_msg+="\n"
                        account_off_message[talkname]+=re_msg
                        player.socket.sendall('message send successfully.\n'.encode())
                else:
                    player.socket.sendall('no this people.\n'.encode())
            else:
                player.socket.sendall('format error: send name message\n'.encode())			
        elif "join" in msg:
            same_room = False
            if len(msg.split()) >= 2: # error check
                room_name = msg.split()[1]
                if player.name in self.room_player_map: # switching?
                    if self.room_player_map[player.name] == room_name:
                        player.socket.sendall(b'You are already in room: ' + room_name.encode())
                        same_room = True
                    else: # switch
                        old_room = self.room_player_map[player.name]
                        self.rooms[old_room].remove_player(player)
                if not same_room:
                    if not room_name in self.rooms: # new room:
                        new_room = Room(room_name)
                        self.rooms[room_name] = new_room
                    self.rooms[room_name].players.append(player)
                    self.rooms[room_name].welcome_new(player)
                    self.room_player_map[player.name] = room_name
            else:
                player.socket.sendall(instructions)

        elif "list" in msg:
            self.list_rooms(player) 

        elif "manual" in msg:
            player.socket.sendall(instructions)
        
        elif "quit" in msg:
            account_type[player.name]=0
            self.players.remove(player)
            player.socket.sendall(QUIT_STRING.encode())
            self.remove_player(player)

        else:
            # check if in a room or not first
            if player.name in self.room_player_map:
                self.rooms[self.room_player_map[player.name]].broadcast(player, msg.encode())
            else:
                msg = 'You are currently not in any room! \n' \
                    + 'Use [<list>] to see available rooms! \n' \
                    + 'Use [<join> room_name] to join a room! \n'
                player.socket.sendall(msg.encode())
    
    def remove_player(self, player):
        if player.name in self.room_player_map:
            self.rooms[self.room_player_map[player.name]].remove_player(player)
            del self.room_player_map[player.name]
        print("Player: " + player.name + " has left\n")

    
class Room:
    def __init__(self, name):
        self.players = [] # a list of sockets
        self.name = name

    def welcome_new(self, from_player):
        msg = self.name + " welcomes: " + from_player.name + '\n'
        for player in self.players:
            player.socket.sendall(msg.encode())
    
    def broadcast(self, from_player, msg):
        msg = from_player.name.encode() + b":" + msg
        for player in self.players:
            player.socket.sendall(msg)

    def remove_player(self, player):
        self.players.remove(player)
        leave_msg = player.name.encode() + b"has left the room\n"
        self.broadcast(player, leave_msg)

class Player:
    def __init__(self, socket, name = "new"):
        socket.setblocking(0)
        self.socket = socket
        self.name = name

    def fileno(self):
        return self.socket.fileno()
