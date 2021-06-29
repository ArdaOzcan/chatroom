# import cryptography.fernet
import time
import socket
import sys
import PyQt5.QtCore
import PyQt5.QtWidgets
import PyQt5.QtGui
import threading
import colorama


class Header:
    BAN = '[_SPECIALBANHEADER_]'
    KICK = '[_USERKICKEDHEADER_]'
    FILE_TRANSFER = '[_FILETRANSFER_]'
    NICK_TAKEN = '[_NICKALREADYTAKEN_]'
    CONNECTION_ACCEPTED = '[_CNACCEPTEDHEADER_]'
    BANNED = '[_USERBANNEDFROMSR_]'
    CLIENT_LIST_REQUEST = '[_CLIENTLISTREQ_]'
    CLIENT_LIST_RESPONSE = '[_CLIENTLISTRESPONSE_]'
    FILE_OFFER = '[_FILEOFFER_]'
    FILE_REQUEST = '[_REQUESTFILE_]'


TERM = False

# key = b'wLqvJ-t5SCJevQDjyRVZmbi2YOrD6e4SC4iC2R_2G2k='
# F = cryptography.fernet.Fernet(key)
ENCODING = 'utf-8'
HEADER_SIZE = 20
SHELL_PROMPT = 'shell'
PORT = 2269

BOLD_FONT = PyQt5.QtGui.QFont()
BOLD_FONT.setBold(True)


def bytes_to_list(data):
    string_data = data.decode(ENCODING)
    string_data = string_data[1:-1]
    string_data = string_data.replace("'", '')
    return string_data.split(', ')


def run_server(host, headers):
    Server(PORT, headers, True, host=host)


def process_msg(msg):
    if type(msg) == str:
        msg = bytes(msg, ENCODING)

    # encrypted = F.encrypt(msg)
    header = bytes(f'{len(msg):<{HEADER_SIZE}}', ENCODING)
    full_msg = header + msg

    return full_msg


def receive(conn, msglen):
    total_bytes_received = 0
    client_response = b''
    chunk = 2048

    while total_bytes_received < msglen:
        if msglen - total_bytes_received < chunk:
            client_response += conn.recv(msglen - total_bytes_received)
            total_bytes_received = msglen
        else:
            client_response += conn.recv(chunk)
            total_bytes_received += chunk
            time.sleep(0.00075)
    # decrypted = F.decrypt(client_response)
    return client_response


class Output:
    colors_dict = {
        'info': colorama.Fore.YELLOW,
        'warning': colorama.Fore.RED,
        'error': colorama.Fore.RED,
        'response': colorama.Fore.GREEN
    }

    colorama.init(autoreset=True)

    @classmethod
    def out(cls, key, msg, prompt=True, start='\n', end='\n'):
        if prompt:
            print(cls.colors_dict[key] +
                  f'{start}{key.upper()}: {msg}', end=end)
        else:
            print(cls.colors_dict[key] + f'{start}{msg}', end=end)

    @classmethod
    def info(cls, msg, prompt=True, start='\n', end='\n'):
        cls.out('info', msg, prompt=prompt, start=start, end=end)

    @classmethod
    def warning(cls, msg, prompt=True, start='\n', end='\n'):
        cls.out('warning', msg, prompt=prompt, start=start, end=end)

    @classmethod
    def error(cls, msg, prompt=True, start='\n', end='\n'):
        cls.out('error', msg, prompt=prompt, start=start, end=end)

    @classmethod
    def response(cls, msg, start='\n', end='\n'):
        cls.out('response', msg, prompt=False, start=start, end=end)

    @classmethod
    def ask(cls, action):
        cls.warning(
            f'Are you sure you want to {action}? (y/n): ', start='', end='')
        answer = input()
        if answer == 'y':
            return True
        return False

    @classmethod
    def aligned(cls, string, length, filler=' '):
        filler_length = (length - len(string)) // 2
        result = (filler * filler_length
                  + string
                  + filler * filler_length)

        return result

    @classmethod
    def list_values(cls, title, captions,
                    values, empty_msg='No values found'):
        if values:
            cls.info(
                cls.aligned(title, 16*(len(values[0])+1), filler='-'),
                prompt=False)

            final_caption = ''
            for cap in captions:
                final_caption += f'{cap:<{16}}'
            cls.info(final_caption,
                     prompt=False)
            for i, v in enumerate(values):
                final_values = f'{i:<{16}}'

                for val in v:
                    final_values += f'{val:<{16}}'
                cls.info(final_values,
                         prompt=False,
                         start='')
        else:
            cls.info(empty_msg, start='')


class Client:
    def __init__(self, conn, address, nickname):
        self.conn = conn
        self.address = address
        self.nickname = nickname

    def get_attributes(self):
        return [self.address[0], self.address[1], self.nickname]

    def ban(self, server):
        server.ban_list.append((self.address[0], self.nickname))
        self.conn.send(process_msg(server.headers.BAN))
        time.sleep(0.5)
        self.conn.close()
        server.broadcast('server', f"{self.nickname}'nin bu sunucuya"
                         + ' girmesi yasaklandı')

    def kick(self, server):
        self.conn.send(process_msg(server.headers.KICK))
        time.sleep(0.5)


class UploadedFile:
    hashed_list = {}

    def __init__(self, server, allowed_clients, file_name, data):
        self.allowed_clients = allowed_clients
        self.server = server
        self.file_name = file_name
        self.export(data)
        del data
        self.offer()

    def export(self, data):
        with open(self.file_name, 'wb') as file:
            file.write(data)

    def offer(self):
        for c in self.allowed_clients:
            threading.Thread(target=self.server.offer_file,
                             args=(c, self.file_name)).start()

    @property
    def data(self):
        return open(self.file_name, 'rb').read()

    @classmethod
    def add(cls, server, allowed_clients, file_name, data):
        file = cls(server, allowed_clients, file_name, data)
        cls.hashed_list[file_name.decode(ENCODING)] = file


class Server:
    def __init__(self, port, headers,
                 outputs=False, host=None, listen_amount=5):
        self.headers = headers
        self.clients = []
        self.ban_list = []
        self.admin_client = None

        if host is None:
            self.host = socket.gethostbyname(socket.gethostname())
        else:
            self.host = host

        self.listen_amount = listen_amount

        self.outputs = outputs
        self.port = port
        Output.info(f'Initiated server in port {self.port}', start='')

        self.create_socket()
        self.shell()

    def create_socket(self):
        try:
            self.s = socket.socket()
            self.s.bind((self.host, self.port))
            if self.outputs:
                Output.info(
                    f'Binding socket {(self.host, self.port)}', start='')
                Output.info(f'Listening {self.listen_amount}', start='')

            self.s.listen(self.listen_amount)
            connection_listener = threading.Thread(
                target=self.accept_connection)
            connection_listener.daemon = True
            connection_listener.start()

        except socket.error:
            Output.warning(
                f'Could not create the socket, probably port {self.port}'
                + ' is already in use', start='')
            Output.info('Press [ENTER] to try again')
            if not input():
                self.create_socket()

    def list_clients(self):
        captions = ['Index', 'IP', 'Port', 'Nickname']
        Output.list_values('Clients', captions, [
            c.get_attributes() for c in self.clients])

    def list_ban_list(self):
        captions = ['Index', 'IP', 'Nickname']
        Output.list_values('Clients', captions, [c for c in self.ban_list])

    def shell(self):
        global receive_thread
        global controller

        print(f'{SHELL_PROMPT}> ', end='')
        cmd = input()
        args = cmd.split(' ')
        if cmd == 'terminate':
            if Output.ask('terminate the server'):
                Output.info('Server terminated', start='')
                receive_thread.s.close()
                controller.main_window.close()
                self.s.close()
                sys.exit(0)
        elif cmd == 'thread':
            Output.info(threading.active_count(), start='')
        elif cmd == 'list':
            self.list_clients()
        elif cmd.startswith('ban '):
            if args[1] == 'all':
                for c in self.clients:
                    self.ban_list.append((c.address[0], c.nickname))
                    c.conn.send(process_msg(self.headers.BAN))

                for _ in range(len(self.clients)):
                    self.clients[0].conn.close()

            else:
                c = self.clients[int(args[1])]
                c.ban(self)
        elif cmd.startswith('kick '):
            c = self.clients[int(args[1])]
            c.kick(self)
            c.conn.close()
        elif cmd == 'banlist':
            self.list_ban_list()
        elif cmd.startswith('unban '):
            if args[1] == 'all':
                self.ban_list = []
            else:
                self.broadcast(
                    'server', f'{self.ban_list[int(args[1])]}'
                    + ' has been unbanned')
                self.ban_list.pop(int(args[1]))

        self.shell()

    def accept_connection(self):
        while True:
            try:
                conn, address = self.s.accept()
            except OSError:
                break

            msglen = int(conn.recv(HEADER_SIZE).decode(ENCODING))
            nickname = str(receive(conn, msglen), ENCODING)
            client = Client(conn, address, nickname)
            accepted = True

            for c in self.clients:
                if (c.nickname == nickname or nickname == 'server'):
                    conn.send(process_msg(self.headers.NICK_TAKEN))
                    accepted = False
            if self.admin_client is not None and nickname == 'admin':
                conn.send(process_msg(self.headers.NICK_TAKEN))
                accepted = False
            if nickname == 'admin':
                self.admin_client = client
            if address[0] in [x[0] for x in self.ban_list]:
                conn.send(process_msg(self.headers.BANNED))
                accepted = False
            if not accepted:
                conn.close()
                continue
            conn.send(process_msg(self.headers.CONNECTION_ACCEPTED))
            Output.info(nickname + ' joined', start='')

            Output.info(
                f'Connection has been established with {address}', start='')
            print(f'{SHELL_PROMPT}> ', end='')
            self.on_accept(client)
        return

    def on_accept(self, client):
        if client.nickname != 'admin':
            self.clients.append(client)
        self.broadcast('server', f'{client.nickname} sunucuya katıldı')
        thread = threading.Thread(target=self.client_thread,
                                  args=(client,))
        thread.start()

    def broadcast(self, nickname, msg):
        if type(nickname) == str:
            nickname = bytes(nickname, ENCODING)
        if type(msg) == str:
            msg = bytes(msg, ENCODING)
        for c in self.clients:
            c.conn.send(process_msg(nickname + b'> ' + msg))
        self.admin_client.conn.send(
            process_msg(nickname + b'> ' + msg))

    def send_file(self, client, file_name, data):
        client.conn.send(process_msg(self.headers.FILE_TRANSFER))
        # client.conn.send(process_msg(file_name))
        client.conn.send(process_msg(data))
        return

    def offer_file(self, client, file_name):
        client.conn.send(process_msg(self.headers.FILE_OFFER))
        client.conn.send(process_msg(file_name))
        return

    def client_thread(self, client):
        running = True
        file_transfer_stage = 0
        file_transfer_targets = []
        file_name = 'received_file'
        while running:
            try:
                msglen = int(client.conn.recv(HEADER_SIZE).decode(ENCODING))

            except (ConnectionResetError, ValueError,
                    ConnectionAbortedError, OSError):
                self.remove(client)
                running = False
            if running:
                received_msg = receive(client.conn, msglen)
                if file_transfer_stage == 3:
                    UploadedFile.add(self, file_transfer_targets,
                                     file_name, received_msg)

                    file_transfer_stage = 0
                    continue

                decoded = received_msg.decode(ENCODING)

                if decoded.startswith(self.headers.FILE_REQUEST):
                    file_name = decoded[len(self.headers.FILE_REQUEST):]
                    file = UploadedFile.hashed_list[file_name]
                    if client in file.allowed_clients:
                        self.send_file(client, file.file_name, file.data)
                    continue

                if file_transfer_stage == 2:
                    file_name = received_msg
                    file_transfer_stage = 3
                    continue

                if file_transfer_stage == 1:
                    targets = bytes_to_list(received_msg)
                    file_transfer_targets = []
                    clients_dict = {c.nickname: c for c in self.clients}
                    for target in targets:
                        if target in clients_dict:
                            file_transfer_targets.append(clients_dict[target])
                    file_transfer_stage = 2
                    continue

                if decoded == self.headers.CLIENT_LIST_REQUEST:
                    nick_list = []
                    for c in self.clients:
                        if c != client:
                            nick_list.append(c.nickname)
                    client.conn.send(process_msg(
                        self.headers.CLIENT_LIST_RESPONSE))
                    client.conn.send(process_msg(str(nick_list)))
                    continue

                if (decoded == self.headers.FILE_TRANSFER
                        and file_transfer_stage == 0):
                    file_transfer_stage = 1
                    continue

                self.broadcast(client.nickname, received_msg)
        return

    def remove(self, client):
        try:
            self.clients.remove(client)
            Output.info(
                f'Connection was reset with {client.address},'
                + ' removed from the list',
                end='\n')
            self.broadcast('server', f'{client.nickname} sunucudan ayrıldı')
        except ValueError:
            pass


class ReceiveThread(PyQt5.QtCore.QThread):
    add_line = PyQt5.QtCore.pyqtSignal(bytes)

    def __init__(self, s, headers):
        super().__init__()
        self.s = s
        self.headers = headers

    def run(self):
        running = True
        while running:
            try:
                header = int(self.s.recv(HEADER_SIZE).decode(ENCODING))
            except (ConnectionResetError, OSError):
                running = False
            except ValueError:
                continue
            if running:
                received_msg = receive(self.s, header)
                decoded = received_msg.decode(ENCODING)
                if (decoded == headers.BAN or
                        decoded == headers.KICK):
                    continue

                self.add_line.emit(received_msg)

        return


receive_thread = None


class AdminWindow(PyQt5.QtWidgets.QMainWindow):
    def __init__(self, controller, title, server_host, s, headers):
        global receive_thread
        super().__init__()
        self.s = s
        self.controller = controller
        self.setStyleSheet('background-color:#0F0F0F;color:#FFFFFF')
        receive_thread = ReceiveThread(self.s, headers)
        receive_thread.add_line.connect(self.add_line)
        receive_thread.start()

        self.server_host = server_host
        self.setWindowTitle(title)
        self.initiate_ui()

    def initiate_ui(self):
        self.layout = PyQt5.QtWidgets.QVBoxLayout()

        self.info_label = PyQt5.QtWidgets.QLabel(
            f"{self.server_host}'ya bağlısın")
        self.layout.addWidget(self.info_label)

        self.text_area = PyQt5.QtWidgets.QTextEdit()
        self.text_area.setFocusPolicy(PyQt5.QtCore.Qt.NoFocus)
        self.text_area.setStyleSheet('background-color:#1F1F1F')
        self.layout.addWidget(self.text_area)

        self.type_bar = PyQt5.QtWidgets.QLineEdit()
        self.type_bar.returnPressed.connect(self.type_enter)
        self.type_bar.setStyleSheet('background-color:#1F1F1F')
        self.layout.addWidget(self.type_bar)

        w = PyQt5.QtWidgets.QWidget()
        w.setLayout(self.layout)
        self.setCentralWidget(w)

    def add_line(self, msg):
        if type(msg) == bytes:
            msg = msg.decode(ENCODING)
        self.text_area.append(msg)

    def type_enter(self):
        self.s.send(process_msg(self.type_bar.text()))
        self.type_bar.setText('')


class Controller:
    def __init__(self, host, headers):
        self.headers = headers
        self.server_select = None
        self.main_window = None
        self.s = socket.socket()
        self.s.connect((host, PORT))
        self.s.send(process_msg(
            bytes('admin', ENCODING)))
        msglen = int(self.s.recv(HEADER_SIZE).decode(ENCODING))
        receive(self.s, msglen)
        self.to_main(host)

    def to_main(self, host):
        self.main_window = AdminWindow(
            self, 'Admin Paneli', host,
            self.s, headers)
        self.main_window.show()


server_thread = None
controller = None

if __name__ == "__main__":
    app = PyQt5.QtWidgets.QApplication(sys.argv)
    app.setStyle('Fusion')

    host = socket.gethostbyname(socket.gethostname())
    headers = Header()

    server_thread = threading.Thread(target=run_server, args=(host, headers))
    server_thread.setDaemon(True)
    server_thread.start()

    controller = Controller(host, headers)

    app.exec_()
