# import cryptography.fernet
import time
import socket
import sys
import PyQt5.QtCore
import PyQt5.QtWidgets
import PyQt5.QtGui

PORT = 2269
# key = b'wLqvJ-t5SCJevQDjyRVZmbi2YOrD6e4SC4iC2R_2G2k='
# F = cryptography.fernet.Fernet(key)

ENCODING = 'utf-8'
HEADER_SIZE = 20
BOLD_FONT = PyQt5.QtGui.QFont()
BOLD_FONT.setBold(True)


def bytes_to_list(data):
    string_data = data.decode(ENCODING)
    string_data = string_data[1:-1]
    string_data = string_data.replace("'", '')
    return string_data.split(', ')


def process_msg(msg):
    if type(msg) == str:
        msg = bytes(msg, ENCODING)

    # encrypted = F.encrypt(msg)
    header = bytes(f'{len(msg):<{HEADER_SIZE}}',
                   ENCODING)
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
        print(total_bytes_received, '/', msglen)
    # decrypted = F.decrypt(client_response)
    return client_response


class NicknameAlreadyTaken(Exception):
    pass


class BannedFromServer(Exception):
    pass


class AcceptFileDialog(PyQt5.QtWidgets.QDialog):
    def __init__(self, title, msg, file_name, parent=None):
        super().__init__(parent=parent)
        self.setWindowTitle(title)
        self.file_name = file_name
        self.msg = msg
        self.setStyleSheet('background-color:#0F0F0F;color:#FFFFFF')
        self.answer = None
        self.init_ui()

    def init_ui(self):
        self.layout = PyQt5.QtWidgets.QVBoxLayout()

        self.msg_label = PyQt5.QtWidgets.QLabel(self.msg)
        self.layout.addWidget(self.msg_label)

        self.file_label = PyQt5.QtWidgets.QLabel(self.file_name)
        self.layout.addWidget(self.file_label)
        self.file_label.setStyleSheet('background-color:#1F1F1F')

        self.button_layout = PyQt5.QtWidgets.QHBoxLayout()

        self.no_button = PyQt5.QtWidgets.QPushButton('No')
        self.no_button.clicked.connect(self.no_clicked)
        self.button_layout.addWidget(self.no_button)

        self.yes_button = PyQt5.QtWidgets.QPushButton('Yes')
        self.yes_button.clicked.connect(self.yes_clicked)
        self.button_layout.addWidget(self.yes_button)

        self.layout.addLayout(self.button_layout)
        self.setLayout(self.layout)

    def no_clicked(self):
        self.answer = False
        self.accept()

    def yes_clicked(self):
        self.answer = True
        self.accept()

    def return_answer(self):
        return self.answer

    @staticmethod
    def get_answer(title, msg, file_name, parent=None):
        dialog = AcceptFileDialog(title, msg, file_name, parent=parent)
        dialog.exec_()
        return dialog.return_answer()


class SelectClientDialog(PyQt5.QtWidgets.QDialog):
    def __init__(self, title, iterable, parent=None):
        super().__init__(parent=parent)
        self.setWindowTitle(title)
        self.iterable = iterable
        self.setStyleSheet('background-color:#0F0F0F;color:#FFFFFF')
        self.init_ui()

    def init_ui(self):
        self.layout = PyQt5.QtWidgets.QVBoxLayout()
        self.list = PyQt5.QtWidgets.QListWidget()
        self.list.addItems(self.iterable)
        self.list.setSelectionMode(
            PyQt5.QtWidgets.QAbstractItemView.ExtendedSelection)
        self.list.setStyleSheet('background-color:#1F1F1F')
        self.layout.addWidget(self.list)

        self.ok_button = PyQt5.QtWidgets.QPushButton('OK')
        self.ok_button.clicked.connect(self.accept)
        self.layout.addWidget(self.ok_button)

        self.setLayout(self.layout)

    def return_selected(self):
        return [item.text() for item in self.list.selectedItems()]

    @staticmethod
    def get_selected(title, iterable, parent=None):
        dialog = SelectClientDialog(title, iterable, parent=parent)
        dialog.exec_()
        return dialog.return_selected()


class ReceiveThread(PyQt5.QtCore.QThread):
    add_line = PyQt5.QtCore.pyqtSignal(bytes)
    ban = PyQt5.QtCore.pyqtSignal()
    kick = PyQt5.QtCore.pyqtSignal()
    got_client_list = PyQt5.QtCore.pyqtSignal(bytes)
    received_file_offer = PyQt5.QtCore.pyqtSignal(bytes)
    received_file = PyQt5.QtCore.pyqtSignal(bytes, bytes)

    def __init__(self, s):
        super().__init__()
        self.s = s

    def run(self):
        running = True
        client_list_response = False
        receiving_file_offer = 0
        receiving_file = 0
        file_name = b''
        file_data = b''
        while running:
            try:
                header = int(self.s.recv(HEADER_SIZE).decode(
                    ENCODING))
            except ConnectionResetError:
                running = False
            except (ConnectionAbortedError, OSError, ValueError):
                continue
            if running:
                received_msg = receive(self.s, header)
                if receiving_file_offer == 1:
                    file_name = received_msg
                    self.received_file_offer.emit(file_name)
                    receiving_file_offer = 0
                    continue
                if receiving_file == 1:
                    file_data = received_msg
                    self.received_file.emit(file_name, file_data)
                    receiving_file = 0
                    continue

                decoded = received_msg.decode(ENCODING)
                if client_list_response:
                    self.got_client_list.emit(received_msg)
                    client_list_response = False
                    continue
                if decoded == '[_SPECIALBANHEADER_]':
                    self.ban.emit()
                    return
                elif decoded == '[_USERKICKEDHEADER_]':
                    self.kick.emit()
                    return
                elif decoded == '[_CLIENTLISTRESPONSE_]':
                    client_list_response = True
                    continue
                elif decoded == '[_FILEOFFER_]':
                    receiving_file_offer = 1
                    continue
                elif decoded == '[_FILETRANSFER_]':
                    receiving_file = 1
                    continue
                self.add_line.emit(received_msg)
        return


class MainWindow(PyQt5.QtWidgets.QMainWindow):
    BOLD_CHAR_FORMAT = PyQt5.QtGui.QTextCharFormat()
    BOLD_CHAR_FORMAT.setFontWeight(PyQt5.QtGui.QFont.Bold)

    DEFAULT_CHAR_FORMAT = PyQt5.QtGui.QTextCharFormat()

    def __init__(self, controller, title, server_host, s):
        super().__init__()
        self.s = s
        self.controller = controller
        self.setStyleSheet('background-color:#0F0F0F;color:#FFFFFF')
        self.receive_thread = ReceiveThread(self.s)
        self.receive_thread.add_line.connect(self.add_line)
        self.receive_thread.ban.connect(self.banned)
        self.receive_thread.kick.connect(self.kicked)
        self.receive_thread.got_client_list.connect(self.set_client_list)
        self.receive_thread.received_file_offer.connect(self.file_offer)
        self.receive_thread.received_file.connect(self.received_file)
        self.receive_thread.start()

        self.client_list = []

        self.server_host = server_host
        self.setWindowTitle(title)
        self.initiate_ui()

    def set_client_list(self, data):
        self.client_list = bytes_to_list(data)
        path = PyQt5.QtWidgets.QFileDialog.getOpenFileName()
        if path[0] != '':
            file_path = path[0]
        else:
            return
        self.send_to_server('[_FILETRANSFER_]')
        target_clients = self.choose_clients()
        self.send_to_server(str(target_clients))
        self.send_to_server(file_path.split('/')[-1])
        self.send_to_server(open(file_path, 'rb').read())

    def received_file(self, file_name, data):
        with open(file_name, 'wb') as file:
            file.write(data)

    def file_offer(self, file_name):
        file_name = file_name.decode(ENCODING)
        answer = AcceptFileDialog.get_answer('Gelen Dosya',
                                             'Bir kullanıcı size bu dosyayı '
                                             + 'gönderdi. İndirmek istiyor '
                                             + 'musunuz?', file_name)
        if answer:
            self.send_to_server(f'[_REQUESTFILE_]{file_name}')

    def choose_clients(self):
        return SelectClientDialog.get_selected('Kullanıcı Seç',
                                               self.client_list)

    def request_client_list(self):
        self.send_to_server('[_CLIENTLISTREQ_]')

    def initiate_ui(self):
        self.layout = PyQt5.QtWidgets.QGridLayout()

        self.info_label = PyQt5.QtWidgets.QLabel(
            f"{self.server_host}'ya bağlısın")
        self.layout.addWidget(self.info_label, 0, 0)

        self.text_area = PyQt5.QtWidgets.QTextEdit()
        self.text_area.setFocusPolicy(PyQt5.QtCore.Qt.NoFocus)
        self.text_area.setStyleSheet('background-color:#1F1F1F')
        self.layout.addWidget(self.text_area, 1, 0)

        self.bottom_layout = PyQt5.QtWidgets.QHBoxLayout()

        self.type_bar = PyQt5.QtWidgets.QLineEdit()
        self.type_bar.returnPressed.connect(self.type_enter)
        self.type_bar.setStyleSheet('background-color:#1F1F1F')
        self.bottom_layout.addWidget(self.type_bar)

        self.file_transfer_button = PyQt5.QtWidgets.QPushButton()
        self.file_transfer_button.setStyleSheet('background-color:#1F1F1F')
        self.file_transfer_button.clicked.connect(self.request_client_list)
        self.bottom_layout.addWidget(self.file_transfer_button)

        self.layout.addLayout(self.bottom_layout, 2, 0)

        w = PyQt5.QtWidgets.QWidget()
        w.setLayout(self.layout)
        self.setCentralWidget(w)

    def add_line(self, msg):
        if type(msg) == bytes:
            msg = msg.decode(ENCODING)
        nickname, msg = msg.split('>')
        self.text_area.setCurrentCharFormat(self.BOLD_CHAR_FORMAT)
        self.text_area.append(nickname)
        self.text_area.setCurrentCharFormat(self.DEFAULT_CHAR_FORMAT)
        self.text_area.append(msg)

    def banned(self):
        PyQt5.QtWidgets.QMessageBox.warning(self, 'Girmen Yasak!',
                                            'Bu sunucuya girmen yasaklandı.'
                                            + ' Admin yasağını kaldırana'
                                            + ' kadar sunucuya giremezsin',
                                            PyQt5.QtWidgets.QMessageBox.Ok)
        self.controller.to_server_select()

    def kicked(self):
        PyQt5.QtWidgets.QMessageBox.warning(self, 'Atıldın!',
                                            'Bu sunucudan atıldın.'
                                            + ' Tekrar bağlanabilirsin',
                                            PyQt5.QtWidgets.QMessageBox.Ok)
        self.controller.to_server_select()

    def send_to_server(self, data):
        self.s.send(process_msg(data))

    def type_enter(self):
        self.send_to_server(self.type_bar.text())
        self.type_bar.setText('')


class ServerSelectWindow(PyQt5.QtWidgets.QMainWindow):
    def __init__(self, controller, title, s):
        super().__init__()
        self.s = s
        self.setStyleSheet('background-color:#0F0F0F;color:#FFFFFF')
        self.controller = controller
        self.server_host = None
        self.setWindowTitle(title)
        self.initiate_ui()

    def initiate_ui(self):
        self.layout = PyQt5.QtWidgets.QVBoxLayout()

        self.server_ip_label = PyQt5.QtWidgets.QLabel('Sunucu IP: ')
        self.layout.addWidget(self.server_ip_label)

        self.server_ip_line_edit = PyQt5.QtWidgets.QLineEdit()
        self.server_ip_line_edit.returnPressed.connect(self.enter)
        self.server_ip_line_edit.setStyleSheet('background-color:#1F1F1F')

        self.layout.addWidget(self.server_ip_line_edit)

        self.nickname_label = PyQt5.QtWidgets.QLabel('Nickname: ')
        self.layout.addWidget(self.nickname_label)

        self.nickname_line_edit = PyQt5.QtWidgets.QLineEdit()
        self.nickname_line_edit.setStyleSheet('background-color:#1F1F1F')

        self.nickname_line_edit.returnPressed.connect(self.enter)

        self.layout.addWidget(self.nickname_line_edit)

        self.msg_label = PyQt5.QtWidgets.QLabel()
        self.msg_label.setFont(BOLD_FONT)
        self.layout.addWidget(self.msg_label)

        w = PyQt5.QtWidgets.QWidget()
        w.setLayout(self.layout)
        self.setCentralWidget(w)

    def show_msg(self, msg):
        self.msg_label.setText(msg)

    def get_server_host(self):
        return self.server_host

    def connect_to_server(self, address):
        host, port = address
        self.s.connect((host, port))
        self.s.send(process_msg(
            bytes(self.nickname_line_edit.text(), ENCODING)))
        msglen = int(self.s.recv(HEADER_SIZE).decode(
            ENCODING))
        response = receive(self.s, msglen)
        decoded = response.decode(ENCODING)
        if decoded == '[_NICKALREADYTAKEN_]':
            self.s = socket.socket()
            raise NicknameAlreadyTaken
        elif decoded == '[_USERBANNEDFROMSR_]':
            self.s = socket.socket()
            raise BannedFromServer
        elif decoded == '[_CNACCEPTEDHEADER_]':
            pass
        else:
            raise ConnectionRefusedError

    def enter(self):
        try:
            self.connect_to_server((self.server_ip_line_edit.text(), PORT))
            self.server_host = self.server_ip_line_edit.text()
            self.controller.to_main()
        except ConnectionRefusedError:
            self.show_msg(
                f'{self.server_ip_line_edit.text()} bağlantıyı reddetti')
        except BannedFromServer:
            self.show_msg('Bu sunucuya girmen yasak.')
        except NicknameAlreadyTaken:
            self.show_msg(
                f'{self.nickname_line_edit.text()} ismi çoktan alınmış')
        except socket.gaierror:
            self.show_msg(
                f'{self.server_ip_line_edit.text()} bir IP adresi değil')


class Controller:
    def __init__(self):
        self.server_select = None
        self.main_window = None
        self.to_server_select()

    def to_server_select(self):
        try:
            self.main_window.close()
        except AttributeError:
            pass
        self.s = socket.socket()
        self.server_select = ServerSelectWindow(
            self, 'Select Server', self.s)
        self.server_select.show()

    def to_main(self):
        try:
            self.server_select.close()
        except AttributeError:
            pass
        self.main_window = MainWindow(
            self, 'Chatroom', self.server_select.get_server_host(),
            self.server_select.s)
        self.main_window.show()


if __name__ == "__main__":
    app = PyQt5.QtWidgets.QApplication(sys.argv)
    app.setStyle('Fusion')
    controller = Controller()

    app.exec_()
