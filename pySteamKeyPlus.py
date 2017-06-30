import logging
import re
import gevent
from PyQt5.QtGui import QIcon
from steam import SteamClient
from steam.enums import EResult
from enumresult import EPurchaseResultDetail
from PyQt5.QtCore import  *
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QLineEdit, QLabel, QGridLayout, QAction, QWidget, QInputDialog, QMessageBox, \
    QPushButton, QHBoxLayout, QTableWidgetItem, QTableWidget, QHeaderView, QVBoxLayout, QTextEdit

class myThread (QThread):   #Thread
    loginInfo = pyqtSignal(int,str)
    regInfo = pyqtSignal(int,str,str)
    def __init__(self, parent=None):
        super(myThread, self).__init__(parent)
        self.needlogin = False
        self.needlogout = False
        self.needredeem = False
        self.LOGON_DETAILS = {
            'username': '',
            'password': '',
            'login_key':None,
            'auth_code':None,
            'two_factor_code':None,
        }
        self.gamekey = ''
        self.remNum = 0;


    def setAccount(self,usernmae,password,authmode=None,authcode=None):
        self.LOGON_DETAILS['username'] = usernmae
        self.LOGON_DETAILS['password'] = password
        if authmode =='mail':
            self.LOGON_DETAILS['auth_code'] = authcode
        if authmode =='2fa':
            self.LOGON_DETAILS['two_factor_code'] = authcode
        self.needlogin = True
    #return 990 not username
    #return 991 not password
    #return 992 need auth password
    #return 993 need mailauth
    #return 994 need a2f auth
    #retrun 995 server time out
    #return 996 login num more
    def login(self):
        if not self.LOGON_DETAILS['username']:
            self.loginInfo.emit(990,'')
            # username = _cli_input("Username: ")
            self.needlogin = False
            return '990'
        if not self.LOGON_DETAILS['password']:
            self.loginInfo.emit(991,'')
            self.needlogin = False
            return '991'

        auth_code = two_factor_code = None
        prompt_for_unavailable = True

        result = client.login(**self.LOGON_DETAILS)
        login_num = 0
        while result in (EResult.AccountLogonDenied, EResult.InvalidLoginAuthCode,
                         EResult.AccountLoginDeniedNeedTwoFactor, EResult.TwoFactorCodeMismatch,
                         EResult.TryAnotherCM, EResult.ServiceUnavailable,
                         EResult.InvalidPassword,
                         ):
            gevent.sleep(0.1)
            if login_num > 5:
                self.needlogin = False
                return

            if result == EResult.InvalidPassword:
                login_num += 1
                self.loginInfo.emit(992,'')
                self.needlogin = False
                return
            elif result == EResult.RateLimitExceeded:
                self.loginInfo.emit(996,'')
                self.needlogin = False
                return
            elif result == EResult.AccountLogonDenied or result ==  EResult.InvalidLoginAuthCode:
                login_num += 1
                self.loginInfo.emit(993,'')
                self.needlogin = False
                return

            elif result == EResult.AccountLoginDeniedNeedTwoFactor or result == EResult.TwoFactorCodeMismatch:
                login_num += 1
                self.loginInfo.emit(994,'')
                self.needlogin = False
                return

            elif result == EResult.TryAnotherCM or result == EResult.ServiceUnavailable:
                login_num += 1
                if prompt_for_unavailable and result == EResult.ServiceUnavailable:
                    self.loginInfo.emit(995,'')
                    self.needlogin = False
                    break
                return
        if result == EResult.OK:
            self.needlogin = False
            self.loginInfo.emit(999,client.steam_id.community_url)
            return result

    def setOut(self):
        self.needlogout = True
    def logout(self):
        print('logout')
        if client.connected:
            client.logout()
        self.needlogout = False
    def setKey(self,num,key,timer):
        self.remNum = num
        self.gamekey = key
        self.timer = timer
        self.needredeem = True
    def redeem(self):
        self.regnum = 0
        for itkey in self.gamekey:
            print('redeem')
            res = client.register_product_key(itkey)
            if str(res[2]) =='None':
                self.regInfo.emit(self.regnum,'None')
                self.needredeem = False
                return
            elif str(res[2]['ResultDetail'])=='0' or str(res[2]['ResultDetail'])=='9':
                self.regInfo.emit(self.regnum ,str(res[2]['ResultDetail']),str(res[2]['lineitems']['0']['ItemDescription']))
            else:
                self.regInfo.emit(self.regnum, str(res[2]['ResultDetail']),'')
            self.sleep(self.timer)
            self.regnum+=1
        self.needredeem = False



    def run(self):
        logging.basicConfig(format="%(asctime)s | %(message)s", level=logging.INFO)
        LOG = logging.getLogger()
        global client
        client = SteamClient()
        client.set_credential_location(".")  # where to store sentry files and other stuff

        @client.on("error")
        def handle_error(result):
            LOG.info("Logon result: %s", repr(result))
            if result == EResult.RateLimitExceeded:
                self.loginInfo.emit(996, '')
                self.needlogin = False

        @client.on("channel_secured")
        def send_login():
            if client.relogin_available:
                client.relogin()

        @client.on("connected")
        def handle_connected():
            LOG.info("Connected to %s", client.current_server_addr)

        @client.on("reconnect")
        def handle_reconnect(delay):
            LOG.info("Reconnect in %ds...", delay)

        @client.on("disconnected")
        def handle_disconnect():
            LOG.info("Disconnected.")
            if client.relogin_available:
                LOG.info("Reconnecting...")
                client.reconnect(maxdelay=30)

        # main bit
        LOG.info("Persistent logon recipe")
        LOG.info("-" * 30)
        while True:
            self.msleep(10)
            self.run_num = 0
            if self.needlogin:
                self.login()
            if self.needlogout:
                self.logout()
            if self.needredeem:
                self.redeem()


class MainWindow(QtWidgets.QMainWindow):
    no_login_once_flag = True

    def __init__(self, parent=None):
        QtWidgets.QMainWindow.__init__(self)
        self.setWindowTitle(self.tr('SteamKeyRedeem Powerby:Knva'))
        self.statusBar().showMessage(self.tr('Ready'))
        self.setWindowIcon(QIcon('icon.png'))  # 图标的位置
        self.mainWid = QWidget()
        self.userlabel = QLabel(self.tr('User:'))
        self.passwdlabel = QLabel(self.tr('PassWord:'))
        self.userEdit = QLineEdit()
        self.passwdEdit = QLineEdit()
        self.passwdEdit.setEchoMode(QtWidgets.QLineEdit.Password)

        self.userUrlLabel =QLabel(self.tr('SteamUri:'))
        self.userUrlLink = QLabel('')
        self.userUrlLabel.setHidden(True)
        self.userUrlLink.setHidden(True)

        self.lgbtn = QPushButton(self.tr('Login Now'))
        self.lgbtn.clicked.connect(self.setUsPs)

        self.regbtn = QPushButton(self.tr('Reg Key!'))
        self.regbtn.setHidden(True)
        self.regbtn.clicked.connect(self.showKeyDialog)

        self.grid = QGridLayout()
        self.grid.setSpacing(10)

        self.grid.addWidget(self.userlabel, 1, 0)
        self.grid.addWidget(self.userEdit, 1, 1)
        self.grid.addWidget(self.passwdlabel, 2, 0)
        self.grid.addWidget(self.passwdEdit, 2, 1)
        self.grid.addWidget(self.userUrlLabel, 3, 0)
        self.grid.addWidget(self.userUrlLink, 3, 1)
        self.grid.addWidget(self.lgbtn, 4, 1)
        self.grid.addWidget(self.regbtn,5,1)

        self.mainWid.setLayout(self.grid)
        self.setCentralWidget(self.mainWid)
        self.resize(320, 140)
        self.login = QAction(self.tr('Login'), self)
        self.login.setShortcut('Ctrl+L')
        self.login.setStatusTip(self.tr('Login Steam'))
        self.login.triggered.connect(self.setUsPs)

        self.logout = QAction(self.tr('Logout'),self)
        self.logout.setStatusTip(self.tr('Logout Steam'))
        self.logout.triggered.connect(self.logoutSteam)
        self.logout.setEnabled(False)

        self.reg = QAction(self.tr('Regkey'),self)
        self.reg.setShortcut("Ctrl+R")
        self.reg.setStatusTip(self.tr("Redeem Steam Key"))
        self.reg.triggered.connect(self.showKeyDialog)


        self.exit = QAction(self.tr('Exit'), self)
        self.exit.setShortcut('Ctrl+Q')
        self.exit.setStatusTip(self.tr('Exit application'))
        self.exit.triggered.connect(self.close)
        self.statusBar()

        self.menubar = self.menuBar()
        self.file = self.menubar.addMenu(self.tr('&File'))
        self.Regkey = self.menubar.addMenu(self.tr("&RegKey"))
        self.file.addAction(self.login)
        self.file.addAction(self.logout)
        self.file.addAction(self.exit)
        self.Regkey.addAction(self.reg)
        self.passwdEdit.returnPressed.connect(self.setUsPs)

        self.thread1 = myThread()
        self.thread1.loginInfo.connect(self.loginSlot)
        self.thread1.start()

        self.app = MainPanel(self)
        self.app.regSin.connect(self.regKey)
        self.thread1.regInfo.connect(self.app.regSlot)
        with open('qss.qss', 'r') as q:
            self.setStyleSheet(q.read())

    #return 990 not username
    #return 991 not password
    #return 992 need auth password
    #return 993 need mailauth
    #return 994 need 2fa auth
    #return 999 login ok
    def loginSlot(self,res,msg):
        info = ''
        mode = ''
        if res ==990:
            info =self.tr('Not UserName!')
        elif res ==991:
            info =self.tr('Not PassWord!')
        elif res ==992:
            info =self.tr('InvalidPassword! ')
        elif res ==995:
            info =self.tr('Steam Service Down! ')
        elif res ==996:
            info =self.tr('Too many Login! ')
        elif res ==999:
            info =self.tr('Login ok!')

            self.no_login_once_flag = False
            self.logout.setEnabled(True)
            self.login.setEnabled(False)
            self.lgbtn.setEnabled(False)
            self.userEdit.setText('%s'%'aa')
            self.userEdit.setEnabled(False)
            self.passwdlabel.setHidden(True)
            self.passwdEdit.setHidden(True)
            self.userUrlLabel.setHidden(False)
            self.userUrlLink.setHidden(False)
            self.lgbtn.setHidden(True)
            self.regbtn.setHidden(False)
            self.userUrlLink.setText("Link:<a href='%s'>%s</a>" % (msg, msg))
            self.userEdit.setText(msg.split('/')[-1])

        if info:
            self.showinfoMsg(info)
        if res ==993:
            info =self.tr('Please Input your mail code!')
            mode = 'mail'
        if res ==994:
            info =self.tr('Please Input your 2fa code!')
            mode ='2fa'
        if mode:
            self.showAuthDialog(mode,info)


    def setUsPs(self,codemode=None,code=None):
        self.thread1.setAccount(self.userEdit.text(), self.passwdEdit.text(),codemode,code)

    def showinfoMsg(self,msg):
        OK = QMessageBox.information(self, (self.tr("Redeem")), ("%s" % msg),
                                     QMessageBox.StandardButton(QMessageBox.Yes))

    def showAuthDialog(self,mode,msg):
        text, ok = QInputDialog.getText(self, self.tr('Auth'), msg)
        if ok:
            self.setUsPs(mode,text)
            return text
        else:
            return '!!!!!error'

    def showKeyDialog(self):
        self.app.show()

    def regKey(self,num,keystr,timer):
        self.thread1.setKey(num,keystr,timer)
    def logoutSteam(self):
        self.thread1.setOut()
        self.login.setEnabled(True)
        self.logout.setEnabled(False)
        self.userEdit.setEnabled(True)
        self.lgbtn.setHidden(False)
        self.lgbtn.setEnabled(True)
        self.passwdlabel.setHidden(False)
        self.passwdEdit.setHidden(False)
        self.regbtn.setHidden(True)
        self.userUrlLink.setHidden(True)
        self.userUrlLabel.setHidden(True)
        self.userEdit.clear()
        self.passwdEdit.clear()
        # app.exit()


class MainPanel(QtWidgets.QMainWindow):
    regSin = pyqtSignal(int,object,int)
    def __init__(self,parent=None):
        QtWidgets.QMainWindow.__init__(self,parent)
        # self.parent.thread1.regInfo.connect(self.regSlot)
        self.resize(640,360)
        self.mainwid = QWidget()
        self.setWindowTitle(self.tr('Redeem'))
        self.tb = QTableWidget()
        self.regBtn = QPushButton(self.tr('Reg!'))
        self.regBtn.clicked.connect(self.RegAll)
        self.outKeyBtn = QPushButton(self.tr('OutDuplicateKey'))
        self.outKeyBtn.clicked.connect(self.OutKey)

        self.keyInputLabel = QLabel(self.tr('Key Input:'))
        self.keyInputEdit = QTextEdit()
        self.keyInputEdit.setText('Input Key')
        self.inputbox =QHBoxLayout()
        self.inputbox.addWidget(self.keyInputLabel)
        self.inputbox.addWidget(self.keyInputEdit)
        self.inputbox.addSpacing(20)
        self.readKey  = QPushButton(self.tr('Scan'))
        self.readKey.clicked.connect(self.create_table)

        self.remtimeeLabel =QLabel(self.tr('Interval Time:'))
        self.remtimeEdit = QLineEdit('6')
        self.cehbox = QHBoxLayout()
        self.cehbox.addWidget(self.remtimeeLabel)
        self.cehbox.addWidget(self.remtimeEdit)
        self.cehbox.addSpacing(20)

        self.vbox = QVBoxLayout()
        self.vbox.addLayout(self.inputbox)
        self.vbox.addWidget(self.readKey)
        self.vbox.addLayout(self.cehbox)
        self.vbox.addWidget(self.regBtn)
        self.vbox.addWidget(self.outKeyBtn)
        self.hbox = QHBoxLayout()
        self.hbox.addWidget(self.tb)
        self.hbox.addLayout(self.vbox)
        self.mainwid.setLayout(self.hbox)
        self.setCentralWidget(self.mainwid)

    def create_table(self):
        mkey = self.scanKey(self.keyInputEdit.toPlainText())
        if len(mkey)==0:
            return
        self.tb.setRowCount(len(mkey))
        self.tb.setColumnCount(3)
        self.tb.setHorizontalHeaderLabels([ self.tr('key'), self.tr('result'),self.tr('game')])
        self.tb.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.allKey = mkey
        num = 0
        for itkey in mkey:
            self.tb.setItem(num, 0, QTableWidgetItem(itkey))
            self.tb.setItem(num, 1, QTableWidgetItem(self.tr('Null')))
            self.tb.setItem(num, 2, QTableWidgetItem('Null'))
            num+=1

    def scanKey(self, key):
        # client.run_forever()
        # print(mkey)
        if key =='':
            return
        try:
            rkey = re.findall('([0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5})', key)
        except:
            print('err')

        # print(mkey)
        if not len(rkey):
            self.showinfoMsg(self.tr('not found key'))
            return ''
        rkey = list(set(rkey))
        return rkey

    def showinfoMsg(self,msg):
        OK = QMessageBox.information(self, (self.tr("Redeem")), ("%s" % msg),
                                     QMessageBox.StandardButton(QMessageBox.Yes))

    def RegAll(self):
        self.rows = self.tb.rowCount()
        if(self.rows==0):
            return
        for item  in range(self.rows):
            self.tb.setItem(item,1,QTableWidgetItem(self.tr('waitting')))
        self.run_num = len(self.allKey)
        self.regSin.emit(self.run_num,self.allKey,int(self.remtimeEdit.text()))

    def regSlot(self, num,text,name):
        #print(text)
        if text == 'None':
            self.tb.setItem(num, 1, QTableWidgetItem('None'))
        else:
            mtext = text
            # print(repr(EPurchaseResultDetail(int(mtext))))
            if mtext == '0':
                self.tb.setItem(num, 1, QTableWidgetItem(self.tr('OK')))
                self.tb.setItem(num,2,QTableWidgetItem(name))
            elif mtext == '9':
                self.tb.setItem(num, 1, QTableWidgetItem(self.tr('AlreadyPurchased')))
                self.tb.setItem(num,2,QTableWidgetItem(name))
            elif mtext == '15':
                self.tb.setItem(num, 1, QTableWidgetItem(self.tr('Duplicate')))
                self.tb.setItem(num, 2, QTableWidgetItem(name))
            elif mtext == '53':
                self.tb.setItem(num, 1, QTableWidgetItem(self.tr('CD')))
                self.tb.setItem(num, 2, QTableWidgetItem(name))
            else:
                self.tb.setItem(num, 1, QTableWidgetItem(repr(EPurchaseResultDetail(int(mtext)))))
            output = open('rem.txt', 'a')
            key = self.tb.item(num,0).text()
            output.write('%s : %s\n'%(key,text))
            output.close()

    def OutKey(self):
        self.rows = self.tb.rowCount()
        if(self.rows==0):
            return
        outtext =''
        for item in range(self.rows):
            if(self.tb.item(item,1).text()==self.tr('Duplicate')
               or self.tb.item(item,1).text()==self.tr('Null')
               or self.tb.item(item,1).text()==self.tr('waitting')
               or self.tb.item(item, 1).text() == self.tr('AlreadyPurchased')
               or self.tb.item(item, 1).text() == self.tr('CD')
               ):
                outtext += self.tb.item(item,0).text()

        output = open('notusekey.txt', 'a')
        output.write(outtext)
        output.close()
        self.showinfoMsg(self.tr('DuplicateKey save to \"notusekey.txt\"'))

if __name__ == '__main__':
    import sys
    trans = QTranslator()
    trans.load("zh_CN")  # 没有后缀.qm

    app = QApplication(sys.argv)
    app.installTranslator(trans)
    main = MainWindow()

    main.show()
    sys.exit(app.exec_())

