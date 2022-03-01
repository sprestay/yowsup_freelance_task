import os, sys, json
import base64, zipfile, hashlib

try:
    with open('versions.txt', 'r') as fd:
        data = fd.readlines()
        os.environ['version'] = data[0].split()[1]
        os.environ['md5'] = data[1].split()[1]
        os.environ['short_version'] = '.'.join(os.environ['version'].split('.')[0:-1])
        os.environ['full_version'] = os.environ['version']
except:
    os.environ['version'] = '2.21.12.20'
    os.environ['md5'] = "O1/DTWx0YZdGaVPFt7tihA=="
    os.environ['short_version'] = '.'.join(os.environ['version'].split('.')[0:-1])
    os.environ['full_version'] = os.environ['version']
    with open('versions.txt', 'w') as fd:
        fd.write("Version " + os.environ['version'] + '\n')
        fd.write('ClassesDex: ' + os.environ['md5'])

from PyQt5.QtWidgets import QApplication, QWidget, QFileDialog
from PyQt5 import uic
from PyQt5.QtGui import QIntValidator, QRegExpValidator
from PyQt5.QtCore import QRegExp
from local_yowsup import DemosArgParser, RegistrationArgParser, ConfigArgParser, MediaToolsArgParser
from pyaxmlparser import APK


modeDict = {
    "demos": DemosArgParser,
    "registration": RegistrationArgParser,
    "config": ConfigArgParser,
    "media": MediaToolsArgParser,
    "version": None
}

def generateButtonStyle(background="", font=""):
    res = []
    if background:
        res.append("background-color: " + background)
    if font:
        res.append("color: " + font)
    res.append("border-width: 0px;")
    res.append("border-style: solid;")
    res.append("font-weight: bold;")
    res.append("border-radius: 5;")
    return '; '.join(res)

class App(QWidget):
    def __init__(self):
        super().__init__()
        uic.loadUi('form.ui', self)
        self.regexp = QRegExp("[0-9]+")
        self.onlyInt = QRegExpValidator(self.regexp)
        self.sendSMSButton.setDisabled(True)

        # Настройка стилей
        self.setStyleSheet("background-color: #BDD0D6;")
        self.sendSMSButton.setStyleSheet(generateButtonStyle(background="#FAEBAC", font="rgb(0,0,0)"))
        self.submitButton.setStyleSheet(generateButtonStyle(background="#FAEBAC", font="rgb(0,0,0)"))
        self.updateVersions.setStyleSheet(generateButtonStyle(background="#BDB3CE", font="rgb(0,0,0)"))
        self.selectJSONFolder.setStyleSheet(generateButtonStyle(background="#BDB3CE", font="rgb(0,0,0)"))
        self.selectConfig.setStyleSheet(generateButtonStyle(background="#BDB3CE", font="rgb(0,0,0)"))
        self.spamButton.setStyleSheet(generateButtonStyle(background="#FAEBAC", font="rgb(0,0,0)"))
        self.lineEdit.setStyleSheet("background-color: white")
        self.lineEdit_2.setStyleSheet("background-color: white")
        self.lineEdit_3.setStyleSheet("background-color: #C9C9C9")
        self.recepientPhone.setStyleSheet("background-color: white")
        self.recepientMessage.setStyleSheet("background-color: white")

        self.lineEdit.setPlaceholderText("Country Code")
        self.lineEdit.setValidator(self.onlyInt)
        self.lineEdit.textChanged.connect(self.shouldActivateButton)

        self.lineEdit_2.setPlaceholderText("Phone number (include country code)")
        self.lineEdit_2.setValidator(self.onlyInt)
        self.lineEdit_2.textChanged.connect(self.shouldActivateButton)

        self.lineEdit_3.setPlaceholderText("Enter code from SMS")
        self.lineEdit_3.setValidator(self.onlyInt)
        self.lineEdit_3.textChanged.connect(self.shouldActivateSubmit)

        self.recepientPhone.setValidator(self.onlyInt)
        self.recepientPhone.textChanged.connect(self.can_set_msg_validator)
        self.recepientMessage.textChanged.connect(self.can_set_msg_validator)

        # привязка кнопок
        self.sendSMSButton.clicked.connect(self.requestCode)
        self.submitButton.clicked.connect(self.codeSubmit)
        self.updateVersions.clicked.connect(self.update_Version)
        self.selectJSONFolder.clicked.connect(self.set_input_for_JSON)
        self.spamButton.clicked.connect(self.sendSpamMessage)
        self.selectConfig.clicked.connect(self.select_config_file_func)


        self.json_source.setText(str(os.path.abspath('./')))
        self.config_source_label.setText("config file is not selected")
        


    # Активирует и деактивирует кнопку регистрации 
    def shouldActivateButton(self, text):
        if len(self.lineEdit.text()) and len(self.lineEdit_2.text()):
            self.sendSMSButton.setDisabled(False)
            self.sendSMSButton.setStyleSheet(generateButtonStyle(background="#FAEB00", font="rgb(0,0,0)"))
        else:
            self.sendSMSButton.setDisabled(True)
            self.sendSMSButton.setStyleSheet(generateButtonStyle(background="#FAEBAC", font="rgb(0,0,0)"))

    # Кнопка регистрации
    def requestCode(self):
        os.environ['version'] = os.environ['full_version']
        self.resultLabel1.clear()
        self.resultLabel1.setStyleSheet("")
        sys.argv = [
            'registration',
            '--requestcode',
            'sms',
            '--phone',
            self.lineEdit_2.text(),
            '--cc',
            self.lineEdit.text(),
        ]
        args = sys.argv
        parser = modeDict[args[0]]()
        if not parser.process():
            parser.print_help()
        
        if 'send_message_result' in os.environ:
            result = json.loads(os.environ['send_message_result'])
            if result['status'] == 'fail':
                self.resultLabel1.setText("Error happend! Reason - {}.\nTry to update versions or use another number".format(result['reason']))
                self.resultLabel1.setStyleSheet("color: red;")
                self.lineEdit_3.setDisabled(True)
                self.lineEdit_3.setStyleSheet("background-color: #C9C9C9")
            else:
                self.resultLabel1.setText("Message - {}.\nEnter code from SMS and press Submit".format(result['status']))
                os.environ['phone'] = self.lineEdit_2.text()
                os.environ['country_code'] = self.lineEdit.text()
                self.lineEdit_3.setDisabled(False)
                self.lineEdit_3.setStyleSheet("background-color: white")

    
    def shouldActivateSubmit(self, text):
        if len(self.lineEdit_3.text()) == 6:
            self.submitButton.setDisabled(False)
            self.submitButton.setStyleSheet(generateButtonStyle(background="#FAEB00", font="rgb(0,0,0)"))
        else:
            self.submitButton.setDisabled(True)
            self.submitButton.setStyleSheet(generateButtonStyle(background="#FAEBAC", font="rgb(0,0,0)"))
    
    
    def codeSubmit(self):
        os.environ['version'] = os.environ['full_version']
        self.resultLabel1.clear()
        self.resultLabel1.setStyleSheet("")
        code = self.lineEdit_3.text()
        sys.argv = [
            'registration',
            '--register',
            code[:3] + '-' + code[3:],
            '--phone',
            os.environ['phone'],
            '--cc',
            os.environ['country_code'],
        ]
        args = sys.argv
        parser = modeDict[args[0]]()
        if not parser.process():
            parser.print_help()
        if 'sms_code_error' in os.environ and os.environ['sms_code_error'] == 'error':
            self.resultLabel1.setText("Error! Maybe your code is incorrect")
            self.resultLabel1.setStyleSheet("color: red;")
        else:
            self.resultLabel1.setText("Config saved as {} to selected folder".format(os.environ['phone'] + '.json'))


    def update_Version(self):
        apkFile = QFileDialog.getOpenFileName(self, 'Select Whatsapp.apk file', None, 'Image (*.apk)')[0]
        apk = APK(apkFile)
        try:
            zipFile = zipfile.ZipFile(apkFile,'r')
            classesDexFile = zipFile.read('classes.dex')
            hash = hashlib.md5()
            hash.update(classesDexFile)

            with open('versions.txt', 'w') as fd:
                fd.write("Version: " + apk.version_name + "\n")
                os.environ['version'] = apk.version_name
                fd.write("ClassesDex: " + base64.b64encode(hash.digest()).decode("utf-8"))
                os.environ['md5'] = base64.b64encode(hash.digest()).decode("utf-8")
            self.UpdateLabel.setText("Successfully updated\nVersion: {}\nClassesDex: {}".format(apk.version_name, base64.b64encode(hash.digest()).decode("utf-8")))

        except Exception as e:
            self.UpdateLabel1.setText("Not found error")

    def set_input_for_JSON(self):
        file = str(QFileDialog.getExistingDirectory(self, "Select Directory"))
        self.json_source.setText(str(os.path.abspath(file)))
        os.environ['json_source'] = file

    def select_config_file_func(self):
        file = QFileDialog.getOpenFileName(self, "Select .json file with config", None, "Image (*.json)")[0]
        self.config_source_label.setText(str(os.path.abspath(file)))
        self.can_set_msg_validator()

    def can_set_msg_validator(self):
        bool1 = os.path.isfile(self.config_source_label.text())
        bool2 = len(self.recepientPhone.text())
        bool3 = len(self.recepientMessage.toPlainText())
        if bool1 and bool2 and bool3:
            self.spamButton.setDisabled(False)
            self.spamButton.setStyleSheet(generateButtonStyle(background="#FAEB00", font="rgb(0,0,0)"))
        else:
            self.spamButton.setDisabled(True)
            self.spamButton.setStyleSheet(generateButtonStyle(background="#FAEBAC", font="rgb(0,0,0)"))


    def sendSpamMessage(self):
        os.environ['version'] = os.environ['short_version']
        from local_yowsup import DemosArgParser, RegistrationArgParser, ConfigArgParser, MediaToolsArgParser
        print(os.environ)
        modeDict = {
            "demos": DemosArgParser,
            "registration": RegistrationArgParser,
            "config": ConfigArgParser,
            "media": MediaToolsArgParser,
            "version": None
        }
        file = self.config_source_label.text()
        sys.argv = [
            'demos',
            '-c',
            file,
            '-s',
            self.recepientPhone.text(),
            self.recepientMessage.toPlainText(),
        ]
        args = sys.argv
        parser = modeDict[args[0]]()
        if not parser.process():
            parser.print_help()

    



if __name__=="__main__":
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec_())

