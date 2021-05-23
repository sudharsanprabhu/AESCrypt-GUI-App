import pyAesCrypt
import os
import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog

ENCRYPT = 1
DECRYPT = 2
TYPE = 'file'
FILES = {}

app = QtWidgets.QApplication(sys.argv)
mainWindow = QtWidgets.QMainWindow()


def AESDir(inp, out, process):
    global FILES
    if not os.path.exists(out):
        os.mkdir(out)

    items = os.listdir(inp)
    for file in items:
        if os.path.isfile(inp + os.path.sep + file):
            inFile = inp + os.path.sep + file

            if process == ENCRYPT:
                outFile = out + os.path.sep + file + '.enc'
                FILES[inFile] = outFile
                # pyAesCrypt.encryptFile(inFile, outFile, password)

            elif process == DECRYPT:
                outFile = out + os.path.sep + file.rsplit('.enc', 1)[0]
                FILES[inFile] = outFile
                # pyAesCrypt.decryptFile(inFile, outFile, password)

    for folder in items:
        if os.path.isdir(inp + os.path.sep + folder):
            inpDir = inp + os.path.sep + folder
            outDir = out + os.path.sep + folder
            AESDir(inpDir, outDir, process)

    return FILES


def setupUI(mainWindow):
    mainWindow.resize(735, 460)
    mainWindow.setMaximumSize(QtCore.QSize(735, 460))
    mainWindow.setMinimumSize(QtCore.QSize(735, 460))
    mainWindow.setWindowTitle("AESCrypt")
    mainWindow.setWindowIcon(QtGui.QIcon('encrypt.ico'))
    mainWindow.setStyleSheet("background-color: #2a363f")

    line = QtWidgets.QFrame(mainWindow)
    line.setGeometry(QtCore.QRect(400, 25, 20, 400))
    line.setStyleSheet("border-right: 1px solid grey; border-style: inset;")

    inputFileOrFolder = QtWidgets.QLineEdit(mainWindow)
    inputFileOrFolder.setGeometry(QtCore.QRect(20, 130, 290, 40))
    inputFileOrFolder.setStyleSheet("border: 2px solid #6ed9a0; color: white; border-radius: 5px; font-size: 10pt;")
    inputFileOrFolder.setPlaceholderText("Input file...")

    def inputBrowseDialog():
        if TYPE == 'file':
            inputName = QFileDialog.getOpenFileName()
            inputFileOrFolder.setText((inputName[0]))
        elif TYPE == 'folder':
            inputName = QFileDialog.getExistingDirectory()
            inputFileOrFolder.setText(inputName)

    inputBrowseButton = QtWidgets.QPushButton(mainWindow)
    inputBrowseButton.setGeometry(QtCore.QRect(320, 130, 80, 40))
    inputBrowseButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
    inputBrowseButton.setStyleSheet(
        "border: 2px solid #03a9f4; background-color: #03a9f4; color: white; border-radius: 5px; font-size: 12pt;")
    inputBrowseButton.setText("Browse")
    inputBrowseButton.clicked.connect(inputBrowseDialog)

    outputFolder = QtWidgets.QLineEdit(mainWindow)
    outputFolder.setGeometry(QtCore.QRect(20, 200, 290, 40))
    outputFolder.setStyleSheet("border: 2px solid #6ed9a0; color: white; border-radius: 5px; font-size: 10pt;")
    outputFolder.setPlaceholderText("Output Folder...")

    def outputFolderBrowseDialog():
        outputFolderName = QFileDialog.getExistingDirectory()
        outputFolder.setText(outputFolderName)

    outputBrowseButton = QtWidgets.QPushButton(mainWindow)
    outputBrowseButton.setGeometry(QtCore.QRect(320, 200, 80, 40))
    outputBrowseButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
    outputBrowseButton.setStyleSheet(
        "border: 2px solid #03a9f4; background-color: #03a9f4; color: white; border-radius: 5px; font-size: 12pt;")
    outputBrowseButton.setText("Browse")
    outputBrowseButton.clicked.connect(outputFolderBrowseDialog)

    inputPassword = QtWidgets.QLineEdit(mainWindow)
    inputPassword.setGeometry(QtCore.QRect(20, 270, 380, 40))
    inputPassword.setStyleSheet("border: 2px solid #6ed9a0; color: white; border-radius: 5px; font-size: 12pt;")
    inputPassword.setPlaceholderText("Password...")
    inputPassword.setEchoMode(QtWidgets.QLineEdit.Password)

    def setFile():
        global TYPE
        inputFileOrFolder.setPlaceholderText('Input file...')
        inputFileOrFolder.setText('')
        TYPE = 'file'

    def setFolder():
        global TYPE
        inputFileOrFolder.setPlaceholderText('Input folder')
        inputFileOrFolder.setText('')
        TYPE = 'folder'

    fileRadioButton = QtWidgets.QRadioButton(mainWindow)
    fileRadioButton.setGeometry(QtCore.QRect(20, 70, 20, 20))
    fileRadioButton.setChecked(True)
    fileRadioButton.toggled.connect(setFile)

    fileLabel = QtWidgets.QLabel(mainWindow)
    fileLabel.setGeometry(QtCore.QRect(40, 68, 50, 20))
    fileLabel.setStyleSheet("color: white; font-size: 12pt;")
    fileLabel.setText("File")

    folderRadioButton = QtWidgets.QRadioButton(mainWindow)
    folderRadioButton.setGeometry(QtCore.QRect(300, 70, 20, 20))
    folderRadioButton.toggled.connect(setFolder)

    folderLabel = QtWidgets.QLabel(mainWindow)
    folderLabel.setGeometry(QtCore.QRect(320, 68, 50, 20))
    folderLabel.setStyleSheet("color: white; font-size: 12pt;")
    folderLabel.setText("Folder")

    # Console log
    logger = QtWidgets.QPlainTextEdit(mainWindow)
    logger.setGeometry(QtCore.QRect(450, 30, 250, 380))
    logger.setStyleSheet('font-size: 10pt; color: #FFFFFF; border: 0px')
    logger.setPlainText('AESCrypt - - - - - - - - - - - - - - - -')
    logger.setReadOnly(True)

    # Progress bar
    progressBar = QtWidgets.QProgressBar(mainWindow)
    progressBar.setGeometry(450, 370, 260, 20)
    progressBar.setStyleSheet('color: #FFFFFF;')
    progressBar.setVisible(False)

    def validator(inp, out, password):
        if len(inp) == 0:
            logger.appendPlainText('\nPlease enter a input file or directory...')
            return False

        elif len(out) == 0:
            logger.appendPlainText('\nPlease enter a output directory...')
            return False

        elif len(password) == 0:
            logger.appendPlainText('\nPlease enter a password...')
            return False

        else:
            return True

    def encryptor(inp, out, itemType, password):
        global FILES
        logger.setPlainText('AESCrypt - - - - - - - - - - - - - - - -')
        if validator(inp, out, password):
            if itemType == 'file':
                logger.appendPlainText('\nFound ' + inp)
                outFile = inp.rsplit('/', 1)[1]
                try:
                    pyAesCrypt.encryptFile(inp, out + os.path.sep + outFile + '.enc', password)
                    logger.appendPlainText("\n\n$~ Encryption successful - - - - -")
                except ValueError:
                    logger.appendPlainText('\n\n$~ Incorrect password or the file is corrupted - - - - -')

            elif itemType == 'folder':
                try:
                    files = AESDir(inp, out, ENCRYPT)
                    progressBar.setValue(0)
                    progressBar.setVisible(True)
                    numberOfFiles = len(files)
                    processedFile = 0
                    for file in files:
                        pyAesCrypt.encryptFile(file, files[file], password)
                        processedFile += 1
                        percentageCompleted = processedFile / numberOfFiles * 100
                        progressBar.setValue(int(percentageCompleted))
                        QtCore.QCoreApplication.processEvents()

                    logger.appendPlainText("\n\n$~ Encryption successful - - - - -")
                    FILES.clear()
                except ValueError:
                    logger.appendPlainText('\n\n$~ Incorrect password or the file is corrupted - - - - -')

    def decrypter(inp, out, itemType, password):
        global FILES
        logger.setPlainText('AESCrypt - - - - - - - - - - - - - - - -')
        if validator(inp, out, password):
            if itemType == 'file':
                logger.appendPlainText('\nFound ' + inp)
                outFile = inp.rsplit('.enc', 1)[0]
                outFile = outFile.rsplit('/', 1)[1]
                try:
                    pyAesCrypt.decryptFile(inp, out + os.path.sep + outFile, password)
                    logger.appendPlainText("\n\n$~ Decryption successful - - - - -")
                except ValueError:
                    logger.appendPlainText('\n\n$~ Incorrect password or the file is corrupted - - - - -')

            elif itemType == 'folder':
                try:
                    files = AESDir(inp, out, DECRYPT)
                    progressBar.setValue(0)
                    progressBar.setVisible(True)
                    numberOfFiles = len(files)
                    processedFile = 0
                    for file in files:
                        pyAesCrypt.decryptFile(file, files[file], password)
                        processedFile += 1
                        percentageCompleted = processedFile / numberOfFiles * 100
                        progressBar.setVisible(True)
                        progressBar.setValue(int(percentageCompleted))
                        QtCore.QCoreApplication.processEvents()

                    logger.appendPlainText("\n\n$~ Decryption successful - - - - -")
                    FILES.clear()
                except ValueError:
                    logger.appendPlainText('\n\n$~ Incorrect password or the file is corrupted - - - - -')

    # Encrypt button
    encryptButton = QtWidgets.QPushButton(mainWindow)
    encryptButton.setGeometry(QtCore.QRect(20, 350, 150, 41))
    encryptButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
    encryptButton.setStyleSheet(
        "border: 2px solid #03a9f4; color: white; border-radius: 5px; font-size: 12pt;")
    encryptButton.setText("Encrypt")
    encryptButton.clicked.connect(
        lambda: encryptor(inputFileOrFolder.text(), outputFolder.text(), TYPE, inputPassword.text()))

    # Decrypt button
    decryptButton = QtWidgets.QPushButton(mainWindow)
    decryptButton.setGeometry(QtCore.QRect(250, 350, 150, 41))
    decryptButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
    decryptButton.setStyleSheet(
        "border: 2px solid #03a9f4; color: white; border-radius: 5px; font-size: 12pt;")
    decryptButton.setText("Decrypt")
    decryptButton.clicked.connect(
        lambda: decrypter(inputFileOrFolder.text(), outputFolder.text(), TYPE, inputPassword.text()))


setupUI(mainWindow)
mainWindow.show()

sys.exit(app.exec_())
