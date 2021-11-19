import smtplib # Imports for emailing
import ssl
import sys

import mysql.connector # Import for connecting to database

import pandas as pd # Imports for creating the Gantt Chart
import plotly
import plotly.express as px

# Imports for the GUI and specific widgets
from PyQt5 import QtGui, QtWidgets, Qt, QtWebEngineWidgets # PyQt GUI imports
from PyQt5.QtCore import Qt, QDate, QTimer, QTime
from PyQt5.QtGui import QFont
from PyQt5.QtPrintSupport import QPrintDialog
from PyQt5.QtWidgets import (QPushButton, QWidget, QVBoxLayout,
                             QTabWidget, QTableWidget, QTableWidgetItem,
                             QCalendarWidget, QLineEdit, QLabel, QHBoxLayout, QGridLayout,
                             QComboBox, QListWidget, QDateEdit, QListView, QCheckBox,
                             QHeaderView, QFileDialog, QTimeEdit, QPlainTextEdit, QToolBar, QAction)

from win10toast import ToastNotifier # Imports for Reminders
from threading import Timer

import os # Imports Used for Hashing
import hashlib
import random

dbConnected = False

def connectDatabase():
    global database
    global cursor
    global dbConnected

    # creating the db connection
    database = mysql.connector.connect(host="127.0.0.1", user="root", password="", database="projectdb", port="3306")
    cursor = database.cursor() # creating the cursor
    dbConnected = True

def sendEmail(recipient, subject, body):
    # Create a secure SSL context
    context = ssl.create_default_context()
    port = 465  # For SSL
    # Developer/Application email credentials which messages are sent from
    password = ""
    senderEmail = ""
    header = ["From: " + senderEmail,  # Email headers
               "Subject: " + subject,
               "To: " + recipient,
               "MIME-Version: 1.0",
               "Content-Type: text/html"]

    header = "\r\n".join(header)

    try:
        # Sending email via SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
            server.login(senderEmail, password)
            server.sendmail(senderEmail, recipient, header + "\r\n\r\n" + body)
            server.quit()
    except:
        # Creating an error if email fails to send
        global emailError
        emailError = errorWindow("Error sending email ", "SMPT Emailing error "+str(sys.exc_info()[0]))
        emailError.show()
        return emailError

class loginWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__() # Calling the QMainWindow Constructor
        self.vbox = QVBoxLayout()  # Creating the layout for widgets to be added to
        self.centralWidget = QWidget() # Making elements centralised
        self.setCentralWidget(self.centralWidget)

        self.setGeometry(750, 350, 300, 300) # Setting the window size and screen position
        self.setWindowTitle("Login") # Setting the title of the window
        self.setWindowIcon(QtGui.QIcon("logo.ico")) # Setting the window icon

        self.login()

    def login(self):
        # Displaying the program name
        self.softwareName = QLabel(self)
        self.softwareName.setText("ProjectFly")
        self.softwareName.setFont(QFont('Arial', 30))

        # Creating the input boxes
        self.usernameForm = QLineEdit(self)
        self.passwordForm = QLineEdit(self)

        # Masking the password input
        self.passwordForm.setEchoMode(QLineEdit.Password)

        # Resizing the username input box and setting the placeholder text
        self.usernameForm.resize(self.usernameForm.sizeHint())
        self.usernameForm.setPlaceholderText('Username')

        # Resizing the password input box and setting the placeholder text
        self.passwordForm.resize(self.passwordForm.sizeHint())
        self.passwordForm.setPlaceholderText('Password')

        # Creating the login button that will run the checkLogin method
        self.loginButton = QPushButton("Login")
        self.loginButton.clicked.connect(self.checkLogin)

        # Creating the create account button that will run the create account method
        self.createAccountButton = QPushButton("Create Account")
        self.createAccountButton.clicked.connect(self.createAccountWindow)

        # Creating the forgot details button opening the forgot details menu
        self.forgotDetailsButton = QPushButton("Forgot Details")
        self.forgotDetailsButton.clicked.connect(self.forgotDetails)

        # Adding the widgets created above to the layout
        self.vbox.addWidget(self.softwareName, alignment=Qt.AlignCenter)
        self.vbox.addWidget(self.usernameForm)
        self.vbox.addWidget(self.passwordForm)
        self.vbox.addWidget(self.loginButton)
        self.vbox.addWidget(self.createAccountButton)
        self.vbox.addWidget(self.forgotDetailsButton)

        # Stops the user resizing
        self.setFixedSize(self.size())

        # displaying the GUI with the layout
        self.centralWidget.setLayout(self.vbox)
        self.show()

    # Function that validates user inputted credentials against database of users
    # Allows access to the main Window if authenticated
    def checkLogin(self):
        global mainProgram
        global loggedIn
        global loggedInUserID
        global userEmail
        loggedIn = False
        userInput = self.usernameForm.text()  # Store the username input
        passInput = self.passwordForm.text()  # Store the password input
        if userInput != "" and passInput != "":  # Check if the inputs are not empty
            self.fetchUserIDs = "SELECT UserID FROM users"  # Query that fetches the user IDs in the database
            cursor.execute(self.fetchUserIDs)  # Execute the query
            self.fetchedIDs = cursor.fetchall()  # Fetch and store all of the IDs

            # LOOPS through each fetched id with 'field' being the current ID in the fetched IDs
            for field in self.fetchedIDs:  # For the number of IDs in the fetched result
                ID = field[0]  # format the ID as a single number

                # Fetch the salt at the current ID and store it
                self.fetchSaltQuery = ("SELECT Salt FROM users WHERE UserID='%s'" % ID)
                cursor.execute(self.fetchSaltQuery)
                fetchedSalt = cursor.fetchone()[0]

                # Fetch the username at the current ID and store it
                self.usernameCheck = ("SELECT Username FROM users WHERE UserID='%s'" % ID)
                cursor.execute(self.usernameCheck)
                fetchedUsername = cursor.fetchone()[0]

                # Fetch the password at the current ID and store it
                self.passwordCheck = ("SELECT Pass FROM users WHERE UserID='%s'" % ID)
                cursor.execute(self.passwordCheck)
                fetchedPassword = cursor.fetchone()[0]

                # convert the hex retrieved from the database into bytes to use for hashing and comparing
                formattedSaltToBytes = bytes.fromhex(fetchedSalt)
                formattedPassToBytes = bytes.fromhex(fetchedPassword)

                # hash the password that the user has inputted
                hashedPasswordInput = hashlib.pbkdf2_hmac('sha256', passInput.encode('utf-8'), formattedSaltToBytes, 100000)

                # ONLY allow login if the input is not empty, if the fetched credentials arent empty
                # AND only if the hashed user input password using the salt at the current record
                # is the same as the fetched password converted to bytes
                # AND only if the username at that same record is the same as the one the user inputted
                if fetchedPassword is not None and fetchedUsername is not None:
                    if userInput != '' and passInput != '':
                        if fetchedUsername == userInput and formattedPassToBytes == hashedPasswordInput:
                            self.close()
                            loggedInUserID = ID
                            loggedIn = True

                            # Change style sheet to prefered in database
                            fetchStylePreference = "SELECT DarkTheme FROM Users WHERE UserID='%s'" % loggedInUserID
                            cursor.execute(fetchStylePreference)
                            stylePreference = cursor.fetchone()[0]

                            if stylePreference == 1:
                                styleSheet="dark.qss"
                            else:
                                styleSheet="light.qss"

                            with open(os.path.join(sys.path[0], styleSheet), "r") as f:
                                app.setStyleSheet(f.read())

                            f.close()

                            mainProgram = mainWindow()

                            # Store user email for use in program
                            fetchUserEmailQuery = ("SELECT Email FROM users WHERE UserID='%s'" % loggedInUserID)
                            cursor.execute(fetchUserEmailQuery)
                            userEmail = cursor.fetchone()[0]
                            break

        if loggedIn == False:
            self.invalidLoginAttempt = errorWindow("Invalid Login", "Please check you have inputted a valid account")

    def createAccountWindow(self):
        global accountWindow
        accountWindow = accountCreationWindow()

    def forgotDetails(self):
        global forgottenAccount
        forgottenAccount = forgotDetailsWindow()

class forgotDetailsWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(forgotDetailsWindow, self).__init__() # Calling the superclass constructor
        self.centralWidget = QWidget() # Centralising the widgets
        self.setCentralWidget(self.centralWidget)
        self.setWindowTitle("Account Recovery") # Setting the window title
        self.setWindowIcon(QtGui.QIcon("logo.ico"))  # Setting the window icon
        self.setGeometry(1055, 350, 315, 260) # Setting the window geometry
        self.buildWindow()

    def buildWindow(self):
        self.windowLayout = QVBoxLayout() # Creating the layout for the window
        self.recoverAccountLayout = QGridLayout() # Sub layout for widgets

        # Big text title for the window
        self.forgotAccountTitle = QLabel(self)
        self.forgotAccountTitle.setText("Forgot Account Details")
        self.forgotAccountTitle.setFont(QFont('Arial', 20))

        # Email input and accompnying label
        self.emailInputLabel = QLabel(self)
        self.emailInputLabel.setText("Enter Email")
        self.emailInput = QLineEdit(self)

        # Checkbox if user forgot username + accompanying label
        self.forgotUserLabel = QLabel(self)
        self.forgotUserLabel.setText("Forgot Username")
        self.forgotUserCheck = QCheckBox(self)

        # Checkbox if user forgot password + accompanying label
        self.forgotPassCheck = QCheckBox(self)
        self.forgotPassLabel = QLabel(self)
        self.forgotPassLabel.setText("Forgot Password")

        # Button to start accoutn recovery method
        self.recoverAccountButton = QPushButton("Recover Account")
        self.recoverAccountButton.clicked.connect(self.recoverAccount)
        self.recoverAccountButton.sizeHint()

        # Add widgets to layout
        self.windowLayout.addWidget(self.forgotAccountTitle)
        self.recoverAccountLayout.addWidget(self.emailInputLabel, 1, 0)
        self.recoverAccountLayout.addWidget(self.emailInput, 1, 1)
        self.recoverAccountLayout.addWidget(self.forgotUserLabel, 2, 0)
        self.recoverAccountLayout.addWidget(self.forgotUserCheck, 2, 1)
        self.recoverAccountLayout.addWidget(self.forgotPassLabel, 3, 0)
        self.recoverAccountLayout.addWidget(self.forgotPassCheck, 3, 1)
        self.windowLayout.addLayout(self.recoverAccountLayout)
        self.windowLayout.addWidget(self.recoverAccountButton, alignment=Qt.AlignLeft)

        self.centralWidget.setLayout(self.windowLayout)
        self.show()

    def recoverAccount(self):
        # Store the states of the checkboxes
        recoverUsername = self.forgotUserCheck.checkState()
        recoverPassword = self.forgotPassCheck.checkState()
        # Store the inputted email
        userEmail = self.emailInput.text()

        # XOR, if the user wants to recover username XOR password
        if recoverPassword ^ recoverUsername:
            # If the email is not empty
            if userEmail != "":
                # If recovering userame
                if recoverUsername:
                    fetchUsernameQuery = "SELECT Username FROM Users WHERE Email = '%s'" % userEmail
                    try:
                        # Try fetching an account with that email
                        cursor.execute(fetchUsernameQuery)
                        recoveredUsername = cursor.fetchone()[0]
                    # If error is raised, no account exists with the email provided
                    except Exception:
                        self.invalidEmail = errorWindow("Invalid Email", "This email is invalid or belongs to no account")
                    else:
                        # Send the username to that email and show a dialogue to tell the user
                        sendEmail(userEmail, "ProjectFly: Recovered Username", "Your username is "+str(recoveredUsername))
                        self.succesfullUserRecovery = errorWindow("Recovery Email Sent", "Please check your emails")

                # If recovering password
                if recoverPassword:
                    fetchUserIDQuery = "SELECT UserID FROM Users WHERE Email = '%s'" % userEmail
                    try:
                        # Try fetching an account with the inputted email
                        cursor.execute(fetchUserIDQuery)
                        self.userID = cursor.fetchone()[0]
                    except Exception:
                        # raise error if no matches are found
                        self.invalidEmail = errorWindow("Invalid Email", "This email is invalid or belongs to no account")
                    else:
                        # Otherwise generate a 20 digit Auth code made from the alphabet + capitalized + numbers
                        # The code is generated randomly from the string of characters
                        self.authCode = ""
                        characters = "abcdefghijklmnopqrstuvwxyzABCEDFGHIJKLMNOPQRSTUVWXYZ1234567890"
                        for x in range(0, 20):
                            self.authCode += characters[random.randint(0, len(characters)-1)]
                        # Send the user this auth code and tell them to check their email
                        sendEmail(userEmail, "ProjectFly: Password Recovery", "Please Enter this code into the program <br> to set a new password <br> " + str(self.authCode))
                        self.succesfullPassCode = errorWindow("Email Sent", "Check your emails for instructions \n DO NOT close this program")
                        # Add a new layout and widgets to allow the user to input an auth code
                        # This was previously not in the window
                        self.passwordAuthLayout = QVBoxLayout()

                        # Title to show the new section
                        self.authenticationTitle = QLabel(self)
                        self.authenticationTitle.setText("Password Recovery")
                        self.authenticationTitle.setFont(QFont('Arial', 20))

                        # Input, label and button for checking the auth key
                        self.authLabel = QLabel(self)
                        self.authLabel.setText("Enter your auth key")
                        self.authButton = QPushButton("Check Key")
                        self.authButton.clicked.connect(self.checkAuthKey)
                        self.authInput = QLineEdit(self)

                        self.passwordAuthLayout.addWidget(self.authenticationTitle)
                        self.passwordAuthLayout.addWidget(self.authLabel)
                        self.passwordAuthLayout.addWidget(self.authInput)
                        self.passwordAuthLayout.addWidget(self.authButton)
                        self.windowLayout.addLayout(self.passwordAuthLayout)
            else:
                self.noEmail = errorWindow("No email entered", "Please enter your account email")
        else:
            self.checkBoxError = errorWindow("Choice error", "Please choose recover email OR password")

    def checkAuthKey(self):
        # Get the input from the user
        authInput = self.authInput.text()
        # If the key the user inputs matches the one created by the program
        # allow them to set a new password and add widgets to facilitate this
        if authInput == str(self.authCode):
            self.authButton.setEnabled(False)

            self.newPasswordLabel = QLabel(self)
            self.newPasswordLabel.setText("Enter New Password")

            self.newPasswordInput = QLineEdit(self)
            self.newPasswordSetButton = QPushButton("Set New Password")
            self.newPasswordSetButton.clicked.connect(self.setNewPassword)

            self.passwordAuthLayout.addWidget(self.newPasswordLabel)
            self.passwordAuthLayout.addWidget(self.newPasswordInput)
            self.passwordAuthLayout.addWidget(self.newPasswordSetButton)

        else:
            self.invalidAuth = errorWindow("Invalid Key", "Re-check your auth key in your emails")

    def setNewPassword(self):
        # Store the password entered
        newPassword = self.newPasswordInput.text()
        # if it is not empty
        if newPassword != "":
            # if it is bigger than 7 chars
            if len(newPassword) > 7:
                # Fetch the salt from the account record and convert it to byte values
                # Hash the password entered by the user and convert that to hexadecimal values
                # Update the record with the new hashed password in hex form
                connectDatabase()
                ID = self.userID
                fetchSaltQuery = "SELECT Salt FROM Users WHERE UserID=%s " % (ID)
                cursor.execute(fetchSaltQuery)
                salt = cursor.fetchone()[0]
                saltToBytes = bytes.fromhex(salt)
                newPasswordHashed = hashlib.pbkdf2_hmac('sha256', newPassword.encode('utf-8'), saltToBytes, 100000)
                newPasswordHashedHex = newPasswordHashed.hex()

                updatePasswordQuery = "UPDATE Users SET Pass = '%s' WHERE UserID = '%s'" % (newPasswordHashedHex, self.userID)
                cursor.execute(updatePasswordQuery)
                database.commit()

                self.close()
            else:
                self.shortPassword = errorWindow("Short password", "password must be longer than 7 characters")
        else:
            self.noPassword = errorWindow("No password entered", "please enter a new password")

class accountCreationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(accountCreationWindow, self).__init__() # Calling the superclass constructor
        self.vbox = QVBoxLayout() # Creating the layout for the window
        self.centralWidget = QWidget() # Centralising the widgets
        self.setCentralWidget(self.centralWidget)
        self.setWindowTitle("Account Creation") # Setting the window title
        self.setWindowIcon(QtGui.QIcon("logo.ico"))  # Setting the window icon
        self.setGeometry(1055, 350, 315, 250) # Setting the window geometry
        self.setFixedSize(self.size())  # stops Resizing

        self.creationScreen()  # Calls the method to add widgets to the layout

    def creationScreen(self):
        self.firstNameForm = QLineEdit(self) # Creating First Name Input Form
        self.lastNameForm = QLineEdit(self) # Creating Last Name Input Form
        self.usernameForm = QLineEdit(self) # Creating Username Input Form
        self.passwordForm = QLineEdit(self) # Creating Password Input Form
        self.passwordCheckForm = QLineEdit(self) # Creating Retype Password Input Form
        self.emailForm = QLineEdit(self) # Creating Email Input Form

        # Setting the placeholder text to describe what the input forms require from the user
        self.firstNameForm.setPlaceholderText("First Name")
        self.lastNameForm.setPlaceholderText("Last Name")
        self.usernameForm.setPlaceholderText("Username")
        self.passwordForm.setPlaceholderText("Password")
        self.passwordCheckForm.setPlaceholderText("Retype Password")
        self.emailForm.setPlaceholderText("Email")

        self.passwordForm.setEchoMode(QLineEdit.Password)
        self.passwordCheckForm.setEchoMode(QLineEdit.Password)

        self.createButton = QPushButton("Create") # Creating the button to submit the account
        self.createButton.clicked.connect(self.checkAccount) # Call the method to check the details
        # This method will upload the details to the database if they are valid

        self.cancelButton = QPushButton("Cancel") # Creating the cancel button
        self.cancelButton.clicked.connect(self.close)

        # Adding each of the widgets to the layout
        self.vbox.addWidget(self.firstNameForm)
        self.vbox.addWidget(self.lastNameForm)
        self.vbox.addWidget(self.usernameForm)
        self.vbox.addWidget(self.passwordForm)
        self.vbox.addWidget(self.passwordCheckForm)
        self.vbox.addWidget(self.emailForm)
        self.vbox.addWidget(self.createButton)
        self.vbox.addWidget(self.cancelButton)

        self.centralWidget.setLayout(self.vbox) # Setting the layout and displaying it
        self.show()

    def checkAccount(self):
        global loggedIn
        global loggedInID

        firstInput = self.firstNameForm.text() # Getting the input from the forms
        lastInput = self.lastNameForm.text() # Once the function is called and storing them
        userInput = self.usernameForm.text()
        passInput = self.passwordForm.text()
        passCheckInput = self.passwordCheckForm.text()
        emailInput = self.emailForm.text()

        salt = os.urandom(32) # Generating the random salt value for hashing
        saltHex = salt.hex() # converting the byte value to hex for database storing
        # hashing the password and converting the byte value to hex for storage
        hashedPassword = hashlib.pbkdf2_hmac('sha256', passInput.encode('utf-8'), salt, 100000)
        hashedPasswordHex = hashedPassword.hex()

        storeAccountQuery = '''INSERT INTO Users (Email, FirstName, LastName, Username, Pass, Salt) VALUES ("%s", "%s", "%s", "%s", "%s", "%s")''' % (
            emailInput, firstInput, lastInput, userInput, hashedPasswordHex, saltHex)

        # account validation
        if passInput == passCheckInput:
                    if firstInput != "" and lastInput != "" and userInput != "" and passInput != "" and emailInput != "":  # check inputs arent empty
                        if "@" in emailInput and "." in emailInput:  # check email is valid
                            if len(passInput) > 7:  # check password is longer than 7
                                cursor.execute(storeAccountQuery)  # store account details
                                database.commit()  # commit changes
                                accountWindow.close()  # close account creation window

                                # creating error message windows if the validation is false
                            elif len(passInput) < 7:
                                self.shortPassword = errorWindow("Short Password", "Please ensure your password is longer than 7 characters")
                        elif not "@" in emailInput and not "." in emailInput:
                            self.invalidEmail = errorWindow("Invalid email", "Please ensure you have entered a valid email address")
                    elif firstInput == "" or lastInput == "" or userInput == "" or passInput == "" or emailInput == "":
                        self.missingAccountInput = errorWindow("Unfilled input", "Please ensure you have entered information in every input box")
        elif passInput != passCheckInput:
            self.nonMatchingPasswords = errorWindow("Passwords do not match", "Please try re entering your passwords and make sure they match")

class errorWindow(QtWidgets.QMainWindow):
    def __init__(self, error, help):
        super(errorWindow, self).__init__()
        self.centralWidget = QWidget() # Making elements centralised
        self.setCentralWidget(self.centralWidget)

        self.setGeometry(750, 350, 400, 200) # Setting the window size and screen position
        self.setWindowTitle("Error") # Setting the title of the window
        self.setWindowIcon(QtGui.QIcon("logo.ico")) # Setting the window icon

        self.errorMessage = error
        self.helpMessage = help

        self.error()

    def error(self):
        self.vbox = QVBoxLayout() # Creating the layout to add widgets to
        self.errorMessageLabel = QLabel(self) # Creating the error message label
        # Setting the text as the passed in error message
        self.errorMessageLabel.setText(self.errorMessage)
        self.errorMessageLabel.setFont(QFont('Arial', 20))

        self.helpMessageLabel = QLabel(self) # Creating the help message label
        # Setting the text as the passed in help message
        self.helpMessageLabel.setText(self.helpMessage)
        self.helpMessageLabel.setFont(QFont('Arial', 13))

        self.vbox.addWidget(self.errorMessageLabel) # Adding the labels to the layout
        self.vbox.addWidget(self.helpMessageLabel)

        self.centralWidget.setLayout(self.vbox) # Setting the layout and showing it
        self.show()

class mainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(mainWindow, self).__init__()  # Calling the superclass constructor
        self.centralWidget = QWidget() # Centralising Widgets
        self.setCentralWidget(self.centralWidget)
        self.setGeometry(50, 50, 802, 600) # Setting window geometry
        self.setWindowTitle("ProjectFly") # Setting the window title
        self.setWindowIcon(QtGui.QIcon("logo.ico")) # Setting the window icon

        self.home() # calling the function to add everything to the main window

    def home(self):
        self.vbox = QVBoxLayout() # Creating the layout to add widgets to

        self.createMenuBar() # Creating the menu bar

        # Initialize the tabs
        self.tabs = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()
        self.tab4 = QWidget()
        self.tab5 = QWidget()

        self.tabs.resize(300, 200)

        # Add tabs here
        self.tabs.addTab(self.tab1, "Objectives")
        self.tabs.addTab(self.tab2, "Schedule")
        self.tabs.addTab(self.tab3, "Reminders")
        self.tabs.addTab(self.tab4, "Timeline")
        self.tabs.addTab(self.tab5, "Notes")

        # Add widgets to tabs using functions
        self.createObjectivesTab()
        self.createScheduleTab()
        self.createRemindersTab()
        self.createTimelineTab()
        self.createNotesTab()

        # Add tabs to layout and display
        self.vbox.addWidget(self.tabs)
        self.setLayout(self.vbox)

        self.centralWidget.setLayout(self.vbox)
        self.show()

    def createMenuBar(self):
        extractAction = QtWidgets.QAction("&Quit", self)  # Creating the Quit action for menu bar
        extractAction.setStatusTip("Quit to desktop")  # Setting the tooltip
        extractAction.triggered.connect(self.closeApplication)  # Calling the function to close

        logOutOption = QtWidgets.QAction("&Logout", self)  # Creating the Logout action for menu bar
        logOutOption.setStatusTip("Logout of your Account")  # Setting the tooltip
        logOutOption.triggered.connect(self.logout)  # Calling the logout function

        helpThemesOption = QtWidgets.QAction("&Settings", self)  # Creating the settings menu button for the menu bar
        helpThemesOption.setStatusTip("Change your theme or get information")  # Setting the tooltip
        helpThemesOption.triggered.connect(self.helpAndThemes)  # Calling the function to display the menu

        self.statusBar()  # Adding the status bar for tooltips

        mainMenu = self.menuBar()  # Creating the menu bar
        # Adding the actions to the menu bar
        mainMenu.addAction(helpThemesOption)
        mainMenu.addAction(logOutOption)
        mainMenu.addAction(extractAction)

    def createObjectivesTab(self):
        self.tab1.layout = QVBoxLayout(self)  # Setting the layout for the tab

        self.newTaskButton = QPushButton("New Task")  # Creating the new task button
        self.newTaskButton.clicked.connect(self.setTask)  # Calling the function for new tasks
        self.newTaskButton.resize(self.newTaskButton.sizeHint())  # Resizing

        self.editTaskButton = QPushButton("Edit Task")  # Creating the edit task button
        self.editTaskButton.clicked.connect(self.editTask)  # Calling the function for editing tasks
        self.editTaskButton.resize(self.editTaskButton.sizeHint())  # Resizing

        self.exportTasksButton = QPushButton("Export Tasks")  # Creating the export tasks button
        self.exportTasksButton.clicked.connect(self.exportTasks)  # Calling the function for exporting tasks
        self.exportTasksButton.resize(self.exportTasksButton.sizeHint())  # Resizing

        self.createTasksTable()  # Calling the function to create the table

        self.buttonsLayout = QHBoxLayout()  # Creating the nested layout for horizontal buttons

        self.buttonsLayout.addWidget(self.newTaskButton)  # Adding the buttons to the main layout
        self.buttonsLayout.addWidget(self.editTaskButton)
        self.buttonsLayout.addWidget(self.exportTasksButton)

        self.tab1.layout.addLayout(self.tableLayout)  # Adding the table to the tab 1 layout
        self.tab1.layout.addLayout(self.buttonsLayout)  # Adding the nested buttons layout
        self.tab1.setLayout(self.tab1.layout)  # Setting the layout for tab 1

    def createScheduleTab(self):
        self.tab2.layout = QGridLayout(self)  # Setting the layout for the window

        self.scheduleCalendar = QCalendarWidget(self)  # Creating the calendar to select a date
        self.scheduleCalendar.setGridVisible(True)
        self.scheduleCalendar.clicked.connect(self.loadTasksOnDate)  # On clicking a date this function is called
        self.scheduleCalendar.setStyleSheet(" ")

        self.taskDataLabel = QLabel(self)  # Label that will display if there are tasks or not
        self.taskDataLabel.setText("No Tasks Due")  # By default it will say none are due
        self.taskDataLabel.setFont(QFont('Arial', 13))

        self.tab2.layout.addWidget(self.scheduleCalendar,0,0)
        self.tab2.layout.addWidget(self.taskDataLabel,0,1)
        self.tab2.setLayout(self.tab2.layout)
        self.loadTasksOnDate()

    def createRemindersTab(self):
        self.tab3.layout = QVBoxLayout(self)

        # Creating the visual clock for scheduling
        self.clock = QTimer(self)
        self.clock.timeout.connect(self.showTime)
        self.clock.start(1000)

        self.clockLabel = QLabel(self)  # Label that shows the time

        # Each input has an accompanying label to show what it is
        # Title showing the reminders section
        self.reminderTitleLabel = QLabel(self)
        self.reminderTitleLabel.setText("Set Personal Reminder")
        self.reminderTitleLabel.setFont(QFont('Arial', 13))

        # Input for reminder title
        self.tileInputLabel = QLabel(self)
        self.tileInputLabel.setText("Title")
        self.titleInput = QLineEdit(self)

        # Checkbox to send reminder as email
        self.emailCheckBox = QCheckBox(self)
        self.emailCheckLabel = QLabel(self)
        self.emailCheckLabel.setText("Send As Email")

        # Input for reminder description
        self.descriptionInputLabel = QLabel(self)
        self.descriptionInputLabel.setText("Description")
        self.descriptionInput = QLineEdit(self)

        # Checkbox to send reminder as a desktop notification
        self.notificationCheckBox = QCheckBox(self)
        self.notificationCheckLabel = QLabel(self)
        self.notificationCheckLabel.setText("Send As Notification")

        # Input for time the reminder is due
        self.reminderTimeLabel = QLabel(self)
        self.reminderTimeLabel.setText("Set For:")
        self.reminderTime = QTimeEdit(self)

        # Button to set reminder
        self.setButton = QPushButton("Set Reminder")
        self.setButton.clicked.connect(self.setReminder)

        # Label that tells the user the reminder is set
        self.isSetLabel = QLabel(self)
        self.isSetLabel.setText(" ")

        # Title above the messaging section
        self.messageTitleLabel = QLabel(self)
        self.messageTitleLabel.setText("Send Email Reminder / Message")
        self.messageTitleLabel.setFont(QFont('Arial', 13))

        # Subject line input
        self.subjectLabel = QLabel(self)
        self.subjectLabel.setText("Subject")
        self.subjectInput = QLineEdit(self)

        # List to select recipients from
        self.recipientsLabel = QLabel(self)
        self.recipientsLabel.setText("Recipients")
        self.recipientsList = QListWidget(self)
        self.recipientsList.setSelectionMode(2)

        # Adding users to list widget
        # Fetching the first and last names of all users
        # this is used for adding to the list of users
        getUsersQuery = "SELECT FirstName, LastName FROM Users WHERE UserID!=%s" % (loggedInUserID)
        cursor.execute(getUsersQuery)
        realNames = cursor.fetchall()

        # Fetching the IDs of all the users
        # Used for assigning the task to IDs in the database
        getUsersIDsQuery = "SELECT UserID FROM Users WHERE UserID!=%s" % (loggedInUserID)
        cursor.execute(getUsersIDsQuery)
        userIDs = cursor.fetchall()
        self.userIDsList = []

        # Appending all of the fetched IDs to a list
        for record in userIDs:
            ID = record[0]
            self.userIDsList.append(ID)

        # Adding the first and last names of all users to the list
        # Allows user to set a task by selecting peoples names
        for record in realNames:
            name = record[0]
            self.recipientsList.addItem(name)

        # Setting the list size
        self.recipientsList.setMaximumHeight(70)
        self.recipientsList.setResizeMode(QListView.Fixed)

        # Input for the body of the email
        self.messageLabel = QLabel(self)
        self.messageLabel.setText("Message")
        self.messageInput = QLineEdit(self)

        # Button to send the message, calling the sendMessage function
        self.sendButton = QPushButton("Send")
        self.sendButton.clicked.connect(self.sendMessage)

        # Label that tells the user the message is sent
        self.isSentLabel = QLabel(self)
        self.isSetLabel.setText(" ")

        self.paddingLabel = QLabel(self)
        self.paddingLabel.setText("                                  ")

        self.remindersLayout = QGridLayout(self)
        self.tab3.layout.addWidget(self.clockLabel)
        self.tab3.layout.addWidget(self.reminderTitleLabel)

        # Add widgets to the reminders layout
        self.remindersLayout.addWidget(self.tileInputLabel,1,0)
        self.remindersLayout.addWidget(self.titleInput,1,1)
        self.remindersLayout.addWidget(self.emailCheckBox,1,2,Qt.AlignCenter)
        self.remindersLayout.addWidget(self.emailCheckLabel,1,3)
        self.remindersLayout.addWidget(self.descriptionInputLabel,2,0)
        self.remindersLayout.addWidget(self.descriptionInput,2,1)
        self.remindersLayout.addWidget(self.notificationCheckBox,2,2,Qt.AlignCenter)
        self.remindersLayout.addWidget(self.notificationCheckLabel,2,3)
        self.remindersLayout.addWidget(self.reminderTimeLabel,3,0)
        self.remindersLayout.addWidget(self.reminderTime,3,1)

        self.tab3.layout.addLayout(self.remindersLayout)
        self.tab3.layout.addWidget(self.setButton, alignment=Qt.AlignCenter)
        self.tab3.layout.addWidget(self.isSetLabel, alignment=Qt.AlignCenter)

        self.messagesLayout = QGridLayout(self)
        self.tab3.layout.addWidget(self.messageTitleLabel)

        # Add widgets to messages layout
        self.messagesLayout.addWidget(self.subjectLabel,0,0)
        self.messagesLayout.addWidget(self.subjectInput,0,1)
        self.messagesLayout.addWidget(self.messageLabel,1,0)
        self.messagesLayout.addWidget(self.messageInput,1,1)
        self.messagesLayout.addWidget(self.recipientsLabel,2,0)
        self.messagesLayout.addWidget(self.recipientsList,2,1)
        self.messagesLayout.addWidget(self.paddingLabel,2,2)

        self.tab3.layout.addLayout(self.messagesLayout)
        self.tab3.layout.addWidget(self.sendButton, alignment=Qt.AlignCenter)
        self.tab3.layout.addWidget(self.isSentLabel, alignment=Qt.AlignCenter)

        self.tab3.setLayout(self.tab3.layout)

    def createTimelineTab(self):
        # Create the tab layout
        self.tab4.layout = QVBoxLayout(self)
        # Create and add the web view for the gantt chart
        # Plotly can create interactive graphs using HTML/JS
        # Web view will display the HTML/JS
        self.chartWidget = QtWebEngineWidgets.QWebEngineView()
        self.tab4.layout.addWidget(self.chartWidget)
        self.tab4.setLayout(self.tab4.layout)
        self.loadGanttChart()

    def createNotesTab(self):
        self.tab5.layout = QVBoxLayout(self)

        # Initialise the file path variable as "Empty"
        self.notesFilePath = "Empty"

        # The text editor s jsut a plain text edit widget
        self.textEditor = QPlainTextEdit(self)
        self.textEditor.setFont(QFont("Arial", 10))

        # Adding a toolbar for actions e.g. save
        self.textToolBar = QToolBar(self)

        # Toolbar action for saving files
        saveFile = QAction(self)
        saveFile.setText("Save")
        saveFile.setStatusTip("Save your notes")
        saveFile.triggered.connect(self.saveFile)
        self.textToolBar.addAction(saveFile)

        # Toolbar action for saving files as..
        saveFileAs = QAction(self)
        saveFileAs.setText("Save As")
        saveFileAs.setStatusTip("Save your notes to a location")
        saveFileAs.triggered.connect(self.saveFileAs)
        self.textToolBar.addAction(saveFileAs)

        # Toolbar action for opening files
        openFile = QAction(self)
        openFile.setText("Open")
        openFile.setStatusTip("Open a text file")
        openFile.triggered.connect(self.openFile)
        self.textToolBar.addAction(openFile)

        # Toolbar action for printing files
        printFile = QAction(self)
        printFile.setText("Print")
        printFile.setStatusTip("Print your notes")
        printFile.triggered.connect(self.printFile)
        self.textToolBar.addAction(printFile)

        # Adding the layout and widgets
        self.tab5.layout.addWidget(self.textToolBar)
        self.tab5.layout.addWidget(self.textEditor)
        self.tab5.setLayout(self.tab5.layout)

    def saveFile(self):
        # If the filepath is not set, make the user choose one
        if self.notesFilePath == "Empty":
            self.saveFileAs()
        else:
            # Otherwise save to the already set path
            self.saveFileToPath(self.notesFilePath[0])

    def saveFileAs(self):
        # Open a browser to choose the file path
        chosenPath = QFileDialog.getSaveFileName(self, filter="Text documents (*.txt)")
        if chosenPath:
            # If the user has chosen a path, save the fle there using the function
            self.saveFileToPath(chosenPath[0])

    def openFile(self):
        # Open a browser to choose the file to open
        openPath = QFileDialog.getOpenFileName(self, filter="Text documents (*.txt)")
        # Check the user has set a path
        if openPath[0]:
            # Try reading the file and storing the text
            try:
                with open(openPath[0], 'r') as file:
                    textToUpdate = file.read()
            # Catch any errors and show an error window
            except Exception as error:
                self.openingError = errorWindow("Error Opening file", str(error))
            # Otherwise add the text to the editor and save the new file path
            else:
                self.notesFilePath = openPath
                self.textEditor.setPlainText(textToUpdate)

    def saveFileToPath(self, filePath):
        # Get the text in the editor
        textFromEditor = self.textEditor.toPlainText()
        try:
            # Try writing the text to the set file path
            with open(filePath, 'w') as file:
                file.write(textFromEditor)
        # Catch errors and create an error window
        except Exception as error:
            self.saveError = errorWindow("Error saving file", str(error))

    def printFile(self):
        # Open a print menu to select printing options
        printDialogue = QPrintDialog()

        # If they have set a printer print the text to that printer
        if printDialogue.exec_():
            self.textEditor.print_(printDialogue.printer())

    def loadGanttChart(self):
        # List that will be filled with dictionary objects (each one is a task)
        self.tasksDictList = []

        # Fetch the tasks assigned to the user
        fetchUserTasksIDsQuery = "SELECT TaskID FROM SetTasks WHERE UserID='%s'" % loggedInUserID
        cursor.execute(fetchUserTasksIDsQuery)
        taskIDs = cursor.fetchall()

        # Check if the user has tasks assigned to them
        if cursor.rowcount > 0:
            # For each of the tasks the user has, fetch its details and add it to the list of dict objects
            for ID in taskIDs:
                fetchTaskQuery = "SELECT Title, Due, SetOn FROM Tasks WHERE TaskID = '%s'" % ID
                cursor.execute(fetchTaskQuery)
                task = cursor.fetchall()

                self.tasksDictList.append(dict(Task=task[0][0], Start=task[0][1], Finish=task[0][2]))

            # Create the dataframe from the list of task dict objects
            self.tasksData = pd.DataFrame(self.tasksDictList)

            self.tasksFigure = px.timeline(self.tasksData, x_start="Start", x_end="Finish", y="Task")
            self.tasksFigure.update_yaxes(autorange="reversed")  # otherwise tasks are listed from the bottom up

            # Generating the html/js for the Gantt chart and storing it as variable
            self.chartCode = '<html><body>'
            # Plot the dataframe and add the HTML to the chart code variable
            self.chartCode += plotly.offline.plot(self.tasksFigure, output_type='div', include_plotlyjs='cdn')
            self.chartCode += '</body></html>'
        elif cursor.rowcount == 0:
            # If there are no tasks Display that instead of the chart
            self.chartCode = '<html><body><h1>No Tasks Set</h1></body></html>'
        # Set the HTML of the web view widget to the chart HTML
        self.chartWidget.setHtml(self.chartCode)

    def showTime(self):
        # method to constantly update the time by changing the label text
        self.currentTime = QTime.currentTime()
        self.clockString = self.currentTime.toString()
        self.clockLabel.setText(self.clockString)

    def sendMessage(self):
        # Getting the user inputs and storing them
        subject = self.subjectInput.text()
        message = self.messageInput.text()

        # Validation to check if inputs are entered
        if subject != "":
            if message != "":
                if self.recipientsList.selectedIndexes():
                    for x in self.recipientsList.selectedIndexes():
                        # for each selected user, get their email and send the message via email
                        # fetch the current user's email to say who it is from
                        # for 10 seconds, show text saying that it is sent
                        fetchEmailQuery = "SELECT Email FROM Users WHERE UserID=%s" % (self.userIDsList[x.row()])
                        cursor.execute(fetchEmailQuery)
                        email = cursor.fetchone()[0]

                        fetchUserEmailQuery = ("SELECT Email FROM users WHERE UserID='%s'" % loggedInUserID)
                        cursor.execute(fetchUserEmailQuery)
                        userEmail = cursor.fetchone()[0]

                        sendEmail(str(email), ("ProjectFly Message " + str(subject)), (str(message) + " <br>From " + str(userEmail)))

                        self.isSentLabel.setText("Message Sent!")
                        self.isSentLabel.setStyleSheet("QLabel { color : Green; }")
                        self.showEmailIsSent = Timer(10, self.restIsSentText)
                        self.showEmailIsSent.start()
                else:
                    self.noRecipients = errorWindow("No Selected Recipients", "Please select a user to email")
            else:
                self.noMessage = errorWindow("No message created", "Please enter a message to send")
        else:
            self.noSubject = errorWindow("No subject entered", "Please enter a subject for the email")

    def setReminder(self):
        # Get the user inputs, get the states of the checkboxes
        self.reminderText = self.titleInput.text()
        self.reminderDescription = self.descriptionInput.text()
        self.isEmail = self.emailCheckBox.isChecked()
        self.isNotif = self.notificationCheckBox.isChecked()

        # check if inputs are empty and if one of the boxes are checked
        if self.reminderText != "":
            if self.reminderDescription != "":
                if self.isEmail or self.isNotif:
                    # calculate the difference in seconds between the time the user set the reminder for
                    # and the current time, then execute the method after that time has elapsed
                    timeDifferenceInSeconds = QTime.currentTime().secsTo(self.reminderTime.time())
                    self.reminder = Timer(timeDifferenceInSeconds, self.sendReminder)
                    self.reminder.start()

                    self.isSetLabel.setText("Reminder Set!")
                    self.isSetLabel.setStyleSheet("QLabel { color : Green; }")
                    self.showReminderIsSet = Timer(10, self.resetIsSetText)
                    self.showReminderIsSet.start()
                else:
                    self.noChosenType = errorWindow("Reminder not set", "Please make sure you check a reminder type")
            else:
                self.noDescription = errorWindow("No description set", "Please set a description for your reminder")
        else:
            self.noTitle = errorWindow("No title set", "Please set a title for your reminder")

    def resetIsSetText(self):
        # reset the text back to invisible
        self.isSetLabel.setText(" ")
        self.isSetLabel.setStyleSheet("QLabel { color : Black; }")

    def restIsSentText(self):
        # reset the text back to invisible
        self.isSentLabel.setText(" ")
        self.isSentLabel.setStyleSheet("QLabel { color : Black; }")

    def sendReminder(self):
        # if they checked email reminder, send email with the title and description
        # if they checked notification send desktop notification with title and description
        if self.isEmail:
            sendEmail(userEmail, "ProjectFly Reminder! " + str(self.reminderText), str(self.reminderText) + "\n" + str(self.reminderDescription))
        if self.isNotif:
            toaster = ToastNotifier()
            toaster.show_toast("ProjectFly Reminder! ", self.reminderText + "\n" + self.reminderDescription,
                               icon_path="logo.ico", duration=200)

    def loadTasksOnDate(self):
        date = self.scheduleCalendar.selectedDate().toPyDate()  # Storing the selected date
        findUserTasksQuery = """SELECT TaskID FROM SetTasks WHERE UserID = '%s'""" % (loggedInUserID)
        self.tasksDueText = "Tasks Due:"
        cursor.execute(findUserTasksQuery)  # Getting the tasks stored for the user
        userTaskIds = cursor.fetchall()
        if cursor.rowcount == 0:
            self.taskDataLabel.setText("No Tasks Due")
        count = 0

        for record in userTaskIds:  # For all of the tasks assigned to the user
            fetchTaskOnDateQuery = """SELECT Title, Due FROM Tasks WHERE TaskID = '%s'""" % (record)
            cursor.execute(fetchTaskOnDateQuery)
            taskData = cursor.fetchall()

            for row in taskData: # For each task, check the date
                # if the date matches the user's chosen date, add the task
                # title to the text, set the text as the list of tasks
                # if there are no matching tasks, no tasks due
                if row[1] == date:
                    count += 1
                    self.tasksDueText += str("\n" + str(count) + ". " + str(row[0]))
                    self.taskDataLabel.setText(self.tasksDueText)
            if self.tasksDueText == "Tasks Due:":
                self.taskDataLabel.setText("No Tasks Due")

    def createTasksTable(self):
        # Create the inital widget
        self.tableLayout = QVBoxLayout(self)
        self.tasksTable = QTableWidget()
        self.tasksTable.setWordWrap(True)

        # Set the intial rowcount for the title cells
        self.tasksTable.setRowCount(1)
        self.tasksTable.setColumnCount(6)
        # Prevent user editing
        self.tasksTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.header = self.tasksTable.horizontalHeader()
        self.vHeader = self.tasksTable.verticalHeader()

        # Changing the way the table resizes
        # Making it stretch to the window and wrap text downwards
        self.vHeader.setSectionResizeMode(QHeaderView.ResizeToContents)
        self.header.setSectionResizeMode(QHeaderView.ResizeToContents)
        self.header.setMaximumSectionSize(300)
        self.header.setSectionResizeMode(1, QHeaderView.Stretch)

        # Make the headers invisible
        self.tasksTable.verticalHeader().setVisible(False)
        self.tasksTable.horizontalHeader().setVisible(False)

        # Set the title cells to tell the user what coloumns' data is
        self.tasksTable.setItem(0, 0, QTableWidgetItem("Title"))
        self.tasksTable.setItem(0, 1, QTableWidgetItem("Description"))
        self.tasksTable.setItem(0, 2, QTableWidgetItem("Priority"))
        self.tasksTable.setItem(0, 3, QTableWidgetItem("Due On"))
        self.tasksTable.setItem(0, 4, QTableWidgetItem("Set On"))
        self.tasksTable.setItem(0, 5, QTableWidgetItem("Status"))

        self.tableLayout.addWidget(self.tasksTable)
        self.tableLayout.sizeHint()

        # Call the method to populate the table with tasks
        self.populateTable()

    def populateTable(self):
        # Getting the tasks set for the user logged in
        fetchUserTaskIDsQuery = """SELECT TaskID FROM SetTasks WHERE UserID = '%s'""" % (loggedInUserID)
        cursor.execute(fetchUserTaskIDsQuery)
        fetchedTaskIDs = cursor.fetchall()

        # Y must start at 1 to not override the title cells
        y = 1

        # Check if there are tasks to add or not
        if cursor.rowcount != 0:
            for record in fetchedTaskIDs:
                # Increase the row count of the table for each task added
                self.tasksTable.setRowCount(y+1)
                # Fetch the tasks using all the ids of tasks set for the user
                fetchTaskDataQuery = """SELECT `Title`, `Description`, `Priority`, `Due`, `SetOn`, `Status` FROM Tasks WHERE TaskID = '%s'""" % (record)
                cursor.execute(fetchTaskDataQuery)
                taskData = cursor.fetchall()

                # Setting each field as the fields from the fetched task, the counter determines the y position
                self.tasksTable.setItem(y, 0, QTableWidgetItem(taskData[0][0]))
                self.tasksTable.setItem(y, 1, QTableWidgetItem(taskData[0][1]))
                self.tasksTable.setItem(y, 2, QTableWidgetItem(str(taskData[0][2])))
                self.tasksTable.setItem(y, 3, QTableWidgetItem(str(taskData[0][3])))
                self.tasksTable.setItem(y, 4, QTableWidgetItem(str(taskData[0][4])))

                # Converting the status bool to actual words
                if taskData[0][5] == 1:
                    self.tasksTable.setItem(y, 5, QTableWidgetItem("Complete"))
                else:
                    self.tasksTable.setItem(y, 5, QTableWidgetItem("Unfinished"))

                # Increment to next table row
                y+=1

            self.tasksTable.resizeColumnsToContents()

        # If there are no tasks, delete any existing table rows to refresh
        else:
            while self.tasksTable.rowCount() > 1:
                self.tasksTable.removeRow(1)

    def setTask(self):
        self.setTaskWindow = setTaskWindow()

    def editTask(self):
        # Checks if tasks are available to edit before opening
        checkTasksExitQuery = "SELECT EXISTS (SELECT 1 FROM Tasks)"
        cursor.execute(checkTasksExitQuery)
        tasksCheck = cursor.fetchone()[0]

        if tasksCheck == 1:
            self.editTaskWindow = editTaskWindow()
        else:
            self.noTasksError = errorWindow("No Tasks to Edit", "Please ensure there are tasks to edit before editing")

    def exportTasks(self):
        # Checks if tasks are available to edit before opening
        checkTasksExitQuery = "SELECT EXISTS (SELECT 1 FROM Tasks)"
        cursor.execute(checkTasksExitQuery)
        tasksCheck = cursor.fetchone()[0]

        if tasksCheck == 1:
            self.exportTasksWindow = exportTasksWindow()
        else:
            self.noTasksError = errorWindow("No Tasks to Export", "Please ensure there are tasks to export before exporting")

    def logout(self):
        global loggedIn
        global loggedInID
        self.close()  # closing the main window
        self.Login = loginWindow()  # opening the login window
        loggedIn = False
        loggedInID = False

    def helpAndThemes(self):
        self.helpMenu = helpThemesMenu()

    def closeApplication(self):
        sys.exit("application closed")  # Exiting the program

class helpThemesMenu(QtWidgets.QMainWindow):
    def __init__(self):
        # Initialising the window
        super(helpThemesMenu, self).__init__()
        self.centralWidget = QWidget() # Centralising Widgets
        self.setCentralWidget(self.centralWidget)
        self.setGeometry(50, 50, 500, 400)  # setting the window geometry
        self.setFixedSize(self.size())  # preventing resizing
        self.setWindowTitle("Settings")  # setting window title
        self.setWindowIcon(QtGui.QIcon("logo.ico"))  # setting window icon

        self.buildWindow()  # Adding widgets

    def buildWindow(self):
        # Window is made of 1 main layout and 2 nested layouts
        self.settingsLayout = QVBoxLayout() # The main layout

        self.helpLayout = QGridLayout() # The layout for help messages
        self.helpLayout.setColumnStretch(1, 1)
        self.helpLayout.setRowStretch(1, 1)

        # Title to show the help section
        self.helpTitle = QLabel(self)
        self.helpTitle.setText("About the software")
        self.helpTitle.setFont(QFont('Arial', 14))

        # Text that will change based on each help topic
        self.helpText = QLabel(self)
        self.helpText.setFont(QFont('Arial', 9))
        self.helpText.setText("""\nChoose a topic to learn about the program.""")

        # Dropdown of topics user can get help with
        self.topicDropdown = QComboBox(self)
        self.topicDropdown.addItem("Choose a topic")
        self.topicDropdown.addItem("Accounts")
        self.topicDropdown.addItem("Tasks")
        self.topicDropdown.addItem("Schedule Tab")
        self.topicDropdown.addItem("Reminders")
        self.topicDropdown.addItem("Messaging")
        self.topicDropdown.addItem("Timeline")
        self.topicDropdown.addItem("Settings")

        # List of the different help messages for each topic
        # Text correlates to each topic in the dropdown in order
        self.helpList = ["""
Choose a topic to learn about the program.
Please contact jasonrowson@gmail.com for any issues.
                         """,
                         """
Create an account from the login screen,
your account is personalised and holds your tasks and data privately
others can send you messages or set tasks to your account.
                         """,
                         """
Set a task from the objectives tab, tasks are only seen
by the person who set it and the people they are assigned to
tasks can be edited, deleted and exported from the objectives
tab. Tasks have a priority system where 10 is most important
and 1 is less of a priority.
                         """,
                         """
The schedule tab allows you to select dates on a calendar
to see which days have tasks due on them and which 
days have none set.
                         """,
                         """
Reminders can be sent as an email or desktop notification
enter your reminder title and a description of what should be done
and at the time you set you will either be sent an email or
desktop notification with this info depending on your choice
                         """,
                         """
The reminders tab also lets you message other project members
this will send them an email with the information you set.
                         """,
                         """
The timeline tab is a visual representation of your task deadlines
it creates a Gantt chart from your personal tasks to help
better manage your ongoing tasks.
                         """,
                         """
The settings menu, what you now have open, lets you learn about
the program, change the appearance of the program (this choice
will stay after the program closes) or update your account info."""]

        # On changing the topic, load the text for that new topic
        self.topicDropdown.currentIndexChanged.connect(self.showHelpMessage)

        # Layout for the next section, themes
        self.themeLayout = QGridLayout(self)
        self.themeLayout.setColumnStretch(1, 1)
        self.themeLayout.setRowStretch(1, 1)

        # Title to show the next section
        self.themeLabel = QLabel(self)
        self.themeLabel.setText("Program Theme")
        self.themeLabel.setFont(QFont('Arial', 14))

        # Dropdown to select the theme // add more in future
        self.themeDropdown = QComboBox(self)
        self.themeDropdown.addItem("Light")
        self.themeDropdown.addItem("Dark")
        self.themeDropdown.setMinimumWidth(30)

        # Button to apply the selected theme
        self.applyThemeButton = QPushButton("Apply Theme")
        self.applyThemeButton.clicked.connect(self.changeTheme)
        self.applyThemeButton.sizeHint()

        self.accountLayout = QGridLayout()

        self.accountTitle = QLabel(self)
        self.accountTitle.setText("Account")
        self.accountTitle.setFont(QFont("Arial", 14))

        self.newEmailLabel = QLabel(self)
        self.newEmailLabel.setText("Set New Email")
        self.newEmailInput = QLineEdit(self)

        self.newUserLabel = QLabel(self)
        self.newUserLabel.setText("Set New Username")
        self.newUserInput = QLineEdit(self)

        self.newFirstNameLabel = QLabel(self)
        self.newFirstNameLabel.setText("Set New First Name")
        self.newFirstNameInput = QLineEdit(self)

        self.newLastNameLabel = QLabel(self)
        self.newLastNameLabel.setText("Set New Last Name")
        self.newLastNameInput = QLineEdit(self)

        self.newPasswordLabel = QLabel(self)
        self.newPasswordLabel.setText("Set New Password")
        self.newPasswordInput = QLineEdit(self)


        self.updateAccountButton = QPushButton("Update Account")
        self.updateAccountButton.clicked.connect(self.updateAccount)

        self.accountLayout.addWidget(self.newEmailLabel, 0,0)
        self.accountLayout.addWidget(self.newEmailInput, 0,1)
        self.accountLayout.addWidget(self.newUserLabel, 0,2)
        self.accountLayout.addWidget(self.newUserInput, 0,3)

        self.accountLayout.addWidget(self.newFirstNameLabel, 1,0)
        self.accountLayout.addWidget(self.newFirstNameInput, 1,1)
        self.accountLayout.addWidget(self.newLastNameLabel, 1,2)
        self.accountLayout.addWidget(self.newLastNameInput, 1,3)

        self.accountLayout.addWidget(self.newPasswordLabel, 2,0)
        self.accountLayout.addWidget(self.newPasswordInput, 2,1)

        # Adding widgets to respective layouts
        # Adding the help + themes layout to the main layout
        self.helpLayout.addWidget(self.helpText,0,0,alignment=Qt.AlignLeft)

        self.themeLayout.addWidget(self.themeDropdown,0,0, alignment=Qt.AlignCenter)
        self.themeLayout.addWidget(self.applyThemeButton,0,1,)

        self.settingsLayout.addWidget(self.helpTitle)
        self.settingsLayout.addLayout(self.helpLayout)
        self.settingsLayout.addWidget(self.topicDropdown, alignment=Qt.AlignLeft)
        self.settingsLayout.addWidget(self.themeLabel)
        self.settingsLayout.addLayout(self.themeLayout)
        self.settingsLayout.addWidget(self.accountTitle)
        self.settingsLayout.addLayout(self.accountLayout)
        self.settingsLayout.addWidget(self.updateAccountButton)

        # Showing the window
        self.setLayout(self.settingsLayout)
        self.centralWidget.setLayout(self.settingsLayout)
        self.show()

    def updateAccount(self):
        connectDatabase()
        # Get the inputs from the user
        newUser = self.newUserInput.text()
        newEmail = self.newEmailInput.text()
        newFirst = self.newFirstNameInput.text()
        newLast = self.newLastNameInput.text()
        newPass = self.newPasswordInput.text()

        # Fetch the users existing account data
        fetchAccountQuery = "SELECT Username, Email, FirstName, LastName, Pass FROM Users WHERE UserID = '%s'" % loggedInUserID
        cursor.execute(fetchAccountQuery)
        userAccount = cursor.fetchall()

        # If any of the inputs are unfilled, set them to the original account data
        if newUser == "":
            newUser = userAccount[0][0]
        if newEmail == "":
            newEmail = userAccount[0][1]
        if newFirst == "":
            newFirst = userAccount[0][2]
        if newLast == "":
            newLast = userAccount[0][3]
        if newPass == "":
            newPass = userAccount[0][4]

        # If there is a valid email address
        if "@" in newEmail and "." in newEmail:  # check email is valid
            # If the password is secure
            if len(newPass) > 7:
                # If the user has chosen a new password hash the new one with the salt
                # Convert the new hashed pass to hex
                if newPass != userAccount[0][4]:
                    fetchSaltQuery = "SELECT Salt FROM Users WHERE UserID = '%s'" % loggedInUserID
                    cursor.execute(fetchSaltQuery)
                    salt = bytes.fromhex(cursor.fetchone()[0])
                    newPass = hashlib.pbkdf2_hmac('sha256', newPass.encode('utf-8'), salt, 100000)
                    newPass = newPass.hex()

                # Store all the new information along with the existing data for unchanged fields
                newAccountQuery = "UPDATE Users SET Username='%s', Email='%s', FirstName='%s', LastName='%s', Pass='%s' WHERE UserID = '%s'" % (
                    newUser, newEmail, newFirst, newLast, newPass, loggedInUserID)

                cursor.execute(newAccountQuery)
                database.commit()
                connectDatabase()
                self.close()

            else:
                self.shortPassword = errorWindow("Short Password", "Please ensure your password is longer than 7 characters")
        else:
            self.invalidEmail = errorWindow("Invalid email", "Please ensure you have entered a valid email address")

    # Runs when the user applies a theme
    def changeTheme(self):
        # get the index of the selected theme in the dropdown
        themeChoice = self.themeDropdown.currentIndex()

        # If they choose light theme
        if themeChoice == 0:
            # update theme preference in the database so it remains after closing
            updateThemeQuery = "UPDATE Users SET DarkTheme = %s WHERE UserID = %s" % (themeChoice, loggedInUserID)
            cursor.execute(updateThemeQuery)
            database.commit()
            styleSheet="Light.qss"  # Change the style sheet file name to light

        # If they choose dark theme
        elif themeChoice == 1:
            # update theme preference in the database
            updateThemeQuery = "UPDATE Users SET DarkTheme = %s WHERe UserID = %s" % (themeChoice, loggedInUserID)
            cursor.execute(updateThemeQuery)
            database.commit()
            styleSheet="Dark.qss"  # Change the style sheet file name to Dark

        # Open the stylesheet, depends on the variable which is set based on user choice
        # Set the style sheet to the text read in the style sheet file
        with open(os.path.join(sys.path[0], styleSheet), "r") as f:
            app.setStyleSheet(f.read())
        f.close()

    def showHelpMessage(self):
        # Set the text in the help label to the text in the list of help messages
        # that corresponds to the topic chosen, done by indexes
        self.helpText.setText(self.helpList[self.topicDropdown.currentIndex()])

class setTaskWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(setTaskWindow, self).__init__()
        self.centralWidget = QWidget() # Centralising Widgets
        self.setCentralWidget(self.centralWidget)
        self.setGeometry(50, 50, 500, 350)  # setting the window geometry
        self.setFixedSize(self.size())  # preventing resizing
        self.setWindowTitle("Set Task")  # setting window title
        self.setWindowIcon(QtGui.QIcon("logo.ico"))  # setting window icon

        self.buildWindow()  # calling method to build the GUI

    def buildWindow(self):
        # Creating the layout as a grid, setting the stretch limits of columns and rows
        self.GLayout = QGridLayout()
        self.GLayout.setColumnStretch(1, 1)
        self.GLayout.setRowStretch(1, 1)

        # Creating the 'new task' text label
        self.newTaskLabel = QLabel(self)
        self.newTaskLabel.setText("New Task")
        self.newTaskLabel.setFont(QFont('Arial', 20))

        # Creating the title form and accompanying text
        self.titleLabel = QLabel(self)
        self.titleLabel.setText("Title")
        self.titleLabel.setFont(QFont('Arial', 13))
        self.titleForm = QLineEdit(self)

        # Creating the description form and accompanying text
        self.descLabel = QLabel(self)
        self.descLabel.setText("Description")
        self.descLabel.setFont(QFont('Arial', 13))
        self.descForm = QLineEdit(self)

        # Creating the priority dropdown and accompanying text
        self.priorLabel = QLabel(self)
        self.priorLabel.setText("Priority")
        self.priorLabel.setFont(QFont('Arial', 13))
        self.priorDropdown = QComboBox(self)
        # Adding numbers 1 to 10 to the dropdown
        for i in range(0, 10):
            self.priorDropdown.addItem(str(i + 1))

        # Creating the list of people to set the task for and the accompanying text
        self.targetUsersLabel = QLabel(self)
        self.targetUsersLabel.setText("For Members")
        self.targetUsersLabel.setFont(QFont('Arial', 13))
        self.targetUsersList = QListWidget(self)
        # Allowing multiple selection for multiple users
        self.targetUsersList.setSelectionMode(2)

        # Setting the list size and fixating it
        self.targetUsersList.setMaximumWidth(500)
        self.targetUsersList.setMaximumHeight(70)
        self.targetUsersList.setResizeMode(QListView.Fixed)

        # Fetching the first and last names of all users
        # this is used for adding to the list of users
        getUsersQuery = "SELECT FirstName, LastName FROM Users"
        cursor.execute(getUsersQuery)
        realNames = cursor.fetchall()

        # Fetching the IDs of all the users
        # Used for assigning the task to IDs in the database
        getUsersIDsQuery = "SELECT UserID FROM Users"
        cursor.execute(getUsersIDsQuery)
        userIDs = cursor.fetchall()
        self.userIDsList = []

        # Appending all of the fetched IDs to a list
        for record in userIDs:
            ID = record[0]
            self.userIDsList.append(ID)

        # Adding the first and last names of all users to the list
        # Allows user to set a task by selecting peoples names
        for record in realNames:
            name = record[0]
            self.targetUsersList.addItem(name)

        # Creating the date input box and accompanying text
        self.dueDateLabel = QLabel(self)
        self.dueDateLabel.setText("Due Date")
        self.dueDateLabel.setFont(QFont('Arial', 13))
        # The date input is set to only allow dates in the future
        # The user can use a calendar popup for selection of a date
        self.dueDateEdit = QDateEdit(self)
        self.dueDateEdit.setCalendarPopup(True)
        self.dueDateEdit.setDate(QDate.currentDate())
        self.dueDateEdit.setMinimumDate(QDate.currentDate())

        # Creating the set task button that calls the set task method
        self.setTaskButton = QPushButton("Set Task")
        self.setTaskButton.clicked.connect(self.setTask)

        # Creating the cancel button that calls the cancel task method
        self.cancelButton = QPushButton("Cancel")
        self.cancelButton.clicked.connect(self.close)

        # Adding all of the created widgets above to the layout
        # Grid layout uses coordinates to organise widgets
        self.GLayout.addWidget(self.newTaskLabel, 0, 0)
        self.GLayout.addWidget(self.titleLabel, 1, 0)
        self.GLayout.addWidget(self.titleForm, 1, 1)
        self.GLayout.addWidget(self.descLabel, 2, 0)
        self.GLayout.addWidget(self.descForm, 2, 1)
        self.GLayout.addWidget(self.priorLabel, 3, 0)
        self.GLayout.addWidget(self.priorDropdown, 3, 1)
        self.GLayout.addWidget(self.targetUsersLabel, 4, 0)
        self.GLayout.addWidget(self.targetUsersList, 4, 1)
        self.GLayout.addWidget(self.dueDateLabel, 5, 0)
        self.GLayout.addWidget(self.dueDateEdit, 5, 1)
        self.GLayout.addWidget(self.cancelButton, 6, 0)
        self.GLayout.addWidget(self.setTaskButton, 6, 1)

        # Setting the layout for the window as the grid layout
        # Showing the window
        self.setLayout(self.GLayout)
        self.centralWidget.setLayout(self.GLayout)
        self.show()

    def setTask(self):
        # Retrieving the text/data in the input boxes for setting a task
        titleInput = self.titleForm.text()
        descriptionInput = self.descForm.text()
        priorityInput = int(self.priorDropdown.currentText())
        # Formatting the dates in order to store in DB
        dueDateInput = str(self.dueDateEdit.date().toPyDate())
        setDate = str(QDate.currentDate().toPyDate())

        # List that will contain the index of the selected users
        # within the list widget
        self.selectedUsersIndex = []
        # for all of the selected users, adds their index to the list in order
        # These indexes can be used to fetch the IDs of the selected users
        # These IDs come from the userIDsList created further up
        for x in self.targetUsersList.selectedIndexes():
            self.selectedUsersIndex.append(x.row())

        if titleInput != "":
            if priorityInput != "":
                if descriptionInput != "":
                    if self.selectedUsersIndex:
                        # Adding the details of the task to the tasks table
                        setTaskQuery = '''INSERT INTO `projectdb`.`tasks` (`Title`, `Description`, `Priority`, `Due`, `SetOn`, `Status`) VALUES 
                        ('%s', '%s', '%s', '%s', '%s', %s)''' % (titleInput, descriptionInput, priorityInput, dueDateInput, setDate, False)
                        cursor.execute(setTaskQuery)
                        database.commit()

                        # Query that will fetch the ID of the task that we just added
                        # This is used for assigning the task to userIDs in the set tasks table
                        # Done by getting the biggest ID, since that will always be the last task added due to auto increment
                        getLatestTaskQuery = "SELECT TaskID FROM `Tasks` ORDER BY TaskID DESC LIMIT 1"
                        cursor.execute(getLatestTaskQuery)
                        latestTaskID = cursor.fetchone()[0]

                        # Fetch the name of the user that just set the task
                        fetchTaskOwner = '''SELECT FirstName, LastName FROM USERS WHERE UserID = ('%s')''' % (loggedInUserID)
                        cursor.execute(fetchTaskOwner)
                        taskOwner = cursor.fetchone()[0]

                        # For the number of users the task will be set for
                        # Assign the task to each selected user in the set tasks table by referencing the task and user IDs
                        for x in self.selectedUsersIndex:
                            if self.userIDsList[x] != loggedInUserID:
                                # Assign the task by using the latest task ID and the user ID from the list of userIDs but at the index of the selected users in the list widget
                                addTaskQuery = '''INSERT INTO `projectdb`.`settasks` (`TaskID`, `UserID`) VALUES ('%s', '%s')''' % (latestTaskID, self.userIDsList[x])
                                cursor.execute(addTaskQuery)
                                database.commit()

                                # Fetch the email of the user that just got a task assigned
                                fetchEmailQuery = '''SELECT Email FROM Users WHERE UserID = ('%s')''' % (self.userIDsList[x])
                                cursor.execute(fetchEmailQuery)
                                email = cursor.fetchone()[0]

                                # Email the user being set the task containing its details and who set it
                                sendEmail(email, "You have been assigned a new task on ProjectFly", f"Title: {titleInput} <br>" 
                                                                                                    f"Description: {descriptionInput} <br>"
                                                                                                    f"Due on: {dueDateInput}<br>"
                                                                                                    f"Set By: {taskOwner}<br>"
                                                                                                    f"Priority: {priorityInput}/10<br>")

                        # Adding the task for to the user that set it so they can see it and update it
                        addOwnerTaskQuery = '''INSERT INTO `projectdb`.`settasks` (`TaskID`, `UserID`) VALUES ('%s', '%s')''' % (latestTaskID, loggedInUserID)
                        cursor.execute(addOwnerTaskQuery)
                        database.commit()
                        connectDatabase()
                        mainProgram.populateTable()
                        mainProgram.loadGanttChart()
                        self.close()
                    if not self.selectedUsersIndex:
                        self.noTargets = errorWindow("No Selected Members", "Please choose a person/s to assign a task to")
                if descriptionInput == "":
                    self.noDesc = errorWindow("No Task Description", "Please write a description of the task")
            if priorityInput == "":
                self.noPriority = errorWindow("No Selected Priority", "Please choose a task priority 1-10")
        if titleInput == "":
            self.noTitle = errorWindow("No Task Title", "Please write a title for the task")

class editTaskWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(editTaskWindow, self).__init__()
        self.centralWidget = QWidget() # Centralising Widgets
        self.setCentralWidget(self.centralWidget)
        self.setGeometry(50, 50, 500, 350)  # setting the window geometry
        self.setFixedSize(self.size())  # preventing resizing
        self.setWindowTitle("Edit Task")  # setting window title
        self.setWindowIcon(QtGui.QIcon("logo.ico"))  # setting window icon

        self.buildWindow()  # calling method to build the GUI

    def buildWindow(self):
        # Creating the layout as a grid, setting the stretch limits of columns and rows
        self.GLayout = QGridLayout()
        self.GLayout.setColumnStretch(1, 1)
        self.GLayout.setRowStretch(1, 1)

        # Creating the edit task label
        self.editTaskLabel = QLabel(self)
        self.editTaskLabel.setText("Edit Task")
        self.editTaskLabel.setFont(QFont('Arial', 20))

        # Creating the list of people to set the task for and the accompanying text
        self.targetTaskLabel = QLabel(self)
        self.targetTaskLabel.setText("Task to Edit")
        self.targetTaskLabel.setFont(QFont('Arial', 13))
        self.targetTaskDropdown = QComboBox(self)

        selectTasksQuery = """SELECT TaskID FROM SetTasks WHERE UserID = '%s'""" % (loggedInUserID)
        cursor.execute(selectTasksQuery)
        taskIDs = cursor.fetchall()

        self.taskIDsList = []

        # Adding the tasks that can be edited to the list
        # Adding the IDs of these tasks to a list for editing/deleting
        for record in taskIDs:
            ID = record[0]
            fetchTaskTitlesQuery = """SELECT Title FROM Tasks WHERE TaskID = '%s'""" % (record)
            self.taskIDsList.append(ID)
            cursor.execute(fetchTaskTitlesQuery)
            taskTitle = cursor.fetchone()[0]
            self.targetTaskDropdown.addItem(taskTitle)

        # Creating the title form and accompanying text
        self.titleLabel = QLabel(self)
        self.titleLabel.setText("Title")
        self.titleLabel.setFont(QFont('Arial', 13))
        self.titleForm = QLineEdit(self)

        # Creating the description form and accompanying text
        self.descLabel = QLabel(self)
        self.descLabel.setText("Description")
        self.descLabel.setFont(QFont('Arial', 13))
        self.descForm = QLineEdit(self)

        # Creating the priority dropdown and accompanying text
        self.priorLabel = QLabel(self)
        self.priorLabel.setText("Priority")
        self.priorLabel.setFont(QFont('Arial', 13))
        self.priorDropdown = QComboBox(self)
        # Adding numbers 1 to 10 to the dropdown
        for i in range(0, 10):
            self.priorDropdown.addItem(str(i + 1))

        # Creating the date input box and accompanying text
        self.dueDateLabel = QLabel(self)
        self.dueDateLabel.setText("Due Date")
        self.dueDateLabel.setFont(QFont('Arial', 13))
        # The date input is set to only allow dates in the future
        # The user can use a calendar popup for selection of a date
        self.dueDateEdit = QDateEdit(self)
        self.dueDateEdit.setCalendarPopup(True)
        self.dueDateEdit.setDate(QDate.currentDate())
        self.dueDateEdit.setMinimumDate(QDate.currentDate())

        # Creating the status dropdown menu
        self.statusLabel = QLabel(self)
        self.statusLabel.setText("Status")
        self.statusLabel.setFont(QFont('Arial', 13))
        self.statusDropDown = QComboBox(self)
        self.statusDropDown.addItem("Unfinished")
        self.statusDropDown.addItem("Complete")

        # Creating the set task button that calls the set task method
        self.updateTaskButton = QPushButton("Update Task")
        self.updateTaskButton.clicked.connect(self.editTask)

        # Creating the cancel button that cancels editing
        self.cancelButton = QPushButton("Cancel")
        self.cancelButton.clicked.connect(self.close)

        # Creating the delete task button that calls the delete task method
        self.deleteTaskButton = QPushButton("Delete Task")
        self.deleteTaskButton.clicked.connect(self.deleteTask)

        # Adding widgets to layout
        self.GLayout.addWidget(self.editTaskLabel, 0, 0)
        self.GLayout.addWidget(self.targetTaskLabel, 1, 0)
        self.GLayout.addWidget(self.targetTaskDropdown, 1, 1)
        self.GLayout.addWidget(self.titleLabel, 2, 0)
        self.GLayout.addWidget(self.titleForm, 2, 1)
        self.GLayout.addWidget(self.descLabel, 3, 0)
        self.GLayout.addWidget(self.descForm, 3, 1)
        self.GLayout.addWidget(self.priorLabel, 4, 0)
        self.GLayout.addWidget(self.priorDropdown, 4, 1)
        self.GLayout.addWidget(self.dueDateLabel, 5, 0)
        self.GLayout.addWidget(self.dueDateEdit, 5, 1)
        self.GLayout.addWidget(self.statusLabel, 6, 0)
        self.GLayout.addWidget(self.statusDropDown, 6, 1)
        self.GLayout.addWidget(self.cancelButton, 7, 0)
        self.GLayout.addWidget(self.updateTaskButton, 7, 1)
        self.GLayout.addWidget(self.deleteTaskButton, 7, 2)

        self.setLayout(self.GLayout)
        self.centralWidget.setLayout(self.GLayout)
        self.show()

    def editTask(self):
        # Get the details from the input boxes
        # The selected task is determined by getting the item from the taskIDs list
        # By using the index of the selected task in the dropdown menu
        selectedTaskID = self.taskIDsList[self.targetTaskDropdown.currentIndex()]

        fetchSelectedTaskQuery = """SELECT `Title`, `Description`, `Priority`, `Due`, `Status` FROM Tasks WHERE TaskID = '%s'""" % (selectedTaskID)
        cursor.execute(fetchSelectedTaskQuery)
        fetchedSelectedTaskData = cursor.fetchall()

        newTitle = self.titleForm.text()
        newDescription = self.descForm.text()
        newPrior = self.priorDropdown.currentText()
        newDueDate = self.dueDateEdit.date().toPyDate()
        newStatus = self.statusDropDown.currentIndex()

        # if data is unchanged in an option, set the data to be stored as the original task data
        if newTitle == "":
            newTitle = fetchedSelectedTaskData[0][0]
        if newDescription == "":
            newDescription = fetchedSelectedTaskData[0][1]
        if newPrior == "":
            newPrior = fetchedSelectedTaskData[0][2]
        if newDueDate == "":
            newDueDate = fetchedSelectedTaskData[0][3]
        if newStatus == "":
            newStatus = fetchedSelectedTaskData[0][4]

        # Run the query to update the task using the stored data from the input forms
        updateTaskQuery = """UPDATE Tasks SET Title = '%s', Description = '%s', Priority = '%s', Due = '%s', Status = '%s' WHERE TaskID = '%s'""" \
                          % (newTitle, newDescription, newPrior, newDueDate, newStatus, selectedTaskID)
        cursor.execute(updateTaskQuery)
        database.commit()
        connectDatabase()
        mainProgram.populateTable()
        mainProgram.loadGanttChart()
        self.close()

    def deleteTask(self):
        # Get the ID of the task that is selected
        selectedTaskID = self.taskIDsList[self.targetTaskDropdown.currentIndex()]
        # Delete task from the set tasks table first, otherwise error due to references
        deleteSetTasks = """DELETE FROM SetTasks WHERE TaskID = '%s'""" % (selectedTaskID)
        # Delete task from the task table
        deleteTask = """DELETE FROM Tasks WHERE TaskID = '%s'""" % (selectedTaskID)
        cursor.execute(deleteSetTasks)
        cursor.execute(deleteTask)
        database.commit()
        connectDatabase()
        mainProgram.populateTable()
        mainProgram.loadGanttChart()

        self.close()

class exportTasksWindow(QtWidgets.QMainWindow):
    def __init__(self):
        # Creating the initial window
        super(exportTasksWindow, self).__init__()
        self.centralWidget = QWidget() # Centralising Widgets
        self.setCentralWidget(self.centralWidget)
        self.setGeometry(50, 50, 500, 350)  # setting the window geometry
        self.setFixedSize(self.size())  # preventing resizing
        self.setWindowTitle("Export Tasks")  # setting window title
        self.setWindowIcon(QtGui.QIcon("logo.ico"))  # setting window icon

        self.buildWindow()  # calling method to build the GUI

    def buildWindow(self):
        # Creating the layout for widgets
        self.GLayout = QGridLayout()

        # Creating the export tasks label
        self.exportTasksLabel = QLabel(self)
        self.exportTasksLabel.setText("Export Tasks")
        self.exportTasksLabel.setFont(QFont('Arial', 20))

        # Creating the label for the title input and the input box
        self.fileTitleLabel = QLabel(self)
        self.fileTitleLabel.setText("File Name")
        self.fileTitleLabel.setFont(QFont('Arial', 13))
        self.fileTitle = QLineEdit(self)

        # Creating the label for the tasks choice list and the list itself
        self.tasksToExportTitle = QLabel(self)
        self.tasksToExportTitle.setText("Tasks To Export")
        self.tasksToExportTitle.setFont(QFont('Arial', 13))
        self.tasksToExport = QListWidget(self)
        self.tasksToExport.setSelectionMode(2)

        # Fetching the tasks for the user that is logged in
        fetchUserTaskIDsQuery = """SELECT TaskID FROM SetTasks WHERE UserID = '%s'""" % (loggedInUserID)
        cursor.execute(fetchUserTaskIDsQuery)
        fetchedIDs = cursor.fetchall()

        # Adding the ids of these tasks to a list
        # Adding the names of the tasks to the list used to select tasks to export
        self.taskIDsList = []
        if cursor.rowcount != 0:
            for record in fetchedIDs:
                ID = record[0]
                self.taskIDsList.append(ID)
                fetchTaskTitleQuerey = """SELECT Title FROM Tasks WHERE TaskID = '%s'""" % (ID)
                cursor.execute(fetchTaskTitleQuerey)
                Title = cursor.fetchall()
                self.tasksToExport.addItem(Title[0][0])

        self.exportPath = ""

        # Label for choosing the file path and the line edit where the path will show
        self.filePathLabel = QLabel(self)
        self.filePathLabel.setText("Export To")
        self.filePathLabel.setFont(QFont('Arial', 13))
        self.filePath = QLineEdit(self)
        self.filePath.setReadOnly(True) # Path cannot be manually edited, must use the browse button

        # Button to browse filepath to export to
        self.browseButton = QPushButton("Browse")
        self.browseButton.clicked.connect(self.browsePath)

        # Button to export the tasks
        self.exportButton = QPushButton("Export")
        self.exportButton.clicked.connect(self.export)

        # Button to cancel exporting
        self.cancelButton = QPushButton("Cancel")
        self.cancelButton.clicked.connect(self.close)

        # Adding widgets to the layout in correct order / grid layout
        self.GLayout.addWidget(self.exportTasksLabel, 0, 0)
        self.GLayout.addWidget(self.fileTitleLabel, 1, 0)
        self.GLayout.addWidget(self.fileTitle, 1, 1)
        self.GLayout.addWidget(self.filePathLabel, 2, 0)
        self.GLayout.addWidget(self.filePath, 2, 1)
        self.GLayout.addWidget(self.browseButton, 3, 1)
        self.GLayout.addWidget(self.tasksToExportTitle, 4, 0)
        self.GLayout.addWidget(self.tasksToExport, 4, 1)
        self.GLayout.addWidget(self.exportButton, 5, 0)
        self.GLayout.addWidget(self.cancelButton, 5, 1)

        # Setting the layout and showing the window
        self.setLayout(self.GLayout)
        self.centralWidget.setLayout(self.GLayout)
        self.show()

    def browsePath(self):
        # Opening a file dialoge and storing the directory chosen by the user
        # Showing the user the selected path by changing the line edit text
        self.exportPath = QFileDialog.getExistingDirectory()
        self.filePath.setText(str(self.exportPath))

    def export(self):
        self.tasksToExportIndexes = []

        # Adding the indexes to the list from the list widget
        for x in self.tasksToExport.selectedIndexes():
            self.tasksToExportIndexes.append(x.row())

        forbiddenCharacters = [r"/", r"\\", r":", r"*", r">", r"<", r"|", r'"']
        fileNameInput = str(self.fileTitle.text())

        if not any(x in fileNameInput for x in forbiddenCharacters):
            if fileNameInput:
                if self.exportPath:
                    if self.tasksToExportIndexes:
                        # Creating the file name from the input box and adding the format
                        fileName = self.fileTitle.text() + ".txt"
                        # Calling the function to generate the text to export
                        self.formatTasks()

                        # Creating the complete filepath including the file name
                        completePath = str(self.exportPath + "/" + fileName)
                        # Opening the file in write mode
                        exportFile = open(completePath, "w")
                        # Writing the tasks to the file
                        exportFile.write(self.textToWrite)
                        # Closing the file and window
                        exportFile.close()
                        self.close()
                    else:
                        self.noTasksSelected = errorWindow("No Tasks Selected", "Please select some tasks to export")
                else:
                    self.noFilePath = errorWindow("No file path chosen", "Please hit 'browse' and select a file path to export to")
            else:
                self.noFileName = errorWindow("No File Name", "Please type a name for your file")
        else:
            self.badCharacters = errorWindow("Bad Characters", "Please avoid using these characters in the file name:\n / \ : * > < | \"")

    def formatTasks(self):
        # Creating the list to store the indexes of the items the user has selected in the list
        # Creating the count for numbering tasks
        count = 1

        # Creating the initial string of text that will be written to the file
        self.textToWrite = "Title\nDescription\nDue Date\nSet Date\n\n"

        # For the number of selected tasks, fetch the details of each task from the Db
        # Then add the details to the string in a spaced out manner
        for taskIndex in self.tasksToExportIndexes:
            selectTasksDataQuery = "SELECT Title, Description, Due, SetOn FROM Tasks WHERE TaskID = '%s'" % (self.taskIDsList[taskIndex])
            cursor.execute(selectTasksDataQuery)
            taskData = cursor.fetchall()

            # Add the description, due, set to the string
            self.textToWrite += str(count) + ". " + str(taskData[0][0]) + "\n"
            self.textToWrite += str(taskData[0][1]) + "\n"
            self.textToWrite += str(taskData[0][2]) + "\n"
            self.textToWrite += str(taskData[0][3]) + "\n\n"

            # Increment coutn after the task is added
            count += 1

def run():
    global Login
    global dbConnected
    global app

    app = QtWidgets.QApplication(sys.argv)
    
    # try catch to check if there is a successful database connection
    try:
        connectDatabase()
    except:
        # Show an error window and prevent the program for running further if connection fails
        dbConnected = False
        connectionError = errorWindow("Connection error", "Error connecting to database " + str(sys.exc_info()[0]))
        connectionError.show()
        sys.exit(app.exec_())

    if dbConnected:
        Login = loginWindow()
        Login.show()

        sys.exit(app.exec_())

run()
