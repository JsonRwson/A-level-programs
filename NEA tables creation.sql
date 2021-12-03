CREATE TABLE Tasks(
TaskID INT NOT NULL AUTO_INCREMENT,
Title VARCHAR(100),
Description varchar(100),
Priority INT,
Due DATE,
Seton DATE,
PRIMARY KEY (TaskID)
);

CREATE TABLE Users(
UserID INT NOT NULL AUTO_INCREMENT,
Email VARCHAR(100),
FirstName VARCHAR(100),
LastName VARCHAR(100),
Username VARCHAR(100),
Pass VARCHAR(100),
Salt VARCHAR(100),
DarkTheme BOOL,
PRIMARY KEY (UserID)
);

CREATE TABLE SetTasks(
TaskNo INT NOT NULL AUTO_INCREMENT,
TaskID INT,
UserID INT,
PRIMARY KEY (TaskNO),
FOREIGN KEY (TaskID) REFERENCES Tasks(TaskID),
FOREIGN KEY (UserID) REFERENCES Users(UserID)
);