-- Remove tables
DROP TABLE OfferApplicant;
DROP TABLE Offer;
DROP TABLE Applicant;
DROP TABLE Recruiter;
DROP TABLE MainUser;

-- Create tables
CREATE TABLE MainUser (
    UserID INT PRIMARY KEY,
    PasswordHash NVARCHAR(100) NOT NULL,
    FirstName NVARCHAR(50) NOT NULL,
    LastName NVARCHAR(50) NOT NULL,
    Email NVARCHAR(100) NOT NULL,
    TelephoneNumber NVARCHAR(15),
    UserType NVARCHAR(10),
    UserPublicKey NVARCHAR(256)
);

CREATE TABLE Recruiter (
    UserID INT PRIMARY KEY,
    FOREIGN KEY (UserID) REFERENCES MainUser(UserID)
);

CREATE TABLE Applicant (
    UserID INT PRIMARY KEY,
    [id] UNIQUEIDENTIFIER ROWGUIDCOL NOT NULL UNIQUE DEFAULT NEWID(),
    CV VARBINARY(MAX) FILESTREAM DEFAULT (0x), 
    FOREIGN KEY (UserID) REFERENCES MainUser(UserID)
)ON [PRIMARY] FILESTREAM_ON FileStreamFileGroup;

CREATE TABLE Offer (
    OfferID INT PRIMARY KEY,
    RecruiterID INT NOT NULL,
    OfferTitle NVARCHAR(100) NOT NULL,
    OfferDescription NVARCHAR(1000) NOT NULL,
    FOREIGN KEY (RecruiterID) REFERENCES Recruiter(UserID)
);

CREATE TABLE OfferApplicant (
    OfferID INT,
    UserID INT,
    CV_EncryptedKey NVARCHAR(256),
    PRIMARY KEY (OfferID, UserID),
    FOREIGN KEY (OfferID) REFERENCES Offer(OfferID),
    FOREIGN KEY (UserID) REFERENCES Applicant(UserID)
);


-- Insert sample values
INSERT INTO MainUser (UserID, PasswordHash, FirstName, LastName, Email, TelephoneNumber, UserType) VALUES
    (1, '$2b$12$qni37LHcVYDi6NZzBUN7/uwSPf2xPj.VeOkIjc6nLt1CqWF8EUBqe', 'Larry', 'Cane', 'larryka@gmail.com', '634745323', 'Applicant'), -- password123
    (2, '$2b$12$barPjgDZ1D40b9nOpkwP2.LK5rp6Ydkt2IUH9hTiNwzXgrb6q1Zwi', 'Rosita', 'Melanie', 'rosime@gmail.com', '623745956', 'Applicant'), -- 1234
    (3, '$2b$12$rxoFmscZ2AOFfPtCMT1AH..9O/PDpAJ.vwlBSmlepV21VgAPKX6kS', 'Victor', 'Tazo', 'biggie@gmail.com', '666453784', 'Recruiter'); -- admins

INSERT INTO Recruiter (UserID) VALUES
    (3);

INSERT INTO Applicant (UserID) VALUES
    (1),
    (2);

INSERT INTO Offer (OfferID, RecruiterID, OfferTitle, OfferDescription) VALUES
    (1, 3, 'Backend developer', 'Backend developer with SQL and C# skills. Competitive salary and flexible schedule.'),
    (2, 3, 'Cleaning position', 'Hiring for a cleaning position. Responsibilities include maintaining cleanliness in various areas. Attention to detail and reliability are essential.');

INSERT INTO OfferApplicant (OfferID, UserID) VALUES
    (1,1),
    (2,2);