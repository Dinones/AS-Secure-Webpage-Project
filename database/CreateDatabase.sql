CREATE TABLE MainUser (
    UserID INT PRIMARY KEY,
    PasswordHash NVARCHAR(100) NOT NULL,
    EncryptedFirstName NVARCHAR(50) NOT NULL,
    EncryptedLastName NVARCHAR(50) NOT NULL,
    Email NVARCHAR(100) NOT NULL UNIQUE,
    EncryptedTelephoneNumber NVARCHAR(15),
    UserType NVARCHAR(10),
    UserPublicKey NVARCHAR(256),
    EncryptedSymmetricKey NVARCHAR(256)
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
    RecruiterID INT,
    OfferTitle NVARCHAR(100) UNIQUE,
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
