CREATE TABLE MainUser (
    UserID INT PRIMARY KEY,
    [id] UNIQUEIDENTIFIER ROWGUIDCOL NOT NULL UNIQUE DEFAULT NEWID(),
    PasswordHash NVARCHAR(100) NOT NULL,
    EncryptedFirstName VARBINARY(MAX) NOT NULL,
    EncryptedLastName VARBINARY(MAX) NOT NULL,
    Email NVARCHAR(100) NOT NULL UNIQUE,
    EncryptedTelephoneNumber VARBINARY(MAX),
    UserType NVARCHAR(10),
    UserPublicKey VARBINARY(MAX) FILESTREAM DEFAULT (0x),
    EncryptedSymmetricKey VARBINARY(MAX)
)ON [PRIMARY] FILESTREAM_ON FileStreamFileGroup;

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
    CV_EncryptedKey VARBINARY(MAX),
    PRIMARY KEY (OfferID, UserID),
    FOREIGN KEY (OfferID) REFERENCES Offer(OfferID),
    FOREIGN KEY (UserID) REFERENCES Applicant(UserID)
);
