DELETE FROM MainUser;
DELETE FROM Recruiter;
DELETE FROM Applicant;
DELETE FROM Offer;
DELETE FROM OfferApplicant;

INSERT INTO MainUser (UserID, PasswordHash, FirstName, LastName, Email, TelephoneNumber, UserType) VALUES
    (1, '$2b$12$qni37LHcVYDi6NZzBUN7/uwSPf2xPj.VeOkIjc6nLt1CqWF8EUBqe', 'Larry', 'Capija', 'larryka@gmail.com', '634745323', 'Applicant'), -- password123
    (2, '$2b$12$barPjgDZ1D40b9nOpkwP2.LK5rp6Ydkt2IUH9hTiNwzXgrb6q1Zwi', 'Rosa', 'Melano', 'rosame@gmail.com', '623745956', 'Applicant'), -- 1234
    (3, '$2b$12$rxoFmscZ2AOFfPtCMT1AH..9O/PDpAJ.vwlBSmlepV21VgAPKX6kS', 'Victor', 'Tazo', 'biggie@gmail.com', '666453784', 'Recruiter'); -- admins

INSERT INTO Recruiter (UserID) VALUES
    (3);

INSERT INTO Applicant (UserID) VALUES
    (1),
    (2);

INSERT INTO Offer (OfferID, OfferDescription) VALUES
    (1, 'Backend developer with SQL and C# skills. Competitive salary and flexible schedule.'),
    (2, 'Hiring for a cleaning position. Responsibilities include maintaining cleanliness in various areas. Attention to detail and reliability are essential.');

INSERT INTO OfferApplicant (OfferID, UserID) VALUES
    (1,1),
    (2,2);