# File Integrity Checker and Monitoring System

A Python Flask-based cybersecurity application designed to verify file integrity using the SHA-256 cryptographic hashing algorithm.

## 1. Introduction

The File Integrity Checker is a cybersecurity project developed to detect unauthorised modifications in digital files. It uses the SHA-256 hashing algorithm to generate unique hash values for files and compares them with previously stored trusted hash values.

The system helps users identify whether a file remains unchanged or has been modified.

## 2. Project Objectives

- Understand the importance of file integrity in cybersecurity.
- Implement SHA-256 hashing using Python.
- Generate and store trusted file hash values.
- Detect unauthorised file modifications.
- Maintain records of file verification activities.
- Provide secure user authentication and administrator access.

## 3. Key Features

- User registration and login.
- SHA-256 hash generation.
- Trusted baseline creation and storage.
- File integrity verification.
- Modified file detection.
- Scan history and activity records.
- Administrator access and user role management.

## 4. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend development |
| Flask | Web application framework |
| SHA-256 | File integrity verification |
| hashlib | Hash generation |
| SQLite | Database management |
| HTML and CSS | User interface |
| Werkzeug | Password hashing and security |

## 5. Working Methodology

1. The user registers and logs into the application.
2. The user selects a file for verification.
3. The application generates its SHA-256 hash value.
4. The user saves the hash as a trusted baseline.
5. During verification, the application generates a fresh hash.
6. The new hash is compared with the stored baseline.
7. The system displays the verification result.

### Possible Results

- **Verified:** The file has not changed since the baseline was saved.
- **Modified:** The current hash differs from the stored hash.
- **No Baseline:** No trusted hash is available for comparison.

## 6. Installation and Execution

### Prerequisites
- Python 3.10 or later
- pip
- Visual Studio Code (recommended)
- Web browser

### Installation Steps

**Step 1: Clone the repository**

```bash
git clone https://github.com/siddhahuja/File-Integrity-Checker.git
```

**Step 2: Open the project folder**

```bash
cd File-Integrity-Checker
```

**Step 3: Create a virtual environment**

```bash
py -m venv .venv
```

**Step 4: Activate the environment**

```bash
.venv\Scripts\activate
```

**Step 5: Install dependencies**

```bash
py -m pip install -r requirements.txt
```

**Step 6: Initialise the database**

```bash
py -c "from app import init_db; init_db()"
```

**Step 7: Create an administrator account**

```bash
py -m flask --app app create-admin
```

Follow the prompts to enter the administrator details.

**Step 8: Run the application**

```bash
py app.py
```

Open the following address in your browser:

`http://127.0.0.1:5000`

## 7. Testing and Verification

The application can be tested through the following activities:

- Register a normal user account.
- Log in to the application.
- Select a file and save its trusted baseline.
- Upload the same unchanged file and verify it.
- Modify the file and perform verification again.
- Check the recorded scan history.
- Test administrator access and user management.

## 8. Security Considerations

- SHA-256 is used for file integrity verification.
- Passwords are stored as secure password hashes rather than plaintext.
- Flask sessions maintain login state.
- Administrator-only routes are protected.
- Uploaded file contents are hashed in memory.
- The development server is intended for local demonstration, not production deployment.

## 9. Learning Outcomes

This project provided practical experience in Python programming, Flask backend development, database integration, cryptographic hashing, user authentication and cybersecurity principles.

## 10. Future Enhancements

- Automated background file monitoring.
- Email notifications for detected modifications.
- Detailed security audit reports.
- Improved user dashboard and reporting.
- Deployment on a secure production server.

## Author

**Siddhi Ahuja**

Bachelor of Computer Applications (BCA)  
Graphic Era University

**Project Domain:** Cybersecurity  
**Project Title:** File Integrity Checker using SHA-256 Algorithm
