FILE INTEGRITY CHECKER - WINDOWS SETUP

This working starter uses Python Flask and SQLite. SQLite is built into Python; no separate database server is needed. If your teacher explicitly requires MySQL, we can migrate it after you confirm.

1. Install Python 3.10+ and select "Add Python to PATH".
2. Extract this ZIP. Open the extracted FileIntegrityChecker folder in VS Code.
3. VS Code > Terminal > New Terminal. Run each command:

   py -m venv .venv
   .venv\Scripts\activate
   py -m pip install -r requirements.txt
   py -c "from app import init_db; init_db()"
   py -m flask --app app create-admin

4. Enter the admin name, email and password when asked. Password must be at least 8 characters.
5. Start the app:

   py app.py

6. Open Microsoft Edge: http://127.0.0.1:5000

DEMO
- Sign up as a normal user and log in.
- Select a file and click Save trusted baseline.
- Upload the same unchanged file and click Verify against baseline: expected status Verified.
- Edit the file, save it, then upload it again with the same filename and verify: expected status Modified.
- Admin can view all scan records and manage user roles at Manage users.

NOTES
- Public signups always receive the user role. Admin is created separately with the command above; users cannot self-assign admin.
- Passwords are stored as Werkzeug password hashes, not plaintext.
- Login state is maintained with Flask sessions. Admin-only routes are checked on the server.
- Uploaded file contents are hashed in memory, not retained as uploaded files. Maximum upload size: 16 MB.
- The Flask development server is for local demonstration only. Change SECRET_KEY and use production hosting/security controls before deployment.
