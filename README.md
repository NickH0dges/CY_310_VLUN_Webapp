**Company Secrets Vault – Vulnerable Demo App**

This is a deliberately insecure Flask web app built for penetration-testing exercises in
CY310 – Information Security & Assurance at Southeast Missouri State University.


**1. Requirements**

Python 3.8+ installed

Internet connection (for the image loaded from iStock)

pip available on the command line

**2. Install dependencies**

From the folder where the file is saved (e.g. company_secrets_vuln.py):

pip install flask



**3. First-time setup**

Download / copy the Python file from Github
(for example: company_secrets_vuln.py).


Start the app:

python company_secrets_vuln.py


You should see something like:

[+] Database initialized with users + fake company secrets.
* Running on http://127.0.0.1:5001/ (Press CTRL+C to quit)



**4. Using the app**

Open a browser and go to:

http://127.0.0.1:5001/


You’ll see the Company Secrets Vault login page.

Default demo credentials (for normal login):

Username: alice

Password: password123

On successful login you’ll see:

A list of fake “Company secret records”

The user table with plaintext passwords



**5. SQL injection demo (for the project)**

Because the login query is intentionally vulnerable, you can bypass authentication:

Username:

' OR 1=1--


Password: anything (e.g., test)

This should also log you in and display all records, demonstrating SQL injection.



**6. Stopping the app**

In the terminal where the app is running, press:

CTRL + C


to stop the Flask development server.
