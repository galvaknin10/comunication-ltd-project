# Communication LTD – Secure vs Vulnerable Web System

A full-stack web application designed to demonstrate real-world security flaws such as XSS and SQL Injection and their proper mitigations. The app includes both **vulnerable** and **secure** versions of the backend for learning and comparison purposes.

---

## Features

- User registration and login with password policy enforcement
- Password reset via email with token validation
- Account lockout after failed login attempts
- Add and view customer records
- Separate **vulnerable** and **secure** implementations:
  - Stored XSS demonstration and mitigation
  - SQL Injection attack and defense
- Fully Dockerized microservices architecture
- Clean, modular frontend built with Streamlit

---

## Tech Stack

The application is built with a **Python**-based tech stack. The frontend is developed using **Streamlit**, providing a simple and interactive UI. The backend is powered by **FastAPI**, with **SQLite** used as the lightweight relational database. Security features are implemented using **HMAC** for password hashing, bleach for input sanitization, and custom password policy enforcement. Both the backend and frontend services are containerized using **Docker** and orchestrated with Docker Compose. Email functionality for password reset is handled via SMTP using Gmail.

---

## Installation

1. Terminal:

  ```bash
  git clone https://github.com/galvaknin10/comunication-ltd-project.git
  cd comunication-ltd-project
  ```

2.  Create a `.env` file inside the `backend` directory and paste:

```python
EMAIL_USER="your-email"
EMAIL_PASS="your-app-password"
```

> You can generate a **Gmail App Password** by enabling 2-Step Verification on your account and visiting your Google App Passwords page. Select Mail as the app and generate a password for your project. Copy and paste the 16-character key into your .env file as EMAIL_PASS.

3. Start the project: 

```bash
docker-compose -f docker-compose.secure.yml up --build
```

> For the secure system

```bash
docker-compose -f docker-compose.vulnerable.yml up --build
```

> For the vulnerable system

You’re all set - Go to `http://localhost:8501` in your browser to start using the application.

---

## Project Structure

```plaintext
.
├── backend/                     # FastAPI backend (secure & vulnerable implementations)
├── database/                    # SQLite database file (mounted via volume)
├── frontend/                    # Streamlit frontend microservice
├── docker-compose.secure.yml   # Docker Compose file for secure version
├── docker-compose.vulnerable.yml # Docker Compose file for vulnerable version
├── .gitignore                   # Git ignored files list
└── README.md                    # Project documentation and setup guide
```

---

## Secure vs Vulnerable Comparison

#### This section highlights how common web attacks are demonstrated in the vulnerable version and how they’re mitigated in the secure version.

### XSS (On adding new customer)

> Attack Vector:
Malicious HTML/JavaScript is injected into user-controlled fields (e.g., customer name). When the backend returns this data without sanitizing it, the frontend renders it directly, executing the injected code in the browser.

> How to Prevent It: Escape or encode outputs before rendering user input into HTML (most important). Optionally sanitize/validate inputs using whitelists to block known-dangerous characters before saving to the database.

**Example payload:**

Customer name: `<b style="color:red">Hacked</b>`

* Vulnerable Implementation:

```python
# Input not Escaped or validated
customer_id = request.customer_id
name        = request.name
email       = request.email
phone       = request.phone 

# Output returned directly to frontend without escaping
return {
    "name":  name,
    "email": email,
    "phone": phone
}
```

* Secure Implementation:

```python
# Escape user inputs to prevent XSS
safe_name        = html.escape(request.name)
safe_email       = html.escape(request.email)
safe_phone       = html.escape(request.phone)
safe_customer_id = html.escape(request.customer_id)

# Escape output before sending to the client
name  = html.escape(row.name)
email = html.escape(row.email)
phone = html.escape(row.phone)

# Return the sanitized data
return {
    "name":  name,
    "email": email,
    "phone": phone
}
```
---

### SQL Injection (On adding new user)

> Attack vector: The attacker injects malicious SQL code into the registration form, tricking the database into executing unintended commands.

> How to prevent it: Use prepared statements (parameterized queries), which treat user input as plain text — not executable SQL.

**Example payload:**

User name: `'; DROP TABLE users; --`

* Vulnerable Implementation:

```python
# User input is directly embedded into the SQL string
SELECT 1 FROM users WHERE username = '{username}'
```

* Secure Implementation:

```python
# User input is safely passed as a parameter
SELECT 1 FROM users WHERE username = :username,
{"username": safe_username}
```

---

### SQL Injection (On login)

> Attack vector: The attacker bypasses authentication logic using crafted SQL that always evaluates to true.

> How to prevent it: Use prepared statements (parameterized queries), which treat user input as plain text — not executable SQL.

**Example payload:**

User name: `'OR '1'='1' --`

* Vulnerable Implementation:

```python
# User input is directly embedded into the SQL string
SELECT salt FROM users WHERE username = '{username}'
```

* Secure Implementation:

```python
# User input is safely passed as a parameter
SELECT 1 FROM users WHERE username = :username,
{"username": safe_username}
```
---

### SQL Injection (On adding new customer)

> Attack vector: SQL is injected into the customer ID field to execute additional malicious commands like dropping a table.

> How to prevent it: Use prepared statements (parameterized queries), which treat user input as plain text — not executable SQL.

**Example payload:**

Customer ID: `';DROP TABLE customers; --`

* Vulnerable Implementation:

```python
# User input is directly embedded into the SQL string
SELECT 1 FROM customers WHERE customer_id = '{customer_id}'
```

* Secure Implementation:

```python
# User input is safely passed as a parameter
SELECT 1 FROM customers WHERE customer_id = :cid,
{"cid": safe_customer_id}
```
---

## Sample Users for Testing

| Username | Password   |
|----------|------------|
| `gal`    | `12345Hh&` |
| `harel`  | `67890Jj*` |


## License

MIT © 2025 
