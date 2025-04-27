# Communication LTD – Secure vs Vulnerable Web System

A full-stack web application designed to demonstrate real-world security flaws—such as XSS and SQL Injection—and their proper mitigations. The app includes both **vulnerable** and **secure** versions of the backend for learning and comparison purposes.

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

### This section highlights how common web attacks are demonstrated in the vulnerable version and how they’re mitigated in the secure version.

1. XSS (Cross-Site Scripting)

> Attack vector: HTML is injected into a customer name field and later rendered in the frontend without sanitization.

* Example payload:

```html
customer_name: <b style="color:red">Hacked</b>
```

* Vulnerable Implementation:
```python
INSERT INTO customers (customer_id, name, email, phone)
VALUES (
  '{request.customer_id}',
  '{request.name}',
  '{request.email}',
  '{request.phone}'
);
"""
```

* Secure Implementation:
```python
name=bleach.clean(request.name)
```

> Using bleach.clean() strips unsafe HTML before storing it in the database, effectively neutralizing stored XSS.

2. SQL Injection (User Registration)

> Attack vector: The attacker injects malicious SQL code into the registration form, tricking the database into executing unintended commands.

* Example payload:

```sql
username: hacker', 'x','y','z'); DROP TABLE users; --
```

* Vulnerable Implementation:

```python
raw_sql = f"""
INSERT INTO users (username, email, ...)
VALUES ('{request.username}', ...)
"""
db.connection().connection.executescript(raw_sql)
```

* Secure Implementation:

```python
user = User(username=request.username, ...)
db.add(user)
db.commit()
```

> The vulnerable version directly injects user input into raw SQL strings. The secure version uses SQLAlchemy ORM, which automatically escapes inputs and prevents injection.

3. SQL Injection (Login)

> Attack vector: The attacker bypasses authentication logic using crafted SQL that always evaluates to true.

* Example payload:

```sql
username: ' OR '1'='1' -- 
```

* Vulnerable Implementation:

```python
    raw_sql = f"""
      SELECT * FROM users
      WHERE username = '{request.username}'
        AND password_hash = '{hash_password(request.password, generate_salt())}';
    """
```

* Secure Implementation:

```python
user = db.query(User).filter(User.username == request.username).first()
```

> The vulnerable query is blindly constructed from user input, allowing injection. The secure version uses SQLAlchemy’s query builder, which ensures safe parameter binding.

4. SQL Injection (Add New Customer)

> Attack vector: SQL is injected into the customer ID field to execute additional malicious commands like dropping a table.

* Example payload:

```sql
customer_id: 999', 'x','y','z'); DROP TABLE customers; -- 
```

* Vulnerable Implementation:

```python
    INSERT INTO customers (customer_id, name, email, phone)
    VALUES (
      '{request.customer_id}',
      '{request.name}',
      '{request.email}',
      '{request.phone}'
    );
    """
```

* Secure Implementation:

```python
def create_customer(db: Session, customer_id: int, name: str, email: str, phone: str):
    customer = Customer(customer_id=customer_id, name=name, email=email, phone=phone)
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer
```

> The secure version uses ORM objects to safely persist data. This prevents attackers from chaining raw SQL payloads that can harm the database.

## Sample Users for Testing

| Username | Password   |
|----------|------------|
| `gal`    | `12345Hh&` |
| `harel`  | `67890Jj*` |


## License

MIT © 2025 
