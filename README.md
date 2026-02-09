# Encrypted Mail App - Portfolio Project

### Overview
This is a secure, PGP-based messaging web application designed as a portfolio project to showcase my skills in backend development, cryptography, and full-stack integration using **Python, Flask, PostgreSQL, and Jinja2.**

Upon user signup, the app automatically generates a **PGP key pair.** Messages sent between users are end-to-end **encrypted (E2EE)** using the recipient's public key and **digitally signed** be the sender.

The entier project runs locally and is not hosted poblicly -- it's meant to demonstrate strong backend logic, cryptography, and project structure.

## Key Features
- Auto-generation of **PGP key pairs** on user signup
- Encrypted messaging using recipient's **public key**
- Digital signature using sender's private key
- Secure storage of private keys (encrypted on disk)
- Authentication using **JWT**
- Clean, server-rendered HTML frontend using Jinja2
- Modular Flask backend and well-structured
---
## Tech Stack 
* **Bakend:** Flask + SQLAlchemy
* **Frontend:** HTML + Jinja2 templates
* **Encryption:** python-gnupg
* **Database:** PostgreSQL (via SQLAlchemy ORM)
* **Auth:** JWT (using python-jose)
* **Key Encryption:** AES (Fernet) with password-derived keys (PBKDF2)
* **Password Hashing:** bcrypt
---
## Local-Only designed
> This app is not hosted or deployed online. It's designed to run locally and securely for the sake of demonstration. You can clone the repo, run it, create users, send encrypted messages between them, and view the decryption proccess in action -- all on your machine.

## System Atchitecture
### 1. Signup 
- User register with username + password-derived
- Server generates PGP key pair
- public key stored in Database
- Private key is encrypted using a key derived from the user's password and stored securely 
### 2. Login 
- User logs in with username + password
- JWT token is issued and user for session handling
### **3. Send Message**

- User writes a message to another username
    
- App retrieves the recipient’s public key
    
- Encrypts the message using it
    
- Optionally signs the message using sender’s private key
    
- Stores the encrypted message in the database
    

### **4. Read Message**

- User fetches inbox messages
    
- Messages are decrypted using their private key (decrypted in memory using password-derived key)
    

---

## **Database Schema**

```sql
Users (
    id UUID PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key_encrypted TEXT NOT NULL,
    created_at TIMESTAMP
)

Messages (
    id UUID PRIMARY KEY,
    sender_id UUID REFERENCES Users(id),
    recipient_id UUID REFERENCES Users(id),
    message_encrypted TEXT NOT NULL,
    signature TEXT,  -- optional
    created_at TIMESTAMP
)
```

---

## **How to Run Locally**

```bash
git clone https://github.com/DevMohammad-SA/encrypted-mail-app.git
cd encrypted-mail-app
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Access it on `http://127.0.0.1:5000`

---

## **Planned Features**

-  User Signup + Login
    
-  PGP Keypair Generation
    
-  Encrypt + Send Message
    
-  Decrypt + Read Message
    
-  Optional: Message signing + verification
    
-  Optional: Export public/private key
    
-  Optional: Message expiration
    

---

## **What You’ll Learn From This Project**

- Working with public-key cryptography (PGP)
    
- Secure key handling and password-based encryption
    
- Flask backend architecture
    
- Integrating cryptographic systems with relational databases
    
- Jinja2 for clean server-side rendering
    

---

## **Why I Built This**

> I wanted to build something more meaningful than another TODO app — something that reflects real-world use cases in **privacy, cryptography, and backend development**. This project helped me explore PGP, encryption flows, and secure data handling. Now it's part of my portfolio to show what I can do beyond CRUD.

---

## **License**

MIT License [LICENSE](LICENSE).

