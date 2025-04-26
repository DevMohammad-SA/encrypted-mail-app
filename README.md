# Encrypted Mail App - Portfolio Project

### Overview
This is a secure, PGP-based messaging web application designed as a portfolio project to showcase my skills in backend development, cryptography, and full-stack integration using **Python, Flask, PostgreSQL, and Jinja2.**

Upon user signup, the app automatically generates a **PGP key pair.** Messages sent between users are end-to-end **encrypted (E2EE)** using the recipient's public key and **digitally signed** be the sender.

The entier project runs locally and is not hosted poblicly -- it's meant to demonstrate strong backend logic, cryptography, and project structure.

### Key Features
- Auto-generation of **PGP key pairs** on user signup
- Encrypted messaging using recipient's **public key**
- Digital signature using sender's private key
- Secure storage of private keys (encrypted on disk)
- Authentication using **JWT**
- Clean, server-rendered HTML frontend using Jinja2
- Modular Flask backend and well-structured
---
### Tech Stack 
* **Bakend:** Flask + SQLAlchemy
* **Frontend:** HTML + Jinja2 templates
* **Encryption:** PGPy
* **Database:** PostgreSQL (via SQLAlchemy ORM)
* **Auth:** JWT (using python-jose)
* **Key Encryption:** AES (Fernet) with password-derived keys (PBKDF2)
* **Password Hashing:** bcrypt
---
### Local-Only designed
> 
