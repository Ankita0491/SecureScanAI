# SecureScan AI

## AI-Powered Source Code Vulnerability Detection Platform

SecureScan AI is a web-based security analysis platform that detects vulnerabilities in C/C++ source code using a hybrid approach combining Machine Learning and Rule-Based Analysis.

The system performs static code analysis, identifies security weaknesses, maps findings to CWE (Common Weakness Enumeration) standards, and generates professional PDF security reports.

---

## Features

* AI-Based Vulnerability Detection
* TF-IDF + Logistic Regression Model
* Rule-Based Security Scanner
* CWE Classification
* Vulnerability Severity Assessment
* Security Recommendations
* PDF Report Generation
* User Authentication (Signup/Login)
* Persistent Login Sessions
* Scan History Tracking
* Modern React Frontend
* FastAPI Backend

---

## Technology Stack

### Frontend

* React
* Vite
* JavaScript
* CSS

### Backend

* FastAPI
* Python
* Joblib
* Scikit-learn
* ReportLab

### Machine Learning

* TF-IDF Vectorization
* Logistic Regression Classifier

### Security Standards

* CWE Classification
* Static Code Analysis

---

## Project Structure

```text
frontend/
backend/
training/
README.md
.gitignore
```

---

## Installation

### Backend

```bash
cd backend

python -m venv venv

venv\Scripts\activate

pip install -r requirements.txt

python -m uvicorn app:app --reload
```

Backend URL:

```text
http://127.0.0.1:8000
```

Swagger Docs:

```text
http://127.0.0.1:8000/docs
```

---

### Frontend

```bash
cd frontend

npm install

npm run dev
```

Frontend URL:

```text
http://localhost:5173
```

---

## Workflow

1. User logs into SecureScan AI.
2. Source code file is uploaded.
3. ML model analyzes the code.
4. Rule engine scans for unsafe functions.
5. Vulnerabilities are mapped to CWE standards.
6. Security recommendations are generated.
7. PDF report is created.
8. User downloads the report.

---

## Example Vulnerabilities

* CWE-120 Buffer Overflow
* CWE-242 Dangerous Function Usage
* CWE-416 Use After Free
* CWE-78 Command Injection
* CWE-20 Improper Input Validation

---

## Future Enhancements

* CodeBERT Integration
* PostgreSQL Database
* Multi-Language Support
* Real-Time Security Monitoring
* Cloud Deployment
* Advanced Vulnerability Classification

---

## Author

Final Year Major Project

SecureScan AI – Intelligent Vulnerability Detection Platform
