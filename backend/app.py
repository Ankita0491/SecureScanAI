from fastapi import FastAPI, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime
import joblib
import os
import uuid
from auth.users import register_user, login_user
from database import SessionLocal
from models import ScanHistory
from models import Report


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.path.join("model", "baseline_model.pkl")
VECTORIZER_PATH = os.path.join("model", "tfidf_vectorizer.pkl")
REPORT_DIR = "reports"

os.makedirs(REPORT_DIR, exist_ok=True)

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

CWE_MODEL_PATH = os.path.join(
    "model",
    "cwe_model.pkl"
)

CWE_VECTORIZER_PATH = os.path.join(
    "model",
    "cwe_vectorizer.pkl"
)

CWE_LABEL_ENCODER_PATH = os.path.join(
    "model",
    "cwe_label_encoder.pkl"
)

cwe_model = joblib.load(
    CWE_MODEL_PATH
)

cwe_vectorizer = joblib.load(
    CWE_VECTORIZER_PATH
)

cwe_label_encoder = joblib.load(
    CWE_LABEL_ENCODER_PATH
)


class ReportRequest(BaseModel):
    file_name: str
    status: str
    confidence: int
    severity: str
    message: str
    ml_prediction: str
    ml_confidence: int
    rule_based_issues: int
    issues: list = []

class AuthRequest(BaseModel):
    email: str
    password: str

class ScanHistoryRequest(BaseModel):
    user_email: str
    filename: str
    status: str
    severity: str
    confidence: int

class SaveReportRequest(BaseModel):
    user_email: str
    report_name: str

@app.get("/")
def home():
    return {
        "message": "Backend Running",
        "model": "TF-IDF + Logistic Regression loaded",
        "report": "PDF report endpoint ready",
    }


def rule_scan(code: str):
    issues = []

    patterns = [
    {
        "keyword": "gets(",
        "cwe": "CWE-242",
        "type": "Unsafe Input Function",
        "severity": "Critical",
        "message": "gets() is unsafe and can cause buffer overflow.",
    },
    {
        "keyword": "strcpy(",
        "cwe": "CWE-120",
        "type": "Buffer Overflow Risk",
        "severity": "High",
        "message": "strcpy() does not check destination buffer size.",
    },
    {
        "keyword": "strcat(",
        "cwe": "CWE-120",
        "type": "Buffer Overflow Risk",
        "severity": "High",
        "message": "strcat() can overflow destination buffer.",
    },
    {
        "keyword": "sprintf(",
        "cwe": "CWE-120",
        "type": "Format/Buffer Risk",
        "severity": "High",
        "message": "sprintf() can write beyond buffer limits.",
    },
    {
        "keyword": "malloc(",
        "cwe": "CWE-401",
        "type": "Memory Management",
        "severity": "Medium",
        "message": "Dynamic memory allocation found; verify proper memory handling.",
    },
    {
        "keyword": "free(",
        "cwe": "CWE-416",
        "type": "Use After Free Risk",
        "severity": "Medium",
        "message": "free() detected; check for use-after-free vulnerabilities.",
    },
    {
        "keyword": "scanf(",
        "cwe": "CWE-20",
        "type": "Improper Input Validation",
        "severity": "Medium",
        "message": "scanf() can be unsafe without width restrictions.",
    },
    {
        "keyword": "system(",
        "cwe": "CWE-78",
        "type": "OS Command Injection",
        "severity": "Critical",
        "message": "system() may allow command injection attacks.",
    },
]

    for item in patterns:
        if item["keyword"] in code:
            issues.append(item)

    return issues


def ml_predict(code: str):
    code_vector = vectorizer.transform([code])
    prediction = model.predict(code_vector)[0]
    probabilities = model.predict_proba(code_vector)[0]

    confidence = round(max(probabilities) * 100)
    status = "Vulnerable" if prediction == 1 else "Safe"

    return status, confidence

def predict_cwe(code: str):

    code_vector = cwe_vectorizer.transform(
        [code]
    )

    prediction = cwe_model.predict(
        code_vector
    )[0]

    predicted_cwe = (
        cwe_label_encoder
        .inverse_transform([prediction])[0]
    )

    probabilities = (
        cwe_model.predict_proba(
            code_vector
        )[0]
    )

    confidence = round(
        max(probabilities) * 100
    )

    return (
        predicted_cwe,
        confidence
    )

@app.post("/predict-cwe")
async def predict_cwe_route(file: UploadFile):
    content = await file.read()

    code = content.decode(
        "utf-8",
        errors="ignore"
    )

    predicted_cwe, confidence = predict_cwe(code)

    return {
        "predicted_cwe": predicted_cwe,
        "confidence": confidence
    }

@app.post("/auth/signup")
def signup(data: AuthRequest):
    user = register_user(
        data.email,
        data.password
    )

    if not user:
        return {
            "success": False,
            "message": "User already exists"
        }

    return {
        "success": True,
        "message": "Signup successful",
        "email": data.email
    }


@app.post("/auth/login")
def login(data: AuthRequest):
    result = login_user(
        data.email,
        data.password
    )

    if not result:
        return {
            "success": False,
            "message": "Invalid email or password"
        }

    return {
        "success": True,
        "message": "Login successful",
        "access_token": result["access_token"],
        "token_type": result["token_type"],
        "email": result["email"]
    }

@app.get("/dashboard-stats/{user_email}")
def dashboard_stats(user_email: str):
    db = SessionLocal()

    try:
        scans = db.query(ScanHistory).filter(
            ScanHistory.user_email == user_email
        ).all()

        total_scans = len(scans)

        vulnerable_count = len([
            scan for scan in scans
            if scan.status == "Vulnerable"
        ])

        safe_count = len([
            scan for scan in scans
            if scan.status == "Safe"
        ])

        risk_score = 0

        if total_scans > 0:
            risk_score = round(
                (vulnerable_count / total_scans) * 100
            )

        return {
            "files_scanned": total_scans,
            "vulnerabilities": vulnerable_count,
            "safe_files": safe_count,
            "risk_score": risk_score
        }

    finally:
        db.close()

@app.post("/scan")
async def scan(file: UploadFile):
    content = await file.read()

    code = content.decode(
        "utf-8",
        errors="ignore"
    )

    ml_status, ml_confidence = ml_predict(code)
    issues = rule_scan(code)
    predicted_cwe, cwe_confidence = predict_cwe(code)

    for issue in issues:
        issue["cwe"] = predicted_cwe
        issue["cwe_confidence"] = cwe_confidence

    final_status = "Vulnerable" if issues else ml_status

    if issues:
        severity_order = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4,
        }

        highest_issue = max(
            issues,
            key=lambda issue: severity_order[issue["severity"]]
        )

        severity = highest_issue["severity"]
        message = highest_issue["message"]
    else:
        message = (
            "ML model predicts this code may be vulnerable."
            if ml_status == "Vulnerable"
            else
            "ML model predicts no major vulnerability."
        )

        severity = "Medium" if ml_status == "Vulnerable" else "Low"

    confidence = ml_confidence

    if issues:
        confidence = max(confidence, 90)

    return {
        "status": final_status,
        "confidence": confidence,
        "severity": severity,
        "message": message,
        "issues": issues,
        "issue_count": len(issues),
        "ml_prediction": ml_status,
        "ml_confidence": ml_confidence,
        "rule_based_issues": len(issues),
        "predicted_cwe": predicted_cwe,
        "cwe_confidence": cwe_confidence,
    }


@app.post("/save-scan-history")
def save_scan_history(data: ScanHistoryRequest):
    db = SessionLocal()

    try:
        history = ScanHistory(
            user_email=data.user_email,
            filename=data.filename,
            status=data.status,
            severity=data.severity,
            confidence=data.confidence
        )

        db.add(history)
        db.commit()
        db.refresh(history)

        return {
            "success": True,
            "message": "Scan history saved",
            "id": history.id
        }

    finally:
        db.close()


@app.post("/generate-report")
def generate_report(data: ReportRequest):
    report_id = str(uuid.uuid4())[:8]
    filename = f"SecureScanAI_Report_{report_id}.pdf"
    filepath = os.path.join(REPORT_DIR, filename)

    pdf = canvas.Canvas(filepath, pagesize=A4)
    width, height = A4

    y = height - 60

    pdf.setFont("Helvetica-Bold", 22)
    pdf.drawString(50, y, "SecureScan AI - Vulnerability Report")

    y -= 40

    pdf.setFont("Helvetica", 11)
    pdf.drawString(50, y, f"Generated On: {datetime.now().strftime('%d-%m-%Y %I:%M %p')}")

    y -= 30

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Scan Summary")

    y -= 25

    pdf.setFont("Helvetica", 11)

    summary = [
        f"File Name: {data.file_name}",
        f"Final Status: {data.status}",
        f"Confidence: {data.confidence}%",
        f"Severity: {data.severity}",
        f"ML Prediction: {data.ml_prediction}",
        f"ML Confidence: {data.ml_confidence}%",
        f"Rule-Based Issues: {data.rule_based_issues}",
        f"Message: {data.message}",
    ]

    for line in summary:
        pdf.drawString(50, y, line)
        y -= 22

    y -= 15

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Detected Issues")

    y -= 25

    pdf.setFont("Helvetica", 11)

    if data.issues:
        for index, issue in enumerate(data.issues, start=1):
            if y < 100:
                pdf.showPage()
                y = height - 60
                pdf.setFont("Helvetica", 11)

            pdf.drawString(50, y, f"{index}. {issue.get('type', 'Unknown Issue')}")
            y -= 18
            pdf.drawString(70, y, f"Severity: {issue.get('severity', 'Unknown')}")
            y -= 18
            pdf.drawString(70, y, f"Details: {issue.get('message', 'No details')}")
            y -= 28
    else:
        pdf.drawString(50, y, "No rule-based vulnerability issues detected.")
        y -= 25

    y -= 15

    if y < 130:
        pdf.showPage()
        y = height - 60

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Security Recommendations")

    y -= 25

    pdf.setFont("Helvetica", 11)

    recommendations = [
        "Avoid unsafe functions such as gets(), strcpy(), strcat(), sprintf(), and system().",
        "Validate all user inputs before processing.",
        "Use bounded functions such as fgets(), strncpy(), snprintf(), and safer alternatives.",
        "Check memory allocation results before using pointers.",
        "Avoid using freed memory and always set freed pointers to NULL.",
        "Perform manual code review for high and critical severity findings.",
    ]

    for rec in recommendations:
        if y < 80:
            pdf.showPage()
            y = height - 60
            pdf.setFont("Helvetica", 11)

        pdf.drawString(50, y, f"- {rec}")
        y -= 20

    pdf.save()

    return {
        "message": "Report generated successfully",
        "report_file": filename,
        "download_url": f"http://127.0.0.1:8000/download-report/{filename}",
    }

@app.post("/save-report")
def save_report(data: SaveReportRequest):
    db = SessionLocal()

    try:
        report = Report(
            user_email=data.user_email,
            report_name=data.report_name
        )

        db.add(report)
        db.commit()
        db.refresh(report)

        return {
            "success": True,
            "message": "Report saved",
            "id": report.id
        }

    finally:
        db.close()


@app.get("/download-report/{filename}")
def download_report(filename: str):
    filepath = os.path.join(REPORT_DIR, filename)

    return FileResponse(
        filepath,
        media_type="application/pdf",
        filename=filename,
    )