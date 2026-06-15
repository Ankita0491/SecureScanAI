import { useEffect, useState } from "react"

export default function Home() {
  const [fileName, setFileName] = useState("")
  const [code, setCode] = useState("")
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState(() => {
  const savedHistory = localStorage.getItem("scanHistory")
  return savedHistory ? JSON.parse(savedHistory) : []
})
  const [selectedFile, setSelectedFile] = useState(null)
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [authMode, setAuthMode] = useState("login")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [userEmail, setUserEmail] = useState("")

  useEffect(() => {
  const token = localStorage.getItem("token")
  const savedEmail = localStorage.getItem("email")

  if (token && savedEmail) {
  setIsLoggedIn(true)
  setUserEmail(savedEmail)
  fetchDashboardStats(savedEmail)
}
}, [])

useEffect(() => {
  localStorage.setItem(
    "scanHistory",
    JSON.stringify(history)
  )
}, [history])
  

  const [stats, setStats] = useState({
    scanned: 0,
    vulnerable: 0,
    safe: 0,
    risk: 0,
  })

  function handleFile(file) {
    if (!file) return

    const allowed = [".c", ".cpp", ".h"]
    const valid = allowed.some((ext) =>
      file.name.toLowerCase().endsWith(ext)
    )

    if (!valid) {
      alert("Only .c, .cpp, or .h files allowed")
      return
    }

    setFileName(file.name)
    setSelectedFile(file)
    setResult(null)

    const reader = new FileReader()
    reader.onload = (event) => {
      setCode(event.target.result)
    }
    reader.readAsText(file)
  }

  function upload(event) {
    handleFile(event.target.files[0])
  }

  function handleDrop(event) {
    event.preventDefault()
    handleFile(event.dataTransfer.files[0])
  }

  function handleDragOver(event) {
    event.preventDefault()
  }

  async function scan() {

  if (!selectedFile) {
    alert("Upload file first")
    return
  }

  setLoading(true)

  const formData = new FormData()

  formData.append(
    "file",
    selectedFile
  )

  try {

    const response = await fetch(
      "http://127.0.0.1:8000/scan",
      {
        method: "POST",
        body: formData,
      }
    )

    const data = await response.json()

    setResult(data)
    saveScanHistoryToDatabase(data)
    fetchDashboardStats(userEmail)

    

    setHistory((old) => [
      {
        file: fileName,
        status: data.status,
        confidence:
          data.confidence + "%",
        severity:
          data.severity,
        time:
          new Date().toLocaleTimeString(),
      },
      ...old,
    ])

  } catch (error) {

    console.log(error)

    alert(
      "Backend connection failed"
    )

  }

  setLoading(false)
}

  function resetFile() {
    setFileName("")
    setCode("")
    setResult(null)
    setLoading(false)
  }

  function resetDashboard() {
    setStats({
      scanned: 0,
      vulnerable: 0,
      safe: 0,
      risk: 0,
    })
    setHistory([])
  }

async function downloadReport() {
  if (!result) {
    alert("Please scan a file first")
    return
  }

  const reportData = {
    file_name: fileName,
    status: result.status,
    confidence: result.confidence,
    severity: result.severity,
    message: result.message,
    ml_prediction: result.ml_prediction,
    ml_confidence: result.ml_confidence,
    rule_based_issues: result.rule_based_issues,
    issues: result.issues || [],
  }

  try {
    const response = await fetch(
      "http://127.0.0.1:8000/generate-report",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(reportData),
      }
    )

    const data = await response.json()
    saveReportToDatabase(data.report_file)
    
    const downloadUrl = `http://127.0.0.1:8000/download-report/${data.report_file}`

    window.open(downloadUrl, "_blank")
  } catch (error) {
    console.log(error)
    alert("Report generation failed")
  }
}

async function handleAuth() {
  if (!email || !password) {
    alert("Please enter email and password")
    return
  }

  const endpoint =
    authMode === "login"
      ? "http://127.0.0.1:8000/auth/login"
      : "http://127.0.0.1:8000/auth/signup"

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email,
        password,
      }),
    })

    const data = await response.json()

    if (!data.success) {
      alert(data.message)
      return
    }

    if (authMode === "signup") {
      alert("Signup successful. Now login.")
      setAuthMode("login")
      return
    }

    localStorage.setItem("token", data.access_token)
    localStorage.setItem("email", data.email)

    setUserEmail(data.email)
    setIsLoggedIn(true)
    fetchDashboardStats(data.email)
  } catch (error) {
    console.log(error)
    alert("Authentication failed")
  }
}

if (!isLoggedIn) {
  return (
    <div className="authPage">
      <div className="authCard">
        <h1>SecureScan AI</h1>

        <h2>
          {authMode === "login" ? "Login" : "Create Account"}
        </h2>

        <input
          type="email"
          placeholder="Enter email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <input
          type="password"
          placeholder="Enter password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button onClick={handleAuth}>
          {authMode === "login" ? "Login" : "Signup"}
        </button>

        <p>
          {authMode === "login"
            ? "Don't have an account?"
            : "Already have an account?"}

          <span
            onClick={() =>
              setAuthMode(authMode === "login" ? "signup" : "login")
            }
          >
            {authMode === "login" ? " Signup" : " Login"}
          </span>
        </p>
      </div>
    </div>
  )
}

async function saveScanHistoryToDatabase(scanResult) {
  try {
    await fetch("http://127.0.0.1:8000/save-scan-history", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        user_email: userEmail,
        filename: fileName,
        status: scanResult.status,
        severity: scanResult.severity,
        confidence: scanResult.confidence,
      }),
    })
  } catch (error) {
    console.log("Failed to save scan history:", error)
  }
}

async function saveReportToDatabase(reportName) {
  try {
    await fetch("http://127.0.0.1:8000/save-report", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        user_email: userEmail,
        report_name: reportName,
      }),
    })
  } catch (error) {
    console.log(error)
  }
}

async function fetchDashboardStats(emailValue) {
  if (!emailValue) return

  try {
    const response = await fetch(
      `http://127.0.0.1:8000/dashboard-stats/${emailValue}`
    )

    const data = await response.json()

    setStats({
      scanned: data.files_scanned,
      vulnerable: data.vulnerabilities,
      safe: data.safe_files,
      risk: data.risk_score,
    })
  } catch (error) {
    console.log("Failed to fetch dashboard stats:", error)
  }
}




  return (
    <div className="home">
      <nav className="navbar">
  <h2 className="logo">SecureScan AI</h2>

  <div className="navActions">
    <span>{userEmail}</span>

    <button onClick={resetDashboard}>
      Reset Dashboard
    </button>

    <button
      className="logoutBtn"
      onClick={() => {
  localStorage.removeItem("token")
  localStorage.removeItem("email")
  localStorage.removeItem("scanHistory")

  setHistory([])
  setIsLoggedIn(false)
}}
    >
      Logout
    </button>
  </div>
</nav>

      <div className="dashboard">
        <div className="card">
          <h3>Files Scanned</h3>
          <h1>{stats.scanned}</h1>
        </div>

        <div className="card">
          <h3>Vulnerabilities</h3>
          <h1>{stats.vulnerable}</h1>
        </div>

        <div className="card">
          <h3>Safe Files</h3>
          <h1>{stats.safe}</h1>
        </div>

        <div className="card">
          <h3>Risk Score</h3>
          <h1>{stats.risk}%</h1>
        </div>
      </div>

      <section className="hero">
        <div className="mainGrid">
          <div className="uploadBox">
            <h2>Upload Source Code</h2>

            <label
              className="upload"
              onDrop={handleDrop}
              onDragOver={handleDragOver}
            >
              <span>Drag & Drop File Here</span>
              <small>or click to choose .c, .cpp, .h file</small>

              <input
                type="file"
                accept=".c,.cpp,.h"
                onChange={upload}
              />
            </label>

            {fileName && <p className="selected">Selected: {fileName}</p>}

            <div className="actions">
              <button onClick={scan}>Start Scan</button>
              <button className="reset" onClick={resetFile}>
                Reset File
              </button>
            </div>

            {loading && (
              <div className="scanLoader">
                <div className="scannerLine"></div>
                <p>AI is scanning your source code...</p>
              </div>
            )}

            {result && (
  <div
    className={
      result.status === "Vulnerable"
        ? "result danger"
        : "result safe"
    }
  >
    <h2>{result.status}</h2>

    <div className="meter">
      <div
        className="meterFill"
        style={{ width: `${result.confidence}%` }}
      ></div>
    </div>

    <p>Confidence: {result.confidence}%</p>
    <p>Severity: {result.severity}</p>
    <p>{result.message}</p>

    <div className="mlDetails">
  <h3>Detection Details</h3>

  <p>
    Final Decision: {result.status}
  </p>

  <p>
    ML Prediction: {result.ml_prediction}
  </p>

  <p>
    ML Confidence: {result.ml_confidence}%
  </p>

  <p>
    Rule-Based Issues: {result.rule_based_issues}
  </p>

  <p>
    ML Predicted CWE: {result.predicted_cwe}
  </p>

  <p>
    CWE Confidence: {result.cwe_confidence}%
  </p>

</div>

<button className="reportBtn" onClick={downloadReport}>
  Download PDF Report
</button>

    {result.issue_count > 0 && (
      <div className="issuesList">
        <h3>Detected Issues: {result.issue_count}</h3>

        {result.issues.map((issue, index) => (
          <div className="issueItem" key={index}>
  <h4>{issue.cwe}</h4>

  <p>Type: {issue.type}</p>

  <p>Severity: {issue.severity}</p>

  <p>{issue.message}</p>

  <p>
    Recommendation:
    {
      issue.cwe === "CWE-120"
        ? " Use strncpy() or safer bounded functions."
        : issue.cwe === "CWE-242"
        ? " Replace gets() with fgets()."
        : issue.cwe === "CWE-416"
        ? " Set pointers to NULL after free()."
        : issue.cwe === "CWE-78"
        ? " Avoid system() and validate external input."
        : " Review secure coding practices."
    }
  </p>

</div>
        ))}
      </div>
    )}
  </div>
)}
          </div>

          <div className="codeBox">
            <h2>Code Preview</h2>
            <pre>{code || "No code uploaded"}</pre>
          </div>
        </div>

        <div className="history">
          <h2>Scan History</h2>

          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Status</th>
                <th>Confidence</th>
                <th>Severity</th>
                <th>Time</th>
              </tr>
            </thead>

            <tbody>
              {history.length === 0 ? (
                <tr>
                  <td colSpan="5">No scans yet</td>
                </tr>
              ) : (
                history.map((item, index) => (
                  <tr key={index}>
                    <td>{item.file}</td>
                    <td>{item.status}</td>
                    <td>{item.confidence}</td>
                    <td>{item.severity}</td>
                    <td>{item.time}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}