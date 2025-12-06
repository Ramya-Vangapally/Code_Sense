const { spawn } = require("child_process");
const path = require("path");

function queueEmail(to, subject, html, adminEmail) {
  const pythonCommand = "C:\\Users\\Sreenithya\\AppData\\Local\\Programs\\Python\\Python310\\python.exe";

  const backendPath = __dirname;  // folder where python_tasks exists

  const scriptPath = path.join(__dirname, "python_tasks", "enqueue_email.py");

  const child = spawn(
    pythonCommand,
    [scriptPath, to, subject, html, adminEmail],
    {
      env: {
        ...process.env,      // FIXED — previously broken
        PYTHONPATH: backendPath
      }
    }
  );

  child.stdout.on("data", data => {
    console.log("PY:", data.toString());
  });

  child.stderr.on("data", data => {
    console.error("PY ERR:", data.toString());
  });
}

module.exports = { queueEmail };
