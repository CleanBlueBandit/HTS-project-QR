import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import QRCode from 'qrcode';
import fs from 'fs/promises';
import ExcelJS from 'exceljs';
import bcrypt from 'bcryptjs';
import Archiver from 'archiver';                   // correct import
import crypto from 'crypto';                       // [FIX 1]
import 'dotenv/config';                            // [FIX 11]
import rateLimit from 'express-rate-limit';        // [FIX 12]

// ---------- Middleware ----------
const app = express();
app.use(express.json());

// [FIX 2] Trust first proxy
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET,              // [FIX 11]
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,                // set to true if using HTTPS
    httpOnly: true
  }
}));

// [FIX 6] CSRF token middleware
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomUUID();
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

// [FIX 12] Rate limiters
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, try later.'
});
app.use(generalLimiter);

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Too many registrations, try later.' }
});

// ---------- Auth ----------
const requireAdmin = (req, res, next) => {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  return res.redirect('/login');
};

// ---------- Constants ----------
const IP = "192.168.1.19";
const PORT = 6767;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ADMIN_HASH = process.env.ADMIN_PASSWORD_HASH;   // [FIX 11]

// ---------- Helper: safe HTML escaping [FIX 7] ----------
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ---------- Helper: capitalise first letter ----------
function cfl(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}

// ---------- File helpers ----------
async function load(fileName, defaultValue = {}) {
  const filePath = path.join(__dirname, fileName);
  try {
    const data = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') return defaultValue;
    throw error;
  }
}

async function save(fileName, data) {
  const filePath = path.join(__dirname, fileName);
  const jsonString = JSON.stringify(data, null, 2);
  await fs.writeFile(filePath, jsonString, 'utf-8');
}

// [FIX 3] Serialise writes to prevent race conditions
let writeLock = Promise.resolve();
async function safeSave(fileName, data) {
  return new Promise((resolve, reject) => {
    writeLock = writeLock.then(async () => {
      try {
        await save(fileName, data);
        resolve();
      } catch (err) {
        reject(err);
      }
    });
  });
}

// ---------- Routes ----------

app.get("/", (req, res) => {
  res.sendStatus(403);
});

// ---------- Login page ----------
app.get('/login', (req, res) => {
  if (req.session.isAdmin) return res.redirect('/dashboard');
  const csrfToken = res.locals.csrfToken;   // [FIX 6]

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Login</title>
      <style>
        body { font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; background-color: #f4f6f9; margin: 0; }
        .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; width: 300px; }
        h1 { color: #1f4e78; margin-bottom: 20px; font-size: 24px; }
        input { width: 100%; padding: 12px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; font-size: 16px; }
        button { width: 100%; background-color: #2f5597; color: white; border: none; padding: 12px; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 16px; transition: 0.2s; }
        button:hover { background-color: #1f4e78; }
        #error { color: #dc3545; font-size: 14px; margin-top: 10px; display: none; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>Admin Access</h1>
        <input type="password" id="password" placeholder="Enter Admin Password" onkeydown="if(event.key === 'Enter') login()">
        <button onclick="login()">Login</button>
        <div id="error">Incorrect password.</div>
      </div>
      <script>
        function login() {
          const pass = document.getElementById("password").value;
          fetch("http://${IP}:${PORT}/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: pass, _csrf: "${csrfToken}" })
          })
          .then(res => res.json())
          .then(data => {
            if (data.success) window.location.href = "/dashboard";
            else {
              document.getElementById("error").style.display = "block";
              setTimeout(() => document.getElementById("error").style.display = "none", 3000);
            }
          })
          .catch(err => console.error(err));
        }
      </script>
    </body>
    </html>
  `);
});

app.post('/login', async (req, res) => {
  const { password, _csrf } = req.body;
  // [FIX 6] CSRF check
  if (_csrf !== req.session.csrfToken) {
    return res.status(403).json({ success: false, error: "Invalid CSRF token" });
  }
  if (!password) return res.status(400).json({ success: false, error: "Password required" });

  const isMatch = await bcrypt.compare(password, ADMIN_HASH);
  if (isMatch) {
    req.session.isAdmin = true;
    return res.status(200).json({ success: true });
  }
  return res.status(401).json({ success: false, error: "Invalid credentials" });
});

// ---------- Zip download (admin only) ----------
app.get('/download-zip', requireAdmin, async (req, res) => {   // now admin-only
  try {
    const data = await load('companies.json', {});
    const companies = Object.keys(data);
    if (companies.length === 0) return res.status(400).send("No companies found.");

    const archive = new Archiver('zip', { zlib: { level: 3 } });
    res.attachment('all-company-qrs.zip');
    archive.pipe(res);

    for (const company of companies) {
      const urlToEncode = `http://${IP}:${PORT}/contact?link=${encodeURIComponent(company)}`;
      const qrBuffer = await QRCode.toBuffer(urlToEncode, { type: 'png', width: 300 });
      archive.append(qrBuffer, { name: `${cfl(company)}-qr.png` });
    }

    await archive.finalize();
  } catch (err) {
    console.error("ZIP Generation Error:", err);
    if (!res.headersSent) res.status(500).send('Error generating QR code batch zip.');
  }
});

// ---------- Dashboard ----------
app.get('/dashboard', requireAdmin, async (req, res) => {
  const defaultUrl = `http://${IP}:${PORT}/`;
  const defaultQrCode = await QRCode.toDataURL(defaultUrl);
  const csrfToken = res.locals.csrfToken;   // [FIX 6]

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Dashboard</title>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"></script>
      <style>
        body { 
          font-family: sans-serif; 
          display: flex; 
          gap: 30px;
          align-items: center; 
          justify-content: center; 
          min-height: 100vh; 
          background-color: #f4f6f9; 
          margin: 0; 
          padding: 20px;
          box-sizing: border-box;
        }
        .qr-link-excel { color: #1f4e78; text-decoration: none; font-size: 13px; font-weight: bold; margin-top: 2px; }
        .qr-link-excel:hover { text-decoration: underline; }
        .card { 
          background: white; 
          padding: 30px; 
          border-radius: 12px; 
          box-shadow: 0 4px 12px rgba(0,0,0,0.1); 
          text-align: center; 
          width: 350px;
          height: 480px; 
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          box-sizing: border-box;
        }
        h1 { color: #1f4e78; margin: 0 0 10px 0; font-size: 22px; }
        p { color: #666; font-size: 14px; margin: 0 0 20px 0; line-height: 1.4; }
        .qr-container { display: flex; flex-direction: column; align-items: center; gap: 10px; }
        #qr { width: 160px; height: 160px; border: 2px solid #ddd; padding: 5px; border-radius: 6px; }
        .qr-link { color: #2f5597; text-decoration: none; font-size: 14px; font-weight: bold; }
        .qr-link:hover { text-decoration: underline; }
        .input-group { display: flex; width: 100%; gap: 5px; }
        input { flex: 1; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; }
        .btn-generate { background: #28a745; color: white; border: none; padding: 0 15px; border-radius: 4px; font-weight: bold; cursor: pointer; }
        .btn-generate:hover { background: #218838; }
        a:visited { color: blue; }
      </style>
    </head>
    <body>
      <div class="card">
        <div>
          <h1>Admin Control Panel</h1>
          <p>Manage authentication keys and export system data logs.</p>
        </div>
        <div class="qr-container">
          <img id="qr" src="${defaultQrCode}" alt="QR Code" />
          <a id="dl-link" href="${defaultQrCode}" download="qr-code.png" class="qr-link">Download This QR</a>
          <a href="/download-zip" class="qr-link-batch" style="color: #2f5597; text-decoration: none; font-size: 14px; font-weight: bold;">Download QRs for all companies</a>
          <a href="/export" class="qr-link-excel">Download Excel User Report</a>
          <div class="input-group" style="margin-top: 12px;">
            <input type="text" placeholder="Company Link Identifier" id="url">
            <button class="btn-generate" onclick="generateNewQR()">Create</button>
          </div>
        </div>
      </div>
      <script>
        const csrfToken = "${csrfToken}";
        function generateNewQR() {
          if (typeof qrcode === 'undefined') return alert("QR generator library not loaded.");
          const urlInput = document.getElementById("url").value.trim();
          if (!urlInput) return alert("Please enter a company link identifier!");
          const targetUrl = "http://${IP}:${PORT}/contact?link=" + encodeURIComponent(urlInput);
          try {
            const qr = qrcode(0, 'L');
            qr.addData(targetUrl);
            qr.make();
            const imgDataUrl = qr.createDataURL(6, 2);
            document.getElementById("qr").src = imgDataUrl;
            document.getElementById("dl-link").href = imgDataUrl;
          } catch (err) {
            console.error(err);
            alert("Error generating QR code locally.");
          }
        }
      </script>
    </body>
    </html>
  `);
});

// ---------- Excel export (updated structure) ----------
app.get('/export', requireAdmin, async (req, res) => {
  try {
    const users = await load("users.json");

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('User Interests');

    const headerFill = { type: 'pattern', pattern: 'solid', fgColor: { argb: '2F5597' } };
    const zebraFill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'F2F5F9' } };
    const whiteFont = { name: 'Segoe UI', size: 11, bold: true, color: { argb: 'FFFFFF' } };
    const bodyFont = { name: 'Segoe UI', size: 11, color: { argb: '000000' } };
    const thinBorder = {
      top: { style: 'thin', color: { argb: 'D9D9D9' } },
      left: { style: 'thin', color: { argb: 'D9D9D9' } },
      bottom: { style: 'thin', color: { argb: 'D9D9D9' } },
      right: { style: 'thin', color: { argb: 'D9D9D9' } }
    };

    worksheet.columns = [
      { header: 'First Name', key: 'first', width: 18 },
      { header: 'Last Name', key: 'last', width: 18 },
      { header: 'Visitors Company', key: 'visitorCompany', width: 25 },  // new column
      { header: 'Registered Exhibitors', key: 'companies', width: 35 },
      { header: 'Total Engagement Count', key: 'count', width: 24 }
    ];

    const headerRow = worksheet.getRow(1);
    headerRow.height = 26;
    headerRow.eachCell((cell) => {
      cell.font = whiteFont;
      cell.fill = headerFill;
      cell.alignment = { horizontal: 'center', vertical: 'middle' };
      cell.border = thinBorder;
    });

    let rowIndex = 2;
    // [FIX 4] Users are now objects with UUID keys; iterate values
    for (const user of Object.values(users)) {
      const companyList = Array.isArray(user.companies) ? user.companies.join(', ') : '';
      const totalCount = Array.isArray(user.companies) ? user.companies.length : 0;

      const row = worksheet.addRow({
        first: user.first || '',
        last: user.lastname || '',
        visitorCompany: user.userCompany || '',
        companies: companyList,
        count: totalCount
      });

      row.height = 20;
      row.eachCell((cell, colNumber) => {
        cell.font = bodyFont;
        cell.border = thinBorder;
        if (rowIndex % 2 === 1) cell.fill = zebraFill;
        cell.alignment = { horizontal: colNumber === 5 ? 'right' : 'left', vertical: 'middle' };
      });
      rowIndex++;
    }

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=Registered_Users_Report.xlsx');
    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error("Failed to generate Excel report:", err);
    res.status(500).send("Error generating Excel report");
  }
});

// ---------- Contact (user-facing) ----------
app.get("/contact", async (req, res) => {
  const company = req.query.link;
  const data = await load("companies.json");
  const session = req.session;
  const safeCompany = escapeHtml(company);        // [FIX 7]

  if (!data[company]) return res.sendStatus(400);

  const successHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${safeCompany}</title>
      <style>
        body { margin: 0; padding: 24px; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; font-family: system-ui, -apple-system, sans-serif; background-color: #f9fafb; color: #111827; text-align: center; }
        .card { background: #ffffff; padding: 48px 24px; border-radius: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.04); max-width: 400px; width: 100%; box-sizing: border-box; }
        .icon { font-size: 48px; margin-bottom: 16px; display: block; }
        h1 { margin: 0 0 12px 0; font-size: 22px; font-weight: 600; line-height: 1.3; }
        h2 { margin: 0 0 32px 0; font-size: 16px; font-weight: 400; color: #6b7280; }
        img { max-width: 100%; height: auto; max-height: 160px; border-radius: 8px; object-fit: contain; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>Thank you for your interest in ${safeCompany}!</h1>
        <h2>Further contact is now easier.</h2>
        <img src="${data[company]}" alt="${safeCompany} logo">
      </div>
    </body>
    </html>
  `;

  // [FIX 5] Ensure session.companies is always an array
  if (!Array.isArray(session.companies)) session.companies = [];

  // [FIX 4] Use session.userId and updated user structure
  if (session.userId) {
    const users = await load("users.json");
    const user = users[session.userId];
    if (user) {
      if (!Array.isArray(user.companies)) user.companies = [];
      if (!user.companies.includes(company)) {
        user.companies.push(company);
        session.companies.push(company);
        await safeSave("users.json", users);     // [FIX 3]
      }
    }
    return res.send(successHTML);
  }

  // No session – show registration form
  const csrfToken = res.locals.csrfToken;

  return res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${safeCompany}</title>
      <style>
        body { margin: 0; padding: 24px; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; font-family: system-ui, -apple-system, sans-serif; background-color: #f9fafb; color: #111827; }
        .card { background: #ffffff; padding: 40px 24px; border-radius: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.04); max-width: 400px; width: 100%; box-sizing: border-box; text-align: center; }
        img { max-width: 140px; height: auto; max-height: 120px; margin-bottom: 24px; object-fit: contain; }
        h1 { margin: 0 0 8px 0; font-size: 22px; font-weight: 600; line-height: 1.3; }
        h2 { margin: 0 0 32px 0; font-size: 15px; font-weight: 400; color: #6b7280; line-height: 1.5; }
        .form-group { display: flex; flex-direction: column; gap: 16px; text-align: left; }
        .input-wrapper { display: flex; flex-direction: column; gap: 4px; }
        input[type="text"] { padding: 16px; border: 1px solid #e5e7eb; border-radius: 12px; font-size: 16px; outline: none; transition: border-color 0.2s; box-sizing: border-box; width: 100%; background: #fff; }
        input[type="text"]:focus { border-color: #111827; }
        .error-msg { color: #dc2626; font-size: 13px; margin: 0; min-height: 16px; padding-left: 4px; }
        button { padding: 16px; background-color: #111827; color: #ffffff; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background-color 0.2s; margin-top: 8px; width: 100%; box-sizing: border-box; }
        button:active { background-color: #374151; }
      </style>
    </head>
    <body>
      <div class="card">
        <img src="${data[company]}" alt="${safeCompany} logo">
        <h1>Thanks for your interest!</h1>
        <h2>Just tell us your name so we can reach out later.</h2>
        <div class="form-group">
          <div class="input-wrapper">
            <input type="text" placeholder="First Name" id="name" required>
            <p id="name-req" class="error-msg"></p>
          </div>
          <div class="input-wrapper">
            <input type="text" placeholder="Last Name" id="lastname" required>
            <p id="last-req" class="error-msg"></p>
          </div>
          <!-- NEW: visitor’s own company (not pre-filled) -->
          <div class="input-wrapper">
            <input type="text" placeholder="Your Company" id="userCompany" required>
            <p id="userCompany-req" class="error-msg"></p>
          </div>
          <button onclick="post()">Submit Details</button>
        </div>
      </div>
      <script>
        function post() {
          const first = document.getElementById("name").value;
          const last = document.getElementById("lastname").value;
          const userCompany = document.getElementById("userCompany").value.trim();
          // Validation
          let valid = true;
          if(first === "") { document.getElementById("name-req").innerText = "This field is required"; valid = false; }
          else document.getElementById("name-req").innerText = "";
          if(last === "") { document.getElementById("last-req").innerText = "This field is required"; valid = false; }
          else document.getElementById("last-req").innerText = "";
          if(userCompany === "") { document.getElementById("userCompany-req").innerText = "Your company name is required"; valid = false; }
          else document.getElementById("userCompany-req").innerText = "";
          if(!valid) return;

          const exhibitor = document.title;
          fetch("http://${IP}:${PORT}/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              first: first,
              last: last,
              company: exhibitor,
              userCompany: userCompany,
              _csrf: "${csrfToken}"        // [FIX 6]
            })
          })
          .then(res => { if(!res.ok) throw new Error("Network error"); return res.json(); })
          .then(() => { window.location.href = "/contact?link=${encodeURIComponent(company)}"; })
          .catch(err => console.error(err));
        }
      </script>
    </body>
    </html>
  `);
});

// ---------- Registration endpoint ----------
app.post('/register', registerLimiter, async (req, res) => {   // [FIX 12]
  try {
    const { first, last, company, userCompany, _csrf } = req.body;
    const session = req.session;

    // [FIX 6] CSRF check
    if (_csrf !== session.csrfToken) {
      return res.status(403).json({ success: false, error: "Invalid CSRF token" });
    }

    if (session.userId) {
      return res.status(400).json({ success: false, error: "Session already exists." });
    }
    if (!first) {
      return res.status(400).json({ success: false, error: "First name is required." });
    }

    const users = await load("users.json");

    // [FIX 4] Use UUID as user key, store additional fields
    const userId = crypto.randomUUID();
    session.userId = userId;
    session.name = first;
    session.lastname = last;
    session.userCompany = userCompany || "";
    session.companies = company ? [company] : [];

    users[userId] = {
      first: first,
      lastname: last || "",
      userCompany: userCompany || "",
      companies: company ? [company] : []
    };

    await safeSave("users.json", users);   // [FIX 3]

    return res.status(200).json({ success: true, message: "User registered." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: "Internal Server Error" });
  }
});

// ---------- Logout ----------
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).send("Error clearing session");
    res.clearCookie('connect.sid');
    res.send("Session destroyed.");
  });
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`Server running on http://${IP}:${PORT}`);
});