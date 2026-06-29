import 'dotenv/config';                               // Load .env (FIX 8)
import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import QRCode from 'qrcode';
import fs from 'fs/promises';
import ExcelJS from 'exceljs';
import bcrypt from 'bcryptjs';
import { ZipArchive } from 'archiver';
import crypto from 'crypto';
import { csrfSync } from 'csrf-sync';
import rateLimit from 'express-rate-limit';          // FIX 9

const app = express();

// --- Trust proxy for correct IP (FIX 2) ---
app.set('trust proxy', 1);                           // Enable if behind a reverse proxy

// --- CSRF Protection Setup ---
const { csrfSynchronisedProtection, generateToken } = csrfSync({
  getTokenFromRequest: (req) => req.body._csrf || req.headers['x-csrf-token'],
});

// --- Middleware ---
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-dev-secret', // FIX 8
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,                         // set true on HTTPS
    httpOnly: true,
    sameSite: 'strict'
  }
}));

// --- Rate Limiting (FIX 9) ---
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,                // 15 minutes
  max: 200,                                // limit each IP to 200 requests per windowMs
  message: { success: false, error: 'Too many requests, please try again later.' }
});
app.use(globalLimiter);

const strictRegisterLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,                                 // stricter limit for registration
  message: { success: false, error: 'Too many registration attempts, please try again later.' }
});

// --- Constants ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicPath = path.join(__dirname, 'public');

// Use environment variable for admin hash (FIX 8)
const ADMIN_HASH = process.env.ADMIN_PASSWORD_HASH || '$2b$10$XhgvQHaYVqyPn6FsP3UGOewx7mP6Qg1f/w06xUpk/PA.4RzRHNUSO';

// Build base URL from environment or fallback to a hardcoded value
const BASE_URL = process.env.BASE_URL || 'https://hts-project-qr.vercel.app';

app.use(express.static(publicPath));

// --- File write mutex (FIX 3) ---
const locks = new Map();

async function safeSave(fileName, data) {
  const filePath = path.join(__dirname, fileName);
  // Simple mutex: wait until no other operation on the same file
  while (locks.has(filePath)) {
    await locks.get(filePath);
  }
  let resolveLock;
  const lockPromise = new Promise(res => resolveLock = res);
  locks.set(filePath, lockPromise);

  try {
    const jsonString = JSON.stringify(data, null, 2);
    await fs.writeFile(filePath, jsonString, 'utf-8');
    return true;
  } catch (error) {
    console.error(`Error saving to ${fileName}:`, error);
    throw error;
  } finally {
    locks.delete(filePath);
    resolveLock();
  }
}

// --- Helpers ---
function cfl(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function sanitizeExcelText(text) {
  if (!text || typeof text !== 'string') return text;
  if (/^[=+\-@]/.test(text)) return "'" + text;
  return text;
}

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

// Use safeSave instead of the old save function
// (We'll call safeSave everywhere)

// --- Middleware: require admin ---
const requireAdmin = (req, res, next) => {
  if (req.session && req.session.isAdmin) return next();
  return res.redirect('/login');
};

// --- Routes ---

app.get("/", (req, res) => {
  res.sendStatus(403);
});

// --- Login page (GET) ---
app.get('/login', (req, res) => {
  if (req.session.isAdmin) return res.redirect('/dashboard');
  const csrfToken = generateToken(req);
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
          fetch("${BASE_URL}/login", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": "${csrfToken}"
            },
            body: JSON.stringify({ password: pass })
          })
          .then(res => res.json())
          .then(data => {
            if (data.success) {
              window.location.href = "/dashboard";
            } else {
              const errDiv = document.getElementById("error");
              errDiv.style.display = "block";
              setTimeout(() => errDiv.style.display = "none", 3000);
            }
          })
          .catch(err => console.error(err));
        }
      </script>
    </body>
    </html>
  `);
});

// --- Download ZIP (now admin only – FIX 10) ---
app.get('/download-zip', requireAdmin, async (req, res) => {
    try {
        const data = await load('companies.json', {});
        const companies = Object.keys(data);

        if (companies.length === 0) {
            return res.status(400).send("No companies found to generate QR codes for.");
        }

        const archive = new ZipArchive('zip', { zlib: { level: 3 } });
        
        res.attachment('all-company-qrs.zip');
        archive.pipe(res);

        for (const company of companies) {
            const urlToEncode = `${BASE_URL}/contact?link=${encodeURIComponent(company)}`;
            const qrBuffer = await QRCode.toBuffer(urlToEncode, { type: 'png', width: 300 });
            archive.append(qrBuffer, { name: `${cfl(company)}-qr.png` });
        }

        await archive.finalize();
    } catch (err) {
        console.error("ZIP Generation Error:", err);
        if (!res.headersSent) {
            res.status(500).send('Error generating QR code batch zip.');
        }
    }
});

// --- Dashboard ---
app.get('/dashboard', requireAdmin, async (req, res) => {
  const defaultUrl = `${BASE_URL}/`;
  const defaultQrCode = await QRCode.toDataURL(defaultUrl);
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Dashboard</title>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"></script>
      <style>
        body { font-family: sans-serif; display: flex; gap: 30px; align-items: center; justify-content: center; min-height: 100vh; background-color: #f4f6f9; margin: 0; padding: 20px; box-sizing: border-box; }
        .qr-link-excel { color: #1f4e78; text-decoration: none; font-size: 13px; font-weight: bold; margin-top: 2px; }
        .qr-link-excel:hover { text-decoration: underline; }
        .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; width: 350px; height: 450px; display: flex; flex-direction: column; justify-content: space-between; box-sizing: border-box; }
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
        a:visited { color: #1f4e78; }
      </style>
    </head>
    <body>
      <div class="card" style="height: 480px;">
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
        function generateNewQR() {
          if (typeof qrcode === 'undefined') return alert("QR library not loaded.");
          const urlInput = document.getElementById("url").value.trim();
          if (!urlInput) return alert("Please enter a company link identifier!");
          const targetUrl = "${BASE_URL}/contact?link=" + encodeURIComponent(urlInput);
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

// --- Excel export (FIX 11: rename column) ---
app.get('/export', requireAdmin, async (req, res) => {
  try {
    const users = await load("users.json");
    const companiesData = await load("companies.json");
    const allCompanyNames = Object.keys(companiesData);

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

    const sanitizedHeaders = allCompanyNames.map(sanitizeExcelText);

    const baseColumns = [
      { header: 'First Name', key: 'first', width: 18 },
      { header: 'Last Name', key: 'last', width: 18 },
      { header: 'Visitors Company', key: 'company', width: 22 },   // FIX 11: renamed
      { header: 'Registered Companies', key: 'companies', width: 35 },
      { header: 'Total Engagement Count', key: 'count', width: 24 }
    ];

    const dynamicCompanyColumns = sanitizedHeaders.map((header, i) => ({
      header,
      key: `comp_${allCompanyNames[i]}`,
      width: 15
    }));

    worksheet.columns = [...baseColumns, ...dynamicCompanyColumns];

    const headerRow = worksheet.getRow(1);
    headerRow.height = 26;
    headerRow.eachCell((cell) => {
      cell.font = whiteFont;
      cell.fill = headerFill;
      cell.alignment = { horizontal: 'center', vertical: 'middle' };
      cell.border = thinBorder;
    });

    let rowIndex = 2;
    for (const userId in users) {
      const userProfile = users[userId];
      const userCompanies = Array.isArray(userProfile.companies) ? userProfile.companies : [];
      const companyList = userCompanies.join(', ');
      const totalCount = userCompanies.length;

      const rowData = {
        first: userProfile.first || '',
        last: userProfile.last || '',
        company: userProfile.company || '',          // "Visitors Company"
        companies: companyList,
        count: totalCount
      };

      allCompanyNames.forEach(company => {
        rowData[`comp_${company}`] = userCompanies.includes(company);
      });

      const row = worksheet.addRow(rowData);
      row.height = 20;
      row.eachCell((cell, colNumber) => {
        cell.font = bodyFont;
        cell.border = thinBorder;
        if (rowIndex % 2 === 1) cell.fill = zebraFill;
        if (colNumber === 4) cell.alignment = { horizontal: 'right', vertical: 'middle' };
        else if (colNumber > 5) cell.alignment = { horizontal: 'center', vertical: 'middle' };
        else cell.alignment = { horizontal: 'left', vertical: 'middle' };
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

// --- Contact page ---
app.get("/contact", async (req, res) => {
  const company = req.query.link;
  const data = await load("companies.json");
  const safeCompany = escapeHtml(company);
  const logoUrl = data[company];
  if (!data[company]) return res.sendStatus(400);

  console.log('Companies data:', data);
  console.log('Requested company:', company);

  

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
        <img src="${logoUrl}" alt="${safeCompany} logo">
      </div>
    </body>
    </html>
  `;

  if (req.session.userId) {
    const users = await load("users.json");
    const user = users[req.session.userId];
    if (user && user.companies) {
      if (user.companies.includes(company)) {
        return res.send(successHTML);
      }
      user.companies.push(company);
      await safeSave("users.json", users);       // FIX 3: safeSave
      req.session.companies = user.companies;
      return res.send(successHTML);
    } else {
      req.session.destroy(() => {});
      return res.redirect(`/contact?link=${encodeURIComponent(company)}`);
    }
  }

  // No session – show registration form
  const csrfToken = generateToken(req);
  res.send(`
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
        <img src="${logoUrl}" alt="${safeCompany} logo">
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
          <div class="input-wrapper">
            <input type="text" placeholder="Your company" id="company" required>
            <p id="comp-req" class="error-msg"></p>
          </div>
          <button onclick="post()">Submit Details</button>
        </div>
      </div>
      <script>
        function post() {
          const first = document.getElementById("name").value;
          const last = document.getElementById("lastname").value;
          const myCompany = document.getElementById("company").value;
          if(first == "" || last == "" || myCompany == ""){
            if(first == "") document.getElementById("name-req").innerText = "This field is required";
            else document.getElementById("name-req").innerText = "";
            if(last == "") document.getElementById("last-req").innerText = "This field is required";
            else document.getElementById("last-req").innerText = "";
            if(myCompany == "") document.getElementById("comp-req").innerText = "This field is required";
            else document.getElementById("comp-req").innerText = "";
            return;
          }
          const company = "${company}";
          fetch("${BASE_URL}/register", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": "${csrfToken}"
            },
            body: JSON.stringify({
              first: first,
              last: last,
              myCompany: myCompany,
              company: company
            })
          })
          .then(res => res.json())
          .then((data) => {
            if(data.success) window.location.href = "/contact?link=${company}";
          })
          .catch(err => console.error(err));
        }
      </script>
    </body>
    </html>
  `);
});

// --- Logout ---
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).send("Error clearing session");
    res.clearCookie('connect.sid');
    res.send("Entire session destroyed.");
  });
});

// --- POST routes (CSRF protected) ---
app.post('/login', csrfSynchronisedProtection, async (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ success: false, error: "Password required" });
  }
  const isMatch = await bcrypt.compare(password, ADMIN_HASH);
  if (isMatch) {
    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, error: "Session regeneration failed" });
      }
      req.session.isAdmin = true;
      return res.status(200).json({ success: true });
    });
  } else {
    return res.status(401).json({ success: false, error: "Invalid credentials" });
  }
});

app.post('/register', strictRegisterLimiter, csrfSynchronisedProtection, async (req, res) => {
  try {
    const { first, last, myCompany, company, lang } = req.body;
    if (req.session.userId) {
      return res.status(400).json({ success: false, error: "Session already exists." });
    }
    if (!first) {
      return res.status(400).json({ success: false, error: "First name is required." });
    }

    const userId = crypto.randomUUID();
    const users = await load("users.json");

    users[userId] = {
      first: first,
      last: last || "",
      company: myCompany,
      companies: company ? [company] : []
    };

    req.session.userId = userId;
    req.session.companies = company ? [company] : [];

    await safeSave("users.json", users);              // FIX 3: safeSave
    return res.status(200).json({ success: true, message: "User registered." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: "Internal Server Error" });
  }
});

// --- Error handler for CSRF & other uncaught errors ---
app.use((err, req, res, next) => {
  if (err.message === 'invalid csrf token') {
    return res.status(403).json({ success: false, error: 'Invalid or missing CSRF token. Please refresh the page.' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: 'Internal Server Error' });
});

// --- Start server ---
const PORT = process.env.PORT || 6767;
app.listen(PORT, () => {
  console.log(`Server running on ${BASE_URL}`);
});
