import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import QRCode from 'qrcode';
import fs from 'fs/promises';
import ExcelJS from 'exceljs';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { csrfSync } from 'csrf-sync';
import rateLimit from 'express-rate-limit';
import postgres from 'postgres';
import JSZip from 'jszip';


const app = express();

// --- Trust proxy (Vercel) ---
app.set('trust proxy', 1);

// --- CSRF ---
const { csrfSynchronisedProtection, generateToken } = csrfSync({
  getTokenFromRequest: (req) => req.body._csrf || req.headers['x-csrf-token'],
});

// --- Constants ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const ADMIN_HASH = process.env.ADMIN_PASSWORD_HASH;
const sql = postgres(process.env.DATABASE_URL, { ssl: 'require' });

// ✅ FIXED BASE_URL
const BASE_URL = process.env.BASE_URL || 'https://hts-project-qr.vercel.app';

// ------------------------------------------------------------------
//  POSTGRES-BACKED SESSION STORE
//  (MemoryStore doesn't survive across serverless invocations on
//  Vercel, since each one can run in a separate process/instance.)
// ------------------------------------------------------------------
class PgSessionStore extends session.Store {
  constructor(sqlClient) {
    super();
    this.sql = sqlClient;
  }

  async get(sid, cb) {
    try {
      const rows = await this.sql`
        SELECT sess FROM "session" WHERE sid = ${sid} AND expire >= now()
      `;
      cb(null, rows.length ? rows[0].sess : null);
    } catch (err) {
      cb(err);
    }
  }

  async set(sid, sessionData, cb) {
    try {
      const expire = new Date(Date.now() + (sessionData.cookie?.maxAge || 86400000));
      await this.sql`
        INSERT INTO "session" (sid, sess, expire)
        VALUES (${sid}, ${this.sql.json(sessionData)}, ${expire})
        ON CONFLICT (sid) DO UPDATE SET sess = EXCLUDED.sess, expire = EXCLUDED.expire
      `;
      cb(null);
    } catch (err) {
      cb(err);
    }
  }

  async destroy(sid, cb) {
    try {
      await this.sql`DELETE FROM "session" WHERE sid = ${sid}`;
      cb(null);
    } catch (err) {
      cb(err);
    }
  }

  async touch(sid, sessionData, cb) {
    try {
      const expire = new Date(Date.now() + (sessionData.cookie?.maxAge || 86400000));
      await this.sql`UPDATE "session" SET expire = ${expire} WHERE sid = ${sid}`;
      cb(null);
    } catch (err) {
      cb(err);
    }
  }
}

// --- Middleware ---
app.use(express.json());
app.use(session({
  store: new PgSessionStore(sql),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,                      // requires HTTPS (Vercel is fine)
    httpOnly: true,
    sameSite: 'none',                  // ✅ iOS Safari attaches the cookie on the cross-app QR jump
    maxAge: 1000 * 60 * 60 * 24 * 7    // 7 days — persistent cookie, survives Safari backgrounding
  }
}));

// --- Rate limiting ---
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, error: 'Too many requests, please try again later.' }
});
app.use(globalLimiter);

// NOTE: at a 1000+ person event, many phones share one NAT'd Wi-Fi IP.
// A low per-IP cap would wrongly block legitimate registrations, so this is
// set generously. Lower it if you ever run this somewhere without shared Wi-Fi.
const strictRegisterLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, error: 'Too many registration attempts, please try again later.' }
});

app.use(express.static(publicPath));

// ------------------------------------------------------------------
//  HELPER: read static JSON files (read-only, for companies.json only)
// ------------------------------------------------------------------
async function loadStatic(fileName, defaultValue = {}) {
  const filePath = path.join(__dirname, fileName);
  try {
    const data = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') return defaultValue;
    throw error;
  }
}

async function loadCompanies() {
  return loadStatic('companies.json', {});
}

// ------------------------------------------------------------------
//  USER DATABASE HELPERS
// ------------------------------------------------------------------
const TABLE_NAME = 'USERS_users';  // ✅ Your prefixed table name

async function loadUsers() {
  const rows = await sql`SELECT * FROM ${sql(TABLE_NAME)};`;
  const users = {};
  rows.forEach(row => {
    let companiesArr = row.companies;
    if (typeof companiesArr === 'string') {
      try {
        companiesArr = JSON.parse(companiesArr);
      } catch {
        companiesArr = [];
      }
    }
    users[row.userid] = {
      first: row.first_name,
      last: row.last_name || '',
      company: row.my_company || '',
      companies: Array.isArray(companiesArr) ? companiesArr : []
    };
  });
  return users;
}

// Load a single user by id (cheaper than loading the whole table)
async function loadUser(userId) {
  const rows = await sql`SELECT * FROM ${sql(TABLE_NAME)} WHERE userid = ${userId} LIMIT 1;`;
  if (!rows.length) return null;
  const row = rows[0];
  let companiesArr = row.companies;
  if (typeof companiesArr === 'string') {
    try { companiesArr = JSON.parse(companiesArr); } catch { companiesArr = []; }
  }
  return {
    first: row.first_name,
    last: row.last_name || '',
    company: row.my_company || '',
    companies: Array.isArray(companiesArr) ? companiesArr : []
  };
}

async function saveUser(userId, data) {
  const { first, last, company, companies } = data;
  await sql`
    INSERT INTO ${sql(TABLE_NAME)} (userid, first_name, last_name, my_company, companies)
    VALUES (${userId}, ${first}, ${last || ''}, ${company || ''}, ${JSON.stringify(companies)})
    ON CONFLICT (userid) DO UPDATE SET
      first_name = EXCLUDED.first_name,
      last_name = EXCLUDED.last_name,
      my_company = EXCLUDED.my_company,
      companies = EXCLUDED.companies
  `;
}

// ------------------------------------------------------------------
//  RELINK TOKEN (cookie-independent identity, for iOS Safari)
//  We hand the browser a signed token after registration. It lives in
//  localStorage. On any later scan, if the cookie was dropped, the page
//  POSTs this token to /relink to re-establish the session. The HMAC
//  signature means a stolen UUID alone can't be used to impersonate.
// ------------------------------------------------------------------
function signUserId(userId) {
  const mac = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(userId)
    .digest('hex');
  return `${userId}.${mac}`;
}

function verifyRelinkToken(token) {
  if (!token || typeof token !== 'string') return null;
  const idx = token.lastIndexOf('.');
  if (idx === -1) return null;
  const userId = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  if (!userId || !sig) return null;
  const expected = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(userId)
    .digest('hex');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;
  return userId;
}

// ------------------------------------------------------------------
//  OTHER HELPERS
// ------------------------------------------------------------------
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

// ------------------------------------------------------------------
//  ADMIN MIDDLEWARE
// ------------------------------------------------------------------
const requireAdmin = (req, res, next) => {
  if (req.session && req.session.isAdmin) return next();
  return res.redirect('/login');
};

// ------------------------------------------------------------------
//  ROUTES
// ------------------------------------------------------------------

app.get("/", (req, res) => {
  res.sendStatus(403);
});

// --- Login page ---
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
          fetch("/login", {
            method: "POST",
            credentials: "same-origin",
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

// --- Download ZIP ---
app.get('/download-zip', requireAdmin, async (req, res) => {
  try {
    const data = await loadCompanies();
    const companies = Object.keys(data);
    if (companies.length === 0) {
      return res.status(400).send("No companies found to generate QR codes for.");
    }

    const zip = new JSZip();
    for (const company of companies) {
      const urlToEncode = `${BASE_URL}/contact?link=${encodeURIComponent(company)}`;
      const qrBuffer = await QRCode.toBuffer(urlToEncode, { type: 'png', width: 300 });
      zip.file(`${cfl(company)}-qr.png`, qrBuffer);
    }

    const zipBuffer = await zip.generateAsync({
      type: 'nodebuffer',
      compression: 'DEFLATE',
      compressionOptions: { level: 6 }
    });

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename=all-company-qrs.zip');
    res.send(zipBuffer);
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

// --- Excel export (uses Postgres) ---
app.get('/export', requireAdmin, async (req, res) => {
  try {
    const users = await loadUsers();               // from DB
    const companiesData = await loadCompanies();   // static file
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
      { header: 'Visitors Company', key: 'company', width: 22 },
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
        company: userProfile.company || '',
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
  const data = await loadCompanies();
  if (!data[company]) return res.sendStatus(400);

  const safeCompany = escapeHtml(company);
  const logoUrl = data[company];

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

  // If user already has a valid session, record the visit and show success.
  if (req.session.userId) {
    const user = await loadUser(req.session.userId);
    if (user) {
      if (user.companies.includes(company)) {
        return res.send(successHTML);
      }
      user.companies.push(company);
      try {
        await saveUser(req.session.userId, user);
      } catch (err) {
        console.error('Failed to save company visit:', err);
      }
      req.session.companies = user.companies;
      return res.send(successHTML);
    } else {
      // session points at a user that no longer exists — clear and retry
      req.session.destroy(() => {});
      return res.redirect(`/contact?link=${encodeURIComponent(company)}`);
    }
  }

  // No session — show registration form, BUT first try a cookie-independent
  // relink using a token previously stored in localStorage (iOS Safari path).
  const csrfToken = generateToken(req);
  const companyJson = JSON.stringify(company);
  const csrfJson = JSON.stringify(csrfToken);

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
        #relink-status { color: #6b7280; font-size: 14px; padding: 24px 0; }
      </style>
    </head>
    <body>
      <div class="card" id="reg-card">
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
        var RELINK_KEY = "hts_qr_relink";
        var COMPANY = ${companyJson};
        var CSRF = ${csrfJson};

        // --- Cookie-independent relink (runs on load) -------------------
        // If this visitor registered before, their signed token is in
        // localStorage even if Safari wiped the session cookie. Use it to
        // restore the session so the form never reappears.
        (function tryRelink() {
          var token = null;
          try { token = localStorage.getItem(RELINK_KEY); } catch (e) {}
          if (!token) return;  // first-time visitor → show the form normally

          var card = document.getElementById("reg-card");
          if (card) card.style.display = "none";  // hide form while relinking

          fetch("/relink", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
            body: JSON.stringify({ token: token, company: COMPANY })
          })
          .then(function (r) { return r.json(); })
          .then(function (d) {
            if (d && d.success) {
              window.location.reload();   // now has a session → success page
            } else {
              try { localStorage.removeItem(RELINK_KEY); } catch (e) {}
              if (card) card.style.display = "";   // token invalid → show form
            }
          })
          .catch(function () {
            if (card) card.style.display = "";
          });
        })();

        // --- Registration ----------------------------------------------
        function post() {
          const first = document.getElementById("name").value;
          const last = document.getElementById("lastname").value;
          const myCompany = document.getElementById("company").value;
          if (first == "" || last == "" || myCompany == "") {
            document.getElementById("name-req").innerText = (first == "") ? "This field is required" : "";
            document.getElementById("last-req").innerText = (last == "") ? "This field is required" : "";
            document.getElementById("comp-req").innerText = (myCompany == "") ? "This field is required" : "";
            return;
          }
          fetch("/register", {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": CSRF
            },
            body: JSON.stringify({
              first: first,
              last: last,
              myCompany: myCompany,
              company: COMPANY
            })
          })
          .then(res => res.json())
          .then((data) => {
            if (data.success) {
              // Save the cookie-independent token for future scans
              if (data.relinkToken) {
                try { localStorage.setItem(RELINK_KEY, data.relinkToken); } catch (e) {}
              }
              window.location.href = "/contact?link=" + encodeURIComponent(COMPANY);
            }
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
    const { first, last, myCompany, company } = req.body;
    if (req.session.userId) {
      return res.status(400).json({ success: false, error: "Session already exists." });
    }
    if (!first) {
      return res.status(400).json({ success: false, error: "First name is required." });
    }

    const userId = crypto.randomUUID();
    await saveUser(userId, {
      first,
      last: last || '',
      company: myCompany || '',
      companies: company ? [company] : []
    });

    req.session.userId = userId;
    req.session.companies = company ? [company] : [];

    return res.status(200).json({
      success: true,
      message: "User registered.",
      relinkToken: signUserId(userId)   // ✅ cookie-independent fallback token
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: "Internal Server Error" });
  }
});

// --- Relink: re-establish a session from a localStorage token ---
// Used when iOS Safari dropped the session cookie. The token is HMAC-signed
// so a bare UUID can't be forged into a valid identity.
app.post('/relink', csrfSynchronisedProtection, async (req, res) => {
  try {
    const { token, company } = req.body;
    const userId = verifyRelinkToken(token);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Invalid token." });
    }

    const user = await loadUser(userId);
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found." });
    }

    // Re-establish the session
    req.session.userId = userId;

    // Record the company visit (only if it's a real company and not a dup)
    if (company) {
      const companies = await loadCompanies();
      if (companies[company] && !user.companies.includes(company)) {
        user.companies.push(company);
        await saveUser(userId, user);
      }
    }
    req.session.companies = user.companies;

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('Relink error:', err);
    return res.status(500).json({ success: false, error: "Internal Server Error" });
  }
});

// --- Error handler for CSRF & others ---
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