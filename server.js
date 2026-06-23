import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import QRCode from 'qrcode';
import fs from 'fs/promises';
import ExcelJS from 'exceljs';
import bcrypt from 'bcryptjs';

// Middleware
const app = express();
app.use(express.json());
app.use(session({
  secret: 'your-super-secret-key', 
  resave: false,                   
  saveUninitialized: true,         
  cookie: {          
    secure: false,                 
    httpOnly: true                 
  }
}));
const requireAdmin = (req, res, next) => {
    if (req.session && req.session.isAdmin) {
        return next();
    }
    return res.redirect('/login');
};

// Constants
const IP = "192.168.1.19";
const PORT = 6767;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ADMIN_HASH = "$2b$10$XhgvQHaYVqyPn6FsP3UGOewx7mP6Qg1f/w06xUpk/PA.4RzRHNUSO";

// Global variables

// Helpers
function sendHTML(file){
    return path.join(__dirname, file + ".html")
}

async function load(fileName, defaultValue = {}) {
    const filePath = path.join(__dirname, fileName);
    try {
        const data = await fs.readFile(filePath, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return defaultValue;
        }
        throw error;
    }
}

async function save(fileName, data) {
    const filePath = path.join(__dirname, fileName);
    try {
        const jsonString = JSON.stringify(data, null, 2);
        await fs.writeFile(filePath, jsonString, 'utf-8');
        return true;
    } catch (error) {
        console.error(`Error saving to ${fileName}:`, error);
        throw error;
    }
}

// Get
app.get("/", (req, res) => {
    res.sendStatus(403);
})

app.get('/login', (req, res) => {
    if (req.session.isAdmin) return res.redirect('/dashboard');

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


app.get('/dashboard', requireAdmin, async (req, res) => {

    try {
        const defaultUrl = `http://${IP}:${PORT}/`;
        const defaultQrCode = await QRCode.toDataURL(defaultUrl);

        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Admin Dashboard</title>
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
                    .card { 
                        background: white; 
                        padding: 30px; 
                        border-radius: 12px; 
                        box-shadow: 0 4px 12px rgba(0,0,0,0.1); 
                        text-align: center; 
                        width: 350px;
                        height: 400px;
                        display: flex;
                        flex-direction: column;
                        justify-content: space-between;
                        box-sizing: border-box;
                    }
                    h1 { color: #1f4e78; margin: 0 0 10px 0; font-size: 22px; }
                    p { color: #666; font-size: 14px; margin: 0 0 20px 0; line-size: 1.4; }
                    
                    /* Export Section styles */
                    .btn-download { 
                        display: block; 
                        background-color: #2f5597; 
                        color: white; 
                        text-decoration: none; 
                        padding: 14px; 
                        border-radius: 6px; 
                        font-weight: bold; 
                        transition: background 0.2s; 
                        font-size: 15px; 
                    }
                    .btn-download:hover { background-color: #1f4e78; }

                    /* QR Section styles */
                    .qr-container { display: flex; flex-direction: column; align-items: center; gap: 10px; }
                    #qr { width: 160px; height: 160px; border: 2px solid #ddd; padding: 5px; border-radius: 6px; }
                    .input-group { display: flex; width: 100%; gap: 5px; }
                    input { flex: 1; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; }
                    .btn-generate { background: #28a745; color: white; border: none; padding: 0 15px; border-radius: 4px; font-weight: bold; cursor: pointer; }
                    .btn-generate:hover { background: #218838; }
                </style>
            </head>
            <body>

                <div class="card">
                    <div>
                        <h1>User Report Exporter</h1>
                    <a href="/export" class="btn-download">Download Excel Report</a>
                    </div>
                </div>

                <div class="card">
                    <div>
                        <h1>QR Authentication Engine</h1>
                    
                    <div class="qr-container">
                        <img id="qr" src="${defaultQrCode}" alt="QR Code" />
                        <div class="input-group">
                            <input type="text" placeholder="" id="url">
                            <button class="btn-generate" onclick="generateNewQR()">Create</button>
                        </div>
                    </div>
                </div>

                <script>
                    function generateNewQR() {
                        const targetLink = document.getElementById("url").value.trim();
                        if (!targetLink) return alert("Please enter a valid company link identifier.");
                        
                        fetch("http://${IP}:${PORT}/qr", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" }, 
                            body: JSON.stringify({ url: targetLink })
                        }) 
                        .then(res => {
                            if (!res.ok) throw new Error("Server rejected QR allocation request.");
                            return res.json();
                        })
                        .then((data) => {
                            document.getElementById("qr").src = data.src;
                        })
                        .catch(err => console.error("Error generating QR:", err));
                    }
                </script>
            </body>
            </html>
        `);
    } catch (err) {
        console.error("Dashboard failed to initialize components:", err);
        res.status(500).send("Error rendering dashboard configurations.");
    }
});

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
            { header: 'Registered Companies', key: 'companies', width: 35 },
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
        for (const firstName in users) {
            const userProfile = users[firstName];
            const companyList = Array.isArray(userProfile.companies) ? userProfile.companies.join(', ') : '';
            const totalCount = Array.isArray(userProfile.companies) ? userProfile.companies.length : 0;

            const row = worksheet.addRow({
                first: firstName,
                last: userProfile.lastname || '',
                companies: companyList,
                count: totalCount
            });

            row.height = 20;

            row.eachCell((cell, colNumber) => {
                cell.font = bodyFont;
                cell.border = thinBorder;
                
                if (rowIndex % 2 === 1) {
                    cell.fill = zebraFill;
                }

                if (colNumber === 4) {
                    cell.alignment = { horizontal: 'right', vertical: 'middle' };
                } else {
                    cell.alignment = { horizontal: 'left', vertical: 'middle' };
                }
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


app.get("/contact", async (req, res) => {
    const company = req.query.link;
    const data = await load("companies.json");
    const session = req.session;
    if(!data[company]){
        return res.sendStatus(400);
    }

    const successHTML = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${company}</title>
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
                <h1>Thank you for your interest in ${company}!</h1>
                <h2>Further contact is now easier.</h2>
                <img src="${data[company]}" alt="${company} logo">
            </div>
        </body>
        </html>
    `;

    if(req.session.name){
        if(session.companies.includes(company)){
            return res.send(successHTML);
        }
        session.companies.push(company);
        const users = await load("users.json");
        users[session.name].companies.push(company);
        await save("users.json", users)
        return res.send(successHTML);
    }

    return res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${company}</title>
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
                <img src="${data[company]}" alt="${company} logo">
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
                    <button onclick="post()">Submit Details</button>
                </div>
            </div>

            <script>
                function post() {
                    const first = document.getElementById("name").value;
                    const last = document.getElementById("lastname").value;
                    
                    if(first == "" || last == ""){
                        if(first == ""){
                            document.getElementById("name-req").innerText = "This field is required";
                        } else {
                            document.getElementById("name-req").innerText = "";
                        }
                        if(last == ""){
                            document.getElementById("last-req").innerText = "This field is required";
                        } else {
                            document.getElementById("last-req").innerText = "";
                        }
                        return;
                    }
                    const company = document.title;
                    
                    fetch("http://${IP}:${PORT}/register", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        }, 
                        body: JSON.stringify({
                            first: first,
                            last: last,
                            company: company
                        })
                    })
                    .then(res => {
                        if (!res.ok) throw new Error("Network response was not ok");
                        return res.json();
                    })
                    .then((data) => {
                        window.location.href = "/contact?link=${company}";
                    })
                    .catch(err => console.error(err));
                }
            </script>
        </body>
        </html>
    `);
})

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).send("Error clearing session");
        
        res.clearCookie('connect.sid'); 
        res.send("Entire session destroyed.");
    });
});

// Post

app.post('/login', async (req, res) => {
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ success: false, error: "Password required" });
    }

    const isMatch = await bcrypt.compare(password, ADMIN_HASH);

    if (isMatch) {
        req.session.isAdmin = true;
        return res.status(200).json({ success: true });
    } else {
        return res.status(401).json({ success: false, error: "Invalid credentials" });
    }
});

app.post('/register', async (req, res) => {
    try {
        const { first, last, company } = req.body;
        const session = req.session;

        if (session.name) {
            return res.status(400).json({ 
                success: false, 
                error: "Session already exists. Registration denied." 
            });
        }

        if (!first) {
            return res.status(400).json({ 
                success: false, 
                error: "First name is required." 
            });
        }

        const users = await load("users.json");

        session.name = first;
        session.lastname = last;
        session.companies = company ? [company] : [];

        users[first] = {
            lastname: last || "",
            companies: company ? [company] : []
        };

        await save("users.json", users);
        
        return res.status(200).json({ 
            success: true, 
            message: "User successfully registered and session created." 
        });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, error: "Internal Server Error" });
    }
});

app.post('/qr', async (req, res) => {
    if(locked){
        return res.sendStatus(404);
    }
    try {
        const urlToEncode = `http://${IP}:${PORT}/contact?link=`+req.body.url;

        const qrCodeDataUrl = await QRCode.toDataURL(urlToEncode);

        res.status(200).json({"src" : qrCodeDataUrl});
    }
    catch (err) {
        res.status(500).json({ "ERR":'Error generating QR code'});
    }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://${IP}:${PORT}`);
});