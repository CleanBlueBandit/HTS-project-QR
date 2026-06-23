import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import QRCode from 'qrcode';
import fs from 'fs/promises';


// Middleware
const app = express();
app.use(express.json());
app.use(session({
  secret: 'your-super-secret-key', 
  resave: false,                   
  saveUninitialized: true,         
  cookie: { 
    maxAge: 60000 * 10,            
    secure: false,                 
    httpOnly: true                 
  }
}));


// Constants

const IP = "10.0.0.110";
const PORT = 6767;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Variables

let locked = false;

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
    res.status(200).sendFile(sendHTML("index"));
})

app.get('/qr', async (req, res) => {
    if(locked){
        return res.sendStatus(404);
    }
    try {
        const urlToEncode = `http://${IP}:${PORT}/`;

        const qrCodeDataUrl = await QRCode.toDataURL(urlToEncode);

        res.send(`
            <!DOCTYPE html>
            <html>
            <head><title>Scan Me</title></head>
            <body style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:100vh; font-family:sans-serif;">
                <h1>Scan to Authenticate</h1>
                <img id="qr" src="${qrCodeDataUrl}" alt="QR Code" style="width:250px; height:250px; border: 2px solid #000; padding: 10px; border-radius: 8px;" />
                <p>Scan this with your phone to instantly log in.</p>
                <input type="text" placeholder="New URL" id="url">
                <button onclick="post()">Generate</button>

                <script>
                    function post() {
                        const iurl = document.getElementById("url").value;
                        
                        fetch("http://10.0.0.110:6767/qr", {
                            method: "POST", // 2. Explicitly set method to POST
                            headers: {
                                "Content-Type": "application/json"
                            }, 
                            body: JSON.stringify({
                                url: iurl
                            })
                        }) 
                        .then(res => {
                            if (!res.ok) throw new Error("Network response was not ok");
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
    } 
    catch (err) {
        res.status(500).send('Error generating QR code');
    }
});

app.get("/contact", async (req, res) => {
    const company = req.query.link;
    const data = await load("companies.json");
    if(!data[company]){
        res.sendStatus(400);
    }
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>${company}</title></head>
        <body style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:100vh; font-family:sans-serif;">
            <h1>Homepage for ${company}!</h1>
            <img src="${data[company]}">
            <div style="display:block">
                <input type="text" placeholder="name">
                <input type="text" placeholder="lastname">
                <button onclick="post()">Submit</button>
            </div>
            <script>
                function post() {
                    const iname = document.getElementById("name").value;
                    const ipass = document.getElementById("pass").value;
                    const companyTitle = document.title;

                    
                    fetch("http://10.0.0.110:6767/register", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        }, 
                        body: JSON.stringify({
                            firstname: ifirst,
                            lastname: ilast,
                            company: companyTitle
                        })
                    })
                    .then(res => {
                        if (!res.ok) throw new Error("Network response was not ok");
                        return res.json();
                    })
                    .then((data) => {
                        window.location.href = "/done";
                    })
                    .catch(err => console.error(err));
                }
            </script>

        </body>
        </html>
    `);
})

app.get("/done", (req, res) => {
    return res.sendFile(sendHTML("completed"));
})
// Post

app.post('/register', async (req, res) => {
    
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


app.post("/register", (req, res) => {
    
})

// Start server

app.listen(PORT, () => {
  console.log(`Server running on http://${IP}:${PORT}`);
});