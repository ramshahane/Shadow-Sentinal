const express = require('express');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const app = express();
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
// const tf = require('@tensorflow/tfjs-node');
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));

const db = new sqlite3.Database('./honeydb.db');

// Middleware
app.use(express.static(path.join(__dirname, 'public'))); // Static files
app.use(express.json()); // JSON parsing
app.use(express.urlencoded({ extended: true })); // Form data parsing
// app.set('trust proxy', true);
app.use('/files', express.static('files'));
app.use('/files/fake', express.static(path.join(__dirname, 'files/fake')));

// Route to get list of files in the 'files/fake' directory
app.get('/get-files', (req, res) => {
  const dirPath = path.join(__dirname, 'files/fake');
  fs.readdir(dirPath, (err, files) => {
    if (err) {
      return res.status(500).send('Unable to scan directory');
    }

    // Filter to only show valid file types if necessary (optional)
    const validFiles = files.filter(file => file.match(/\.(txt|jpg|pdf)$/));
    
    res.json(validFiles);
  });
});


app.use(express.static(path.join(__dirname, 'views')));






// Session setup
app.use(
  session({
    secret: 'honeypotkey',
    resave: false,
    saveUninitialized: true,
  })
);

// Data for users and attack logs
const users = [
  { id: 1, email: 'yash@gmail.com', password: '1234' }, // In production, use hashed passwords
  { id: 2, email: 'user2@example.com', password: '1234' },
];

const attackLogs = [];

// // File upload setup
// const upload = multer({ dest: 'uploads/' }); // Files will be uploaded to the 'uploads' directory

// // Function to check for malicious files
// async function isMaliciousFile(filePath, fileName) {
//   const suspiciousExtensions = ['.php', '.exe'];
//   const extension = path.extname(fileName).toLowerCase();
//   const fileSize = fs.statSync(filePath).size;

//   // Check for suspicious extensions or anomalous file size
//   if (suspiciousExtensions.includes(extension) || fileSize > 10 * 1024 * 1024) {
//     return true; // Flag as malicious
//   }

//   // Example of a simple check for malicious content
//   const fileContent = fs.readFileSync(filePath, 'utf-8');
//   const suspiciousPatterns = ['eval', 'system', 'base64_decode', 'shell_exec'];
//   if (suspiciousPatterns.some((pattern) => fileContent.includes(pattern))) {
//     return true; // Malicious content found
//   }

//   // Add additional detection logic or ML model prediction here if needed
//   return false; // File is safe
// }

// // Middleware for file upload vulnerability detection
// app.post('/upload', upload.single('file'), async (req, res) => {
//   const file = req.file;

//   if (!file) {
//     return res.status(400).send('No file uploaded.');
//   }

//   const isMalicious = await isMaliciousFile(file.path, file.originalname);

//   if (isMalicious) {
//     attackLogs.push({
//       id: attackLogs.length + 1,
//       ip: normalizeIP(req.ip),
//       attackType: 'File Upload Vulnerability',
//       action: 'Blocked',
//       fileName: file.originalname,
//     });

//     fs.unlinkSync(file.path); // Delete the malicious file
//     return res.status(403).send('Malicious file detected and blocked.');
//   }

//   res.status(200).send('File uploaded successfully.');
// });

// Function to normalize IP addresses
function normalizeIP(ip) {
  if (ip === '::1') return '127.0.0.1'; // Normalize localhost IPv6 to IPv4
  if (ip.includes('::ffff:')) return ip.split('::ffff:')[1]; // Normalize IPv4-mapped IPv6
  return ip;
}

// const externalRateLimiter = rateLimit({
//   windowMs: 60 * 1000, // 1 minute
//   max: 5, // Allow only 5 requests per minute
//   message: 'Too many requests, please try again later.',
//   handler: function (req, res) {
//     // Log as a potential DDoS attack
//     attackLogs.push({
//       id: attackLogs.length + 1,
//       ip: normalizeIP(req.ip),
//       attackType: 'DDoS',
//       action: 'Attacker redirected to Honeypot',
//     });
//     // res.status(429).send('Too many requests, please try again later.');
//     res.redirect('/honeypot');
//   }
// });

// --------------
// const externalRateLimiter = rateLimit({
//   windowMs: 60 * 1000, // 1 minute
//   max: 3, // Allow only 5 requests per minute
//   message: 'Too many requests, please try again later.',
//   handler: function (req, res) {
//     // Log as a potential DDoS attack
//     attackLogs.push({
//       id: attackLogs.length + 1,
//       ip: normalizeIP(req.ip),
//       attackType: 'DDoS',
//       action: 'Attacker redirected to Honeypot',
//     });
//     // res.status(429).send('Too many requests, please try again later.');
//     res.redirect('/honeypot');
//   }
// });

const externalRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 6, // Allow only 3 requests per minute
  message: 'Too many requests, please try again later.',
  handler: function (req, res) {
    // Check if this IP is already logged for DDoS
    const alreadyLogged = attackLogs.some(log => 
      log.ip === normalizeIP(req.ip) && log.attackType === 'DDoS'
    );

    // Only log if this is the first time
    if (!alreadyLogged) {
      attackLogs.push({
        id: attackLogs.length + 1,
        ip: normalizeIP(req.ip),
        attackType: 'DDoS',
        action: 'Blocked (Rate Limit Exceeded)',
        entryTimestamp: new Date().toISOString(),
      });
    }

    // Return 429 instead of redirecting (to prevent loops)
    //res.status(429).send('Too many requests, please try again later.');
    res.redirect('/honeypot');
  }
});

// Middleware to apply rate limit for external IPs
function applyRateLimitForExternalIPs(req, res, next) {
  const localIP = '127.0.0.1';
  if (normalizeIP(req.ip) !== localIP) {
    // Apply external rate limiter
    externalRateLimiter(req, res, next);
  } else {
    next();
  }
}

app.use(applyRateLimitForExternalIPs);




// Middleware for Suspicious IP Monitoring
const blockedIPs = ['192.168.1.3']; // Example blocked IPs
function monitorSuspiciousIPs(req, res, next) {
  if (blockedIPs.includes(normalizeIP(req.ip))) {
    attackLogs.push({
      id: attackLogs.length + 1,
      ip: normalizeIP(req.ip),
      attackType: 'Suspicious IP Monitoring',
      action: 'Blocked',
    });
    return res.status(403).send('Access denied: suspicious IP detected.');
  }
  next();
}

// Middleware to apply rate limit for external IPs
function applyRateLimitForExternalIPs(req, res, next) {
  const localIP = '127.0.0.1';
  if (normalizeIP(req.ip) !== localIP) {
    // Apply external rate limiter
    externalRateLimiter(req, res, next);
  } else {
    next();
  }
}

// Rate Limiting for Login (Brute Force Protection)
const loginRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minutes
  max: 3, // Allow 3 login attempts
  message: 'Too many login attempts, please try again later.',
  handler: function (req, res) {
    attackLogs.push({
      id: attackLogs.length + 1,
      ip: normalizeIP(req.ip),
      attackType: 'Brute Force',
      action: 'Redirected to Honeypot',
      entryTimestamp: new Date().toISOString(),
      exitTimestamp: 0,
      duration: 0
    });
    res.redirect('/honeypot');
  },
});


// XSS Detection middleware
function detectXSS(req, res, next) {
  const suspiciousPatterns = [
    // Script tags
    '<script', '</script>', '<ScRiPt>', '</ScRiPt>', '<SCRIPT>', '</SCRIPT>',
    
    // JavaScript URLs
    'javascript:', 'javascript%3A', 'javascript%3a', 'vbscript:', 'data:text/html',
    
    // Event handlers
    'onload=', 'onerror=', 'onclick=', 'onmouseover=', 'onfocus=', 'onblur=', 
    'onchange=', 'onsubmit=', 'onkeydown=', 'onkeyup=', 'onkeypress=', 
    'onresize=', 'onunload=', 'onbeforeunload=', 'oncontextmenu=', 'ondblclick=', 
    'onmousedown=', 'onmouseup=', 'onmousemove=', 'onmouseout=', 'onmouseenter=',
    'onmouseleave=', 'onscroll=', 'onwheel=', 'oninput=', 'oninvalid=',
    'onreset=', 'onselect=', 'onabort=', 'oncanplay=', 'oncanplaythrough=',
    'ondurationchange=', 'onemptied=', 'onended=', 'onloadeddata=',
    'onloadedmetadata=', 'onloadstart=', 'onpause=', 'onplay=', 'onplaying=',
    'onprogress=', 'onratechange=', 'onseeked=', 'onseeking=', 'onstalled=',
    'onsuspend=', 'ontimeupdate=', 'onvolumechange=', 'onwaiting=',
    
    // Dangerous functions
    'alert(', 'confirm(', 'prompt(', 'document.cookie', 'document.write',
    'window.location', 'eval(', 'setTimeout(', 'setInterval(', 'Function(',
    'setImmediate(', 'requestAnimationFrame(',
    
    // DOM manipulation
    'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write',
    'document.writeln', 'document.open', 'document.close',
    
    // Filter evasion techniques
    'String.fromCharCode', 'unescape(', 'decodeURIComponent(', 'atob(',
    'eval(', 'new Function(', 'setTimeout(', 'setInterval(',
    
    // HTML entities and encoding
    '&#x3C;', '&#60;', '&lt;', '&gt;', '&#x3E;', '&#62;',
    
    // SVG and other vectors
    '<svg', '<iframe', '<object', '<embed', '<applet', '<meta',
    '<link', '<style', '<form', '<input', '<textarea', '<select',
    '<option', '<button', '<a href=', '<img', '<video', '<audio',
    
    // Advanced techniques
    'expression(', 'url(', 'import(', 'namespace', 'binding',
    'behavior', '-moz-binding', '-webkit-binding',
    
    // Cookie and session stealing
    'document.cookie', 'sessionStorage', 'localStorage', 'fetch(',
    'XMLHttpRequest', '$.ajax', '$.post', '$.get',
    
    // Redirects and navigation
    'window.location', 'location.href', 'location.replace', 'location.assign',
    'history.pushState', 'history.replaceState', 'history.back', 'history.forward',
    
    // File and network access
    'FileReader', 'Blob', 'URL.createObjectURL', 'navigator.sendBeacon',
    'WebSocket', 'EventSource', 'Worker', 'SharedWorker', 'ServiceWorker'
  ];

  // Check all form data (body)
  const bodyValues = Object.values(req.body || {});
  for (let value of bodyValues) {
    if (typeof value === 'string' && suspiciousPatterns.some((pattern) => 
      value.toLowerCase().includes(pattern.toLowerCase())
    )) {
      attackLogs.push({
        id: attackLogs.length + 1,
        ip: normalizeIP(req.ip),
        attackType: 'XSS Attack',
        action: 'Redirected to Honeypot',
        payload: value.substring(0, 100), // Log first 100 chars of payload
        entryTimestamp: new Date().toISOString(),
        exitTimestamp: 0,
        duration: 0
      });
      
      console.log(`XSS Attack detected from IP: ${normalizeIP(req.ip)}, Payload: ${value.substring(0, 50)}...`);
      return res.redirect('/honeypot');
    }
  }

  // Check query parameters
  const queryValues = Object.values(req.query || {});
  for (let value of queryValues) {
    if (typeof value === 'string' && suspiciousPatterns.some((pattern) => 
      value.toLowerCase().includes(pattern.toLowerCase())
    )) {
      attackLogs.push({
        id: attackLogs.length + 1,
        ip: normalizeIP(req.ip),
        attackType: 'XSS Attack (Query)',
        action: 'Redirected to Honeypot',
        payload: value.substring(0, 100),
        entryTimestamp: new Date().toISOString(),
        exitTimestamp: 0,
        duration: 0
      });
      
      console.log(`XSS Attack detected in query from IP: ${normalizeIP(req.ip)}, Payload: ${value.substring(0, 50)}...`);
      return res.redirect('/honeypot');
    }
  }

  next();
}

// Updated SQL injection detection middleware
function detectSQLInjection(req, res, next) {
  const suspiciousPatterns = ['--', ';', 'DROP', 'SELECT', 'INSERT', 'DELETE', 'UPDATE', 'OR 1=1', "' OR '1'='1"];
  const values = Object.values(req.body);

  for (let value of values) {
    if (typeof value === 'string' && 
        suspiciousPatterns.some(pattern => 
          value.toUpperCase().includes(pattern.toUpperCase()))) {
      
      attackLogs.push({
        id: attackLogs.length + 1,
        ip: normalizeIP(req.ip),
        attackType: 'SQL Injection',
        action: 'Redirected to Honeypot',
      });
      // End the request chain here if SQL injection is detected
      return res.redirect('/honeypot');
    }
  }
  // Only call next() if no SQL injection was found
  next();
}

// Middleware to detect SQL Injection
// function detectSQLInjection(req, res, next) {
//   const suspiciousPatterns = ['--', ';', 'DROP', 'SELECT', 'INSERT', 'DELETE', 'UPDATE', 'OR 1=1', "' OR '1'='1"];
//   const values = Object.values(req.body);

//   for (let value of values) {
//     if (suspiciousPatterns.some((pattern) => value.toUpperCase().includes(pattern.toUpperCase()))) {
//       attackLogs.push({
//         id: attackLogs.length + 1,
//         ip: normalizeIP(req.ip),
//         attackType: 'SQL Injection',
//         action: 'Blocked',
//       });
//       // return res.status(403).send('SQL Injection attempt detected.');
//       res.redirect('/honeypot');
//     }
//   }
//   next();
// }


// Updated login route handler
app.post('/login', detectXSS, detectSQLInjection, loginRateLimiter,  (req, res) => {
  const { email, password } = req.body;

  db.get('SELECT * FROM login WHERE email = ? AND password = ?', 
    [email, password], 
    (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).send('Database error');
      }
      if (user) {
        req.session.userId = user.id;
        return res.sendFile(path.join(__dirname, 'views', 'user-dashboard.html'));
      }
      return res.status(401).send('Invalid credentials');
  });
});

// Apply middleware globally
app.use(monitorSuspiciousIPs);
//app.use(detectHeaderAnomalies);

// Routes
app.get('/', (req, res) => {
  console.log('Client IP:', normalizeIP(req.ip));
  // res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'views', 'HomePage.html'));
});

// XSS Test Page
app.get('/xss-test', detectXSS, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'xss-test.html'));
});

// Advanced XSS Test Page
app.get('/advanced-xss-test', detectXSS, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'advanced-xss-test.html'));
});

// Admin logout
app.get('/admin-login/logout', (req, res) => {
  req.session.destroy(() => {
      res.redirect('/');
  });
});

// Static admin credentials
const ADMIN_EMAIL = 'admin@gmail.com';
const ADMIN_PASSWORD = '123456';

// Admin login route (POST)
app.post('/admin-login', detectXSS, (req, res) => {
    const { email, password } = req.body;
    console.log('Admin Login Attempt:', { email, password });

    // if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
    //     // res.redirect('/admin'); // Redirect to admin dashboard
    //     res.sendFile(path.join(__dirname, 'views', 'admin-dashboard.html'));
    // } else {
    //     res.send('<script>alert("Invalid credentials!"); window.location="/admin-login.html";</script>');
    // }

    db.get('SELECT * FROM login WHERE email = ? AND password = ?', [email, password], (err, admin) => {
      if (err) {
          return res.status(500).send('Database error');
      }
      if (admin && admin.email === 'admin@gmail.com') {
          req.session.adminId = admin.id;
          res.sendFile(path.join(__dirname, 'views', 'admin-dashboard.html'));
      } else {
          res.send('<script>alert("Invalid credentials!"); window.location="/admin-login.html";</script>');
      }
  });
});

app.get('/admin', (req, res) => {
  //  res.sendFile(path.join(__dirname, 'views', 'admin-dashboard.html'));
  // res.sendFile(path.join(__dirname, 'views', 'HomePage.html'));
  res.sendFile(path.join(__dirname, 'views', 'admin-login.html'));
});

app.get('/admin/users', (req, res) => {
  res.json(users);
});

app.get('/admin/attack-logs', (req, res) => {
  res.json(attackLogs);
});

// XSS Test Form Handler
app.post('/xss-test', detectXSS, (req, res) => {
  // If XSS is detected, user will be redirected to honeypot by middleware
  // If no XSS detected, show success message
  res.send(`
    <html>
      <body style="font-family: Arial; padding: 50px; text-align: center; background: #f0f8ff;">
        <h2 style="color: #28a745;">✅ No XSS Attack Detected</h2>
        <p>Your input was clean! Try entering some XSS payloads to test the detection.</p>
        <a href="/xss-test" style="color: #007bff;">← Back to XSS Test Page</a>
      </body>
    </html>
  `);
});

// Reflected XSS Test
app.get('/reflected-xss', detectXSS, (req, res) => {
  const query = req.query.q || '';
  res.send(`
    <html>
      <body style="font-family: Arial; padding: 50px; text-align: center; background: #f0f8ff;">
        <h2>Search Results for: ${query}</h2>
        <p>No results found for "${query}"</p>
        <a href="/advanced-xss-test" style="color: #007bff;">← Back to Advanced XSS Test</a>
      </body>
    </html>
  `);
});

// Stored XSS Test
app.post('/stored-xss', detectXSS, (req, res) => {
  const { comment, username } = req.body;
  res.send(`
    <html>
      <body style="font-family: Arial; padding: 50px; text-align: center; background: #f0f8ff;">
        <h2>Comment Posted Successfully!</h2>
        <p><strong>Username:</strong> ${username}</p>
        <p><strong>Comment:</strong> ${comment}</p>
        <a href="/advanced-xss-test" style="color: #007bff;">← Back to Advanced XSS Test</a>
      </body>
    </html>
  `);
});

// Cookie Test
app.post('/cookie-test', detectXSS, (req, res) => {
  const { payload } = req.body;
  res.send(`
    <html>
      <body style="font-family: Arial; padding: 50px; text-align: center; background: #f0f8ff;">
        <h2>Cookie Test Submitted!</h2>
        <p>Payload: ${payload}</p>
        <a href="/advanced-xss-test" style="color: #007bff;">← Back to Advanced XSS Test</a>
      </body>
    </html>
  `);
});

// Filter Evasion Test
app.post('/filter-evasion', detectXSS, (req, res) => {
  const { payload } = req.body;
  res.send(`
    <html>
      <body style="font-family: Arial; padding: 50px; text-align: center; background: #f0f8ff;">
        <h2>Filter Evasion Test Submitted!</h2>
        <p>Payload: ${payload}</p>
        <a href="/advanced-xss-test" style="color: #007bff;">← Back to Advanced XSS Test</a>
      </body>
    </html>
  `);
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'user-login.html'));
});

// app.post('/login', loginRateLimiter, detectSQLInjection, applyRateLimitForExternalIPs, (req, res) => {
//   const { email, password } = req.body;

//   // const user = users.find((u) => u.email === email && u.password === password);
//   // if (user) {
//   //   req.session.userId = user.id;
//   //   res.sendFile(path.join(__dirname, 'views', 'user-dashboard.html'));
//   // } else {
//   //   res.status(401).send('Invalid credentials');
//   // }

//   db.get('SELECT * FROM login WHERE email = ? AND password = ?', [email, password], (err, user) => {
//     if (err) {
//         return res.status(500).send('Database error');
//     }
//     if (user) {
//         req.session.userId = user.id;
//         res.sendFile(path.join(__dirname, 'views', 'user-dashboard.html'));
//     } else {
//         return res.status(401).send('Invalid credentials');
//     }
// });
// });

app.get('/honeypot', (req, res) => {
  req.session.honeypotEntryTime = Date.now();
  res.sendFile(path.join(__dirname, 'views', 'honeypot.html'));
});

app.all('/honeypot-exit', (req, res) => {
  if (req.session.honeypotEntryTime) {
      const entryTime = req.session.honeypotEntryTime;
      // console.log(new Date(entryTime).toISOString());
      const exitTime = Date.now();
      const duration = (exitTime - entryTime) / 1000; // Convert to seconds

      const accessedFiles = req.session.accessedFiles || [];

      attackLogs.push({
          id: attackLogs.length + 1,
          ip: normalizeIP(req.ip),
          attackType: 'Honeypot Interaction',
          action: 'User visited Honeypot',
          accessedFiles: accessedFiles || "None", // Store the accessed files
          entryTimestamp: new Date(entryTime).toISOString(),
          exitTimestamp: new Date(exitTime).toISOString(),
          duration: duration.toFixed(2) + ' seconds'
      });

      delete req.session.honeypotEntryTime; // Clear session entry time
      delete req.session.accessedFiles; // Clear accessed files
      
  }

  res.redirect('/'); // Redirect to home or any desired page
});

app.post('/log-attack', (req, res) => {
  const { action, filename, timestamp } = req.body;
  // console.log(`Attack Log: ${action} - ${filename} at ${timestamp}`);
  // res.sendStatus(200);

    // Ensure session is initialized
    if (!req.session.accessedFiles) {
      req.session.accessedFiles = [];
  }

  // Store accessed file in session
  req.session.accessedFiles.push(filename);

  console.log(`Attack Log: ${action} - ${filename} at ${timestamp}`);
  res.sendStatus(200);
});

// Cookie stealing endpoint (for XSS demonstration)
app.get('/steal', (req, res) => {
  const { cookie } = req.query;
  console.log(`🍪 Cookie Stolen via XSS: ${cookie}`);
  console.log(`📍 From IP: ${normalizeIP(req.ip)}`);
  console.log(`🕐 Time: ${new Date().toISOString()}`);
  
  // Log this as a cookie theft attempt
  attackLogs.push({
    id: attackLogs.length + 1,
    ip: normalizeIP(req.ip),
    attackType: 'Cookie Theft via XSS',
    action: 'Cookie Stolen',
    payload: `Cookie: ${cookie}`,
    entryTimestamp: new Date().toISOString(),
    exitTimestamp: 0,
    duration: 0
  });
  
  // Return a fake success response to the attacker
  res.send('OK');
});


app.get('/user/dashboard', (req, res) => {
  if (req.session.userId) {
    res.send('<h1>Welcome to your Dashboard!</h1>');
  } else {
    res.redirect('/login');
  }
});

// app.post('/logout', (req, res) => {
//   req.session.destroy((err) => {
//     if (err) return res.status(500).send('Logout failed');
//     res.status(200).send('Logout successful');
//   });
// });

app.post('/logout', (req, res) => {
  // Do not destroy the session
  res.redirect('back'); // sends the user back to the previous page
});

function normalizeIP(ip) {
  if (ip === '::1') return '127.0.0.1'; // Normalize localhost IPv6 to IPv4
  if (ip.includes('::ffff:')) return ip.split('::ffff:')[1]; // Normalize IPv4-mapped IPv6
  return ip;
}


// Server Listen
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
