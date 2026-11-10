const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 5e7 // 50MB buffer limit
});

const PORT = process.env.PORT || 3000;

// Master Admin Credentials (set in environment or use defaults)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "masteradmin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "AdminSecret@123";

// Ensure storage directories exist
const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const USERS_FILE = path.join(dataDir, 'users.json');
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}

function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Multer Storage for Photos & Videos (Up to 50MB)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp|mp4|webm|mov|mkv/;
    const ext = path.extname(file.originalname).toLowerCase().slice(1);
    const mime = file.mimetype.toLowerCase();
    if (allowed.test(ext) || mime.startsWith('image/') || mime.startsWith('video/')) {
      return cb(null, true);
    }
    cb(new Error("Only photo and video files are permitted!"));
  }
});

// Middleware
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'super_secret_chat_key_991',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 24 hours
});

app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));

// Socket.io Session sharing
io.engine.use(sessionMiddleware);

// --- Auth Routes ---

// Login (Handles both Admin and Regular Users)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Check Admin
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.user = { username: ADMIN_USERNAME, role: 'admin' };
    return res.json({ success: true, role: 'admin', username: ADMIN_USERNAME });
  }

  // Check User
  const users = loadUsers();
  const found = users.find(u => u.username === username);
  if (found && bcrypt.compareSync(password, found.password)) {
    req.session.user = { username: found.username, role: 'user' };
    return res.json({ success: true, role: 'user', username: found.username });
  }

  res.status(401).json({ error: "Invalid credentials" });
});

// Current session status
app.get('/api/me', (req, res) => {
  if (req.session.user) {
    return res.json({ loggedIn: true, user: req.session.user });
  }
  res.json({ loggedIn: false });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// --- Admin Only Routes ---

function requireAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') {
    return next();
  }
  res.status(403).json({ error: "Forbidden: Admin access only" });
}

// Get user list
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = loadUsers().map(u => ({ username: u.username, createdAt: u.createdAt }));
  res.json(users);
});

// Create new user (Admin only)
app.post('/api/admin/create-user', requireAdmin, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const users = loadUsers();
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase()) || username === ADMIN_USERNAME) {
    return res.status(400).json({ error: "Username already exists" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  users.push({
    username,
    password: hashedPassword,
    createdAt: new Date().toISOString()
  });

  saveUsers(users);
  res.json({ success: true, message: `User '${username}' created successfully!` });
});

// Delete user (Admin only)
app.post('/api/admin/delete-user', requireAdmin, (req, res) => {
  const { username } = req.body;
  let users = loadUsers();
  users = users.filter(u => u.username !== username);
  saveUsers(users);
  res.json({ success: true });
});

// --- Media Upload (Up to 50MB) ---
app.post('/api/upload', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  upload.single('media')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const isVideo = req.file.mimetype.startsWith('video');
    res.json({
      url: `/uploads/${req.file.filename}`,
      type: isVideo ? 'video' : 'photo',
      name: req.file.originalname
    });
  });
});

// --- Socket.IO Realtime Group Chat ---
io.on('connection', (socket) => {
  const sessionData = socket.request.session;
  if (!sessionData || !sessionData.user) {
    socket.disconnect();
    return;
  }

  // Handle incoming group messages
  socket.on('chat_message', (data) => {
    io.emit('new_message', {
      sender: sessionData.user.username,
      role: sessionData.user.role,
      text: data.text || '',
      mediaUrl: data.mediaUrl || null,
      mediaType: data.mediaType || null,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    });
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});