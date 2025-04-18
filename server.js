require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const redis = require('redis');
const { promisify } = require('util');
const rateLimit = require('express-rate-limit');
const socketioRateLimit = require('socketio-rate-limit');
const winston = require('winston');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGIN,
    methods: ["GET", "POST"]
  }
});

// Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Redis clients
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT
});
const getAsync = promisify(redisClient.get).bind(redisClient);
const setAsync = promisify(redisClient.set).bind(redisClient);

// Socket.IO Redis adapter
const { RedisAdapter } = require('socket.io-redis');
io.adapter(RedisAdapter({
  pubClient: redis.createClient({ host: process.env.REDIS_HOST }),
  subClient: redis.createClient({ host: process.env.REDIS_HOST })
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // Limit per IP
});
app.use('/admin/login', limiter);

// Express routes
app.post('/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const [admins] = await pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    
    if (!admins.length) {
      logger.warn('Failed login attempt', { username });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const admin = admins[0];
    const valid = await bcrypt.compare(password, admin.password_hash);
    
    if (!valid) {
      logger.warn('Invalid password', { username });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ adminId: admin.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    logger.info('Admin login successful', { adminId: admin.id });
    res.json({ token });
  } catch (err) {
    logger.error('Login error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Socket.IO authentication middleware
const authenticateAdmin = async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error'));
    
    const decoded = await jwt.verify(token, process.env.JWT_SECRET);
    const [admins] = await pool.query('SELECT * FROM admins WHERE id = ?', [decoded.adminId]);
    
    if (!admins.length) return next(new Error('Invalid admin'));
    
    socket.admin = admins[0];
    next();
  } catch (err) {
    logger.error('Socket auth error', err);
    next(new Error('Authentication failed'));
  }
};

// Socket.IO connection
io.use(socketioRateLimit({
  window: 5000,
  max: 10,
  onRateLimit: (socket) => {
    logger.warn('Rate limit exceeded', { socketId: socket.id });
    socket.emit('error', 'Rate limit exceeded');
    socket.disconnect();
  }
}));

io.use((socket, next) => {
  authenticateAdmin(socket, (err) => {
    if (err) {
      socket.disconnect();
      return next(err);
    }
    next();
  });
});

io.on('connection', (socket) => {
  logger.info('Admin connected', { adminId: socket.admin.id });
  
  // Admin joins the global admin room
  socket.join('admins');
  
  // Forward session to another admin
  socket.on('forward session', async (sessionId, targetAdminId) => {
    try {
      const [sessions] = await pool.query('SELECT * FROM sessions WHERE id = ?', [sessionId]);
      if (!sessions.length) return;
      
      const session = sessions[0];
      await pool.query('UPDATE sessions SET admin_id = ? WHERE id = ?', [targetAdminId, sessionId]);
      
      // Notify target admin
      const targetSocketId = await getAsync(`admin:${targetAdminId}`);
      if (targetSocketId) {
        io.to(targetSocketId).emit('join session', sessionId);
        logger.info('Session forwarded', { sessionId, targetAdminId });
      }
    } catch (err) {
      logger.error('Forward session error', err);
    }
  });
  
  // Handle chat messages
  socket.on('chat message', async (sessionId, message) => {
    try {
      await pool.query('INSERT INTO messages (content, session_id, sender) VALUES (?, ?, ?)', [
        message,
        sessionId,
        'admin'
      ]);
      io.to(`session-${sessionId}`).emit('chat message', message, 'admin');
    } catch (err) {
      logger.error('Message save error', err);
    }
  });
  
  // Admin disconnects
  socket.on('disconnect', () => {
    logger.info('Admin disconnected', { adminId: socket.admin.id });
  });
});

// User-facing Socket.IO namespace
const userIo = io.of('/user');
userIo.on('connection', (socket) => {
  socket.on('start chat', async (userId) => {
    try {
      const [result] = await pool.query('INSERT INTO sessions (user_id) VALUES (?)', [userId]);
      const sessionId = result.insertId;
      socket.join(`session-${sessionId}`);
      socket.emit('session started', sessionId);
    } catch (err) {
      logger.error('Session start error', err);
    }
  });

  socket.on('chat message', async (sessionId, message) => {
    try {
      await pool.query('INSERT INTO messages (content, session_id, sender) VALUES (?, ?, ?)', [
        message,
        sessionId,
        'user'
      ]);
      io.to(`session-${sessionId}`).emit('chat message', message, 'user');
    } catch (err) {
      logger.error('Message save error', err);
    }
  });
});

// Error handling
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason, promise });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
