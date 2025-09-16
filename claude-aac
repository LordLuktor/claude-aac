#!/bin/bash

# Complete Communication Board Setup Script
# This script creates ALL files needed for the project

set -e

echo "🚀 Creating Complete Communication Board Project..."

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if we're in the right directory
if [ ! -d ".git" ]; then
    log_error "This should be run in your git repository directory!"
    log_info "First run: git clone git@github.com:LordLuktor/claude-aac.git"
    log_info "Then cd claude-aac and run this script"
    exit 1
fi

log_step "Creating project structure..."
mkdir -p public uploads/images uploads/audio data backups
touch uploads/.gitkeep uploads/images/.gitkeep uploads/audio/.gitkeep data/.gitkeep backups/.gitkeep

log_step "Creating package.json..."
cat > package.json << 'EOF'
{
  "name": "communication-board",
  "version": "1.0.0",
  "description": "Interactive Communication Board Web Application for steinmetz.ltd",
  "main": "app.js",
  "scripts": {
    "start": "node app.js",
    "dev": "nodemon app.js",
    "test": "echo \"Error: no test specified\" && exit 1",
    "docker:build": "docker build -t communication-board .",
    "docker:dev": "docker-compose -f docker-compose.yml -f docker-compose.override.yml up",
    "docker:prod": "docker stack deploy -c docker-compose.yml communication-board",
    "backup": "./deploy.sh backup",
    "deploy": "./deploy.sh deploy",
    "update": "./update.sh"
  },
  "dependencies": {
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "multer": "^1.4.5-lts.1",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "mysql2": "^3.6.0",
    "dotenv": "^16.3.1",
    "helmet": "^7.0.0",
    "cors": "^2.8.5",
    "compression": "^1.7.4",
    "express-rate-limit": "^6.10.0",
    "sanitize-html": "^2.11.0",
    "sharp": "^0.32.5",
    "uuid": "^9.0.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "keywords": [
    "communication",
    "accessibility",
    "assistive-technology",
    "aac",
    "steinmetz.ltd"
  ],
  "author": "LordLuktor",
  "license": "MIT"
}
EOF

log_step "Creating app.js..."
cat > app.js << 'EOF'
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const path = require('path');
const fs = require('fs').promises;
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const sharp = require('sharp');
const { v4: uuidv4 } = require('uuid');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "blob:"]
    }
  }
}));

app.use(compression());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
app.use(session({
  secret: process.env.JWT_SECRET || 'fallback-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Static files
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

// Database connection
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'communication_board',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = 'uploads/images';
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}-${Date.now()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, WebP, and GIF are allowed.'));
    }
  }
});

// Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.session.token || req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [users] = await pool.execute(
      'SELECT id, username, role, active FROM users WHERE id = ? AND active = 1',
      [decoded.userId]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = users[0];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const [users] = await pool.execute(
      'SELECT id, username, password, role FROM users WHERE username = ? AND active = 1',
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    req.session.token = token;
    req.session.user = { id: user.id, username: user.username, role: user.role };

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/auth/check', authenticate, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out successfully' });
});

// Communication board routes
app.get('/api/boards/:userId', authenticate, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // Check if user can access this board
    if (req.user.role !== 'admin' && req.user.id !== parseInt(userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const [pages] = await pool.execute(
      'SELECT * FROM pages WHERE user_id = ? ORDER BY sort_order',
      [userId]
    );

    const [buttons] = await pool.execute(`
      SELECT b.*, p.name as page_name 
      FROM buttons b 
      JOIN pages p ON b.page_id = p.id 
      WHERE p.user_id = ? 
      ORDER BY p.sort_order, b.sort_order
    `, [userId]);

    const boardData = pages.map(page => ({
      ...page,
      buttons: buttons.filter(btn => btn.page_id === page.id)
    }));

    res.json(boardData);
  } catch (error) {
    console.error('Get boards error:', error);
    res.status(500).json({ error: 'Failed to fetch boards' });
  }
});

// Button management routes
app.post('/api/buttons', authenticate, upload.single('image'), async (req, res) => {
  try {
    const { text, page_id, sort_order = 0 } = req.body;
    const imageUrl = req.file ? `/uploads/images/${req.file.filename}` : null;

    // Optimize image if uploaded
    if (req.file) {
      await sharp(req.file.path)
        .resize(200, 200, { fit: 'contain', background: { r: 255, g: 255, b: 255, alpha: 1 } })
        .jpeg({ quality: 85 })
        .toFile(req.file.path.replace(path.extname(req.file.path), '_optimized.jpg'));
    }

    const [result] = await pool.execute(
      'INSERT INTO buttons (text, image_url, page_id, sort_order) VALUES (?, ?, ?, ?)',
      [sanitizeHtml(text), imageUrl, page_id, sort_order]
    );

    res.json({ id: result.insertId, text, image_url: imageUrl, page_id, sort_order });
  } catch (error) {
    console.error('Create button error:', error);
    res.status(500).json({ error: 'Failed to create button' });
  }
});

app.put('/api/buttons/:id', authenticate, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;
    const { text, sort_order, page_id } = req.body;
    
    let imageUrl = null;
    if (req.file) {
      imageUrl = `/uploads/images/${req.file.filename}`;
      // Optimize new image
      await sharp(req.file.path)
        .resize(200, 200, { fit: 'contain', background: { r: 255, g: 255, b: 255, alpha: 1 } })
        .jpeg({ quality: 85 })
        .toFile(req.file.path.replace(path.extname(req.file.path), '_optimized.jpg'));
    }

    const updateFields = ['text = ?', 'sort_order = ?'];
    const updateValues = [sanitizeHtml(text), sort_order];
    
    if (imageUrl) {
      updateFields.push('image_url = ?');
      updateValues.push(imageUrl);
    }
    
    if (page_id) {
      updateFields.push('page_id = ?');
      updateValues.push(page_id);
    }
    
    updateValues.push(id);

    await pool.execute(
      `UPDATE buttons SET ${updateFields.join(', ')} WHERE id = ?`,
      updateValues
    );

    res.json({ message: 'Button updated successfully' });
  } catch (error) {
    console.error('Update button error:', error);
    res.status(500).json({ error: 'Failed to update button' });
  }
});

app.delete('/api/buttons/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get image URL to delete file
    const [buttons] = await pool.execute('SELECT image_url FROM buttons WHERE id = ?', [id]);
    
    await pool.execute('DELETE FROM buttons WHERE id = ?', [id]);
    
    // Delete image file if exists
    if (buttons.length > 0 && buttons[0].image_url) {
      try {
        await fs.unlink(`public${buttons[0].image_url}`);
      } catch (err) {
        console.warn('Could not delete image file:', err.message);
      }
    }

    res.json({ message: 'Button deleted successfully' });
  } catch (error) {
    console.error('Delete button error:', error);
    res.status(500).json({ error: 'Failed to delete button' });
  }
});

// Page management routes
app.post('/api/pages', authenticate, async (req, res) => {
  try {
    const { name, user_id, sort_order = 0 } = req.body;
    
    // Check permission
    if (req.user.role !== 'admin' && req.user.id !== parseInt(user_id)) {
      return res.status(403).json({ error: 'Permission denied' });
    }
    
    const [result] = await pool.execute(
      'INSERT INTO pages (name, user_id, sort_order) VALUES (?, ?, ?)',
      [sanitizeHtml(name), user_id, sort_order]
    );

    res.json({ id: result.insertId, name, user_id, sort_order });
  } catch (error) {
    console.error('Create page error:', error);
    res.status(500).json({ error: 'Failed to create page' });
  }
});

app.put('/api/pages/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, sort_order } = req.body;
    
    // Check permission
    const [pages] = await pool.execute('SELECT user_id FROM pages WHERE id = ?', [id]);
    if (pages.length === 0) {
      return res.status(404).json({ error: 'Page not found' });
    }
    
    if (req.user.role !== 'admin' && req.user.id !== pages[0].user_id) {
      return res.status(403).json({ error: 'Permission denied' });
    }
    
    const updateFields = [];
    const updateValues = [];
    
    if (name !== undefined) {
      updateFields.push('name = ?');
      updateValues.push(sanitizeHtml(name));
    }
    
    if (sort_order !== undefined) {
      updateFields.push('sort_order = ?');
      updateValues.push(sort_order);
    }
    
    updateValues.push(id);

    await pool.execute(
      `UPDATE pages SET ${updateFields.join(', ')} WHERE id = ?`,
      updateValues
    );

    res.json({ message: 'Page updated successfully' });
  } catch (error) {
    console.error('Update page error:', error);
    res.status(500).json({ error: 'Failed to update page' });
  }
});

app.delete('/api/pages/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check permission
    const [pages] = await pool.execute('SELECT user_id FROM pages WHERE id = ?', [id]);
    if (pages.length === 0) {
      return res.status(404).json({ error: 'Page not found' });
    }
    
    if (req.user.role !== 'admin' && req.user.id !== pages[0].user_id) {
      return res.status(403).json({ error: 'Permission denied' });
    }
    
    await pool.execute('DELETE FROM pages WHERE id = ?', [id]);

    res.json({ message: 'Page deleted successfully' });
  } catch (error) {
    console.error('Delete page error:', error);
    res.status(500).json({ error: 'Failed to delete page' });
  }
});

// Settings routes
app.get('/api/settings/:userId', authenticate, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // Check permission
    if (req.user.role !== 'admin' && req.user.id !== parseInt(userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const [settings] = await pool.execute(
      'SELECT * FROM user_settings WHERE user_id = ?',
      [userId]
    );

    if (settings.length === 0) {
      // Return default settings
      res.json({
        voice_enabled: true,
        voice_rate: 1.0,
        voice_pitch: 1.0,
        voice_volume: 1.0,
        button_size: 'medium',
        theme: 'default',
        auto_clear_sentence: false
      });
    } else {
      res.json(settings[0]);
    }
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/settings/:userId', authenticate, async (req, res) => {
  try {
    const userId = req.params.userId;
    const settings = req.body;
    
    // Check permission
    if (req.user.role !== 'admin' && req.user.id !== parseInt(userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Upsert settings
    await pool.execute(`
      INSERT INTO user_settings 
      (user_id, voice_enabled, voice_rate, voice_pitch, voice_volume, button_size, theme, auto_clear_sentence, settings_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
      voice_enabled = VALUES(voice_enabled),
      voice_rate = VALUES(voice_rate),
      voice_pitch = VALUES(voice_pitch),
      voice_volume = VALUES(voice_volume),
      button_size = VALUES(button_size),
      theme = VALUES(theme),
      auto_clear_sentence = VALUES(auto_clear_sentence),
      settings_json = VALUES(settings_json)
    `, [
      userId,
      settings.voice_enabled || true,
      settings.voice_rate || 1.0,
      settings.voice_pitch || 1.0,
      settings.voice_volume || 1.0,
      settings.button_size || 'medium',
      settings.theme || 'default',
      settings.auto_clear_sentence || false,
      JSON.stringify(settings)
    ]);

    res.json({ message: 'Settings saved successfully' });
  } catch (error) {
    console.error('Save settings error:', error);
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// Templates routes
app.get('/api/templates', authenticate, async (req, res) => {
  try {
    const [templates] = await pool.execute(`
      SELECT t.*, u.username as created_by_username 
      FROM templates t 
      LEFT JOIN users u ON t.created_by = u.id 
      WHERE t.is_public = 1 OR t.created_by = ?
      ORDER BY t.category, t.name
    `, [req.user.id]);

    res.json(templates);
  } catch (error) {
    console.error('Get templates error:', error);
    res.status(500).json({ error: 'Failed to fetch templates' });
  }
});

app.post('/api/templates', authenticate, requireRole(['admin']), async (req, res) => {
  try {
    const { name, description, template_data, category = 'general', is_public = false } = req.body;
    
    const [result] = await pool.execute(
      'INSERT INTO templates (name, description, template_data, category, created_by, is_public) VALUES (?, ?, ?, ?, ?, ?)',
      [name, description, JSON.stringify(template_data), category, req.user.id, is_public]
    );

    res.json({ id: result.insertId, name, description, category, is_public });
  } catch (error) {
    console.error('Create template error:', error);
    res.status(500).json({ error: 'Failed to create template' });
  }
});

app.post('/api/templates/:id/apply', authenticate, async (req, res) => {
  try {
    const templateId = req.params.id;
    
    const [templates] = await pool.execute('SELECT * FROM templates WHERE id = ?', [templateId]);
    if (templates.length === 0) {
      return res.status(404).json({ error: 'Template not found' });
    }
    
    const template = templates[0];
    const templateData = template.template_data;
    
    // Apply template to user's board
    for (const page of templateData.pages) {
      // Create page
      const [pageResult] = await pool.execute(
        'INSERT INTO pages (name, user_id, sort_order) VALUES (?, ?, ?)',
        [page.name, req.user.id, page.sort_order || 0]
      );
      
      const pageId = pageResult.insertId;
      
      // Create buttons for this page
      if (page.buttons) {
        for (const button of page.buttons) {
          await pool.execute(
            'INSERT INTO buttons (text, image_url, page_id, sort_order) VALUES (?, ?, ?, ?)',
            [button.text, button.image_url || null, pageId, button.sort_order || 0]
          );
        }
      }
    }

    res.json({ message: 'Template applied successfully' });
  } catch (error) {
    console.error('Apply template error:', error);
    res.status(500).json({ error: 'Failed to apply template' });
  }
});

// User management routes (admin only)
app.get('/api/users', authenticate, requireRole(['admin']), async (req, res) => {
  try {
    const [users] = await pool.execute(
      'SELECT id, username, role, active, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/users', authenticate, requireRole(['admin']), async (req, res) => {
  try {
    const { username, password, role = 'user' } = req.body;
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const [result] = await pool.execute(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, hashedPassword, role]
    );

    res.json({ id: result.insertId, username, role });
  } catch (error) {
    console.error('Create user error:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      res.status(500).json({ error: 'Failed to create user' });
    }
  }
});

// Serve the main application
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin', authenticate, requireRole(['admin']), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Error handling
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Communication Board app listening on port ${PORT}`);
});

module.exports = app;
EOF

log_step "Creating database schema (init.sql)..."
cat > init.sql << 'EOF'
-- Communication Board Database Schema

CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'guardian', 'user') DEFAULT 'user',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    user_id INT NOT NULL,
    sort_order INT DEFAULT 0,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_sort_order (sort_order)
);

CREATE TABLE IF NOT EXISTS buttons (
    id INT PRIMARY KEY AUTO_INCREMENT,
    text VARCHAR(255) NOT NULL,
    image_url VARCHAR(500),
    audio_url VARCHAR(500),
    page_id INT NOT NULL,
    sort_order INT DEFAULT 0,
    background_color VARCHAR(7) DEFAULT '#ffffff',
    text_color VARCHAR(7) DEFAULT '#000000',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE,
    INDEX idx_page_id (page_id),
    INDEX idx_sort_order (sort_order)
);

CREATE TABLE IF NOT EXISTS templates (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    template_data JSON NOT NULL,
    category VARCHAR(100) DEFAULT 'general',
    created_by INT,
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_category (category),
    INDEX idx_public (is_public)
);

CREATE TABLE IF NOT EXISTS user_settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT UNIQUE NOT NULL,
    voice_enabled BOOLEAN DEFAULT TRUE,
    voice_rate DECIMAL(3,2) DEFAULT 1.0,
    voice_pitch DECIMAL(3,2) DEFAULT 1.0,
    voice_volume DECIMAL(3,2) DEFAULT 1.0,
    theme VARCHAR(50) DEFAULT 'default',
    button_size VARCHAR(20) DEFAULT 'medium',
    auto_clear_sentence BOOLEAN DEFAULT FALSE,
    settings_json JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INT,
    details JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
);

-- Insert default admin user (password: admin123 - CHANGE THIS!)
INSERT INTO users (username, password, role) VALUES 
('admin', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyNiYOu7l7d7qC', 'admin');

-- Insert sample template data
INSERT INTO templates (name, description, template_data, category, created_by, is_public) VALUES 
('Basic Communication', 'Essential words for daily communication', 
'{"pages":[{"name":"Basics","buttons":[{"text":"Yes","image":"","sort_order":1},{"text":"No","image":"","sort_order":2},{"text":"Please","image":"","sort_order":3},{"text":"Thank you","image":"","sort_order":4},{"text":"Help","image":"","sort_order":5},{"text":"More","image":"","sort_order":6}]}]}', 
'communication', 1, TRUE),

('Emotions', 'Basic emotion words', 
'{"pages":[{"name":"Feelings","buttons":[{"text":"Happy","image":"","sort_order":1},{"text":"Sad","image":"","sort_order":2},{"text":"Angry","image":"","sort_order":3},{"text":"Excited","image":"","sort_order":4},{"text":"Tired","image":"","sort_order":5},{"text":"Hungry","image":"","sort_order":6}]}]}', 
'emotions', 1, TRUE),

('Food & Drinks', 'Common food and beverage items', 
'{"pages":[{"name":"Food","buttons":[{"text":"Water","image":"","sort_order":1},{"text":"Milk","image":"","sort_order":2},{"text":"Bread","image":"","sort_order":3},{"text":"Apple","image":"","sort_order":4},{"text":"Pizza","image":"","sort_order":5},{"text":"Cookie","image":"","sort_order":6}]}]}', 
'food', 1, TRUE);

-- Create indexes for better performance
CREATE INDEX idx_buttons_text ON buttons(text);
CREATE INDEX idx_pages_name ON pages(name);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_templates_name ON templates(name);
EOF

log_step "Creating Docker configuration..."
cat > Dockerfile << 'EOF'
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Create uploads directory
RUN mkdir -p uploads/images uploads/audio

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start the application
CMD ["npm", "start"]
EOF

log_step "Creating production docker-compose.yml..."
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  communication-board:
    build: .
    container_name: communication-board
    environment:
      - NODE_ENV=production
      - JWT_SECRET=a1b2c3d4e5f6789abcdef1234567890abcdef1234567890abcdef1234567890abcdef12
      - DB_HOST=db
      - DB_USER=commboard
      - DB_PASS=ApexWeb2025!
      - DB_NAME=communication_board
    volumes:
      - ./uploads:/app/uploads
      - ./data:/app/data
    depends_on:
      - db
    networks:
      - traefik-network
      - internal
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.aacsteinmetz.rule=Host(`www.aac.steinmetz.ltd`) || Host(`aac.steinmetz.ltd`)"
      - "traefik.http.routers.aacsteinmetz.tls=true"
      - "traefik.http.routers.aacsteinmetz.tls.certresolver=letsencrypt"
      - "traefik.http.services.aacsteinmetz.loadbalancer.server.port=3000"
      - "traefik.http.middlewares.aac-www-redirect.redirectregex.regex=^https://www.aac.steinmetz.ltd/(.*)"
      - "traefik.http.middlewares.aac-www-redirect.redirectregex.replacement=https://aac.steinmetz.ltd/${1}"
      - "traefik.http.routers.aacsteinmetz.middlewares=aac-www-redirect"

  db:
    image: mysql:8.0
    container_name: communication-board-db
    environment:
      - MYSQL_ROOT_PASSWORD=LionsTigers2025*
      - MYSQL_DATABASE=communication_board
      - MYSQL_USER=commboard
      - MYSQL_PASSWORD=ApexWeb2025!
    volumes:
      - db_data:/var/lib/mysql
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - internal
    restart: unless-stopped

volumes:
  db_data:

networks:
  traefik-network:
    external: true
  internal:
    driver: bridge
EOF

log_step "Creating development override..."
cat > docker-compose.override.yml << 'EOF'
# Development overrides for docker-compose.yml
# Use with: docker-compose -f docker-compose.yml -f docker-compose.override.yml up

version: '3.8'

services:
  communication-board:
    environment:
      - NODE_ENV=development
      - JWT_SECRET=dev-secret-key-not-for-production
      - DB_PASS=ApexWeb2025!
    volumes:
      - .:/app
      - /app/node_modules
    ports:
      - "3000:3000"
    command: npm run dev

  db:
    ports:
      - "3306:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=LionsTigers2025*
      - MYSQL_PASSWORD=ApexWeb2025!
EOF

log_step "Creating environment files..."
cat > .env.example << 'EOF'
# Copy this to .env and update with your values

# Database Configuration
DB_HOST=db
DB_USER=commboard
DB_PASS=ApexWeb2025!
DB_NAME=communication_board
MYSQL_ROOT_PASSWORD=LionsTigers2025*

# Application Configuration
JWT_SECRET=a1b2c3d4e5f6789abcdef1234567890abcdef1234567890abcdef1234567890abcdef12
NODE_ENV=production

# Domain Configuration
DOMAIN=aac.steinmetz.ltd
EOF

cat > .env << 'EOF'
# Production Configuration for steinmetz.ltd

# Database Configuration
DB_HOST=db
DB_USER=commboard
DB_PASS=ApexWeb2025!
DB_NAME=communication_board
MYSQL_ROOT_PASSWORD=LionsTigers2025*

# Application Configuration
JWT_SECRET=a1b2c3d4e5f6789abcdef1234567890abcdef1234567890abcdef1234567890abcdef12
NODE_ENV=production

# Domain Configuration
DOMAIN=aac.steinmetz.ltd
EOF

log_step "Creating .gitignore..."
cat > .gitignore << 'EOF'
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.production
.env.development

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Logs
logs
*.log

# Coverage directory used by tools like istanbul
coverage/
*.lcov

# nyc test coverage
.nyc_output

# Docker
.docker/

# Database
*.sql
*.db

# Uploads (but keep the directory structure)
uploads/*
!uploads/.gitkeep
!uploads/images/.gitkeep
!uploads/audio/.gitkeep

# Data directory
data/*
!data/.gitkeep

# Backups
backups/*
!backups/.gitkeep

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Temporary files
*.tmp
*.temp

# Build outputs
dist/
build/
EOF

log_step "Creating deployment scripts..."
cat > deploy.sh << 'EOF'
#!/bin/bash

# Communication Board Deployment Script
set -e

echo "🚀 Starting deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
STACK_NAME="communication-board"
COMPOSE_FILE="docker-compose.yml"
BACKUP_DIR="./backups"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker Swarm is initialized
check_swarm() {
    if ! docker info --format '{{.Swarm.LocalNodeState}}' | grep -q "active"; then
        log_error "Docker Swarm is not initialized!"
        echo "Run: docker swarm init"
        exit 1
    fi
    log_info "Docker Swarm is active"
}

# Create backup
create_backup() {
    log_info "Creating backup..."
    mkdir -p $BACKUP_DIR
    
    # Backup database
    if docker service ls | grep -q "${STACK_NAME}_db"; then
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        docker exec $(docker ps -q -f name=${STACK_NAME}_db) mysqldump -u root -pLionsTigers2025\* communication_board > $BACKUP_DIR/db_backup_$TIMESTAMP.sql 2>/dev/null || log_warn "Database backup failed (service may be starting)"
    fi
    
    # Backup uploads
    if [ -d "uploads" ]; then
        tar -czf $BACKUP_DIR/uploads_backup_$TIMESTAMP.tar.gz uploads/ || log_warn "Uploads backup failed"
    fi
    
    log_info "Backup completed"
}

# Deploy the stack
deploy_stack() {
    log_info "Deploying Docker stack..."
    
    # Check if compose file exists
    if [ ! -f "$COMPOSE_FILE" ]; then
        log_error "docker-compose.yml not found!"
        exit 1
    fi
    
    # Deploy the stack
    docker stack deploy -c $COMPOSE_FILE $STACK_NAME
    
    log_info "Stack deployed successfully"
}

# Wait for services to be ready
wait_for_services() {
    log_info "Waiting for services to start..."
    
    # Wait for services to be running
    timeout=300 # 5 minutes
    elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        running_services=$(docker service ls --filter name=${STACK_NAME} --format "table {{.Replicas}}" | grep -c "1/1" || echo "0")
        total_services=$(docker service ls --filter name=${STACK_NAME} --quiet | wc -l)
        
        if [ "$running_services" -eq "$total_services" ] && [ "$total_services" -gt 0 ]; then
            log_info "All services are running!"
            break
        fi
        
        echo "Services starting... ($running_services/$total_services ready)"
        sleep 10
        elapsed=$((elapsed + 10))
    done
    
    if [ $elapsed -ge $timeout ]; then
        log_warn "Timeout waiting for services to start"
    fi
}

# Show service status
show_status() {
    log_info "Service Status:"
    docker service ls --filter name=${STACK_NAME}
    
    echo ""
    log_info "Service Logs (last 10 lines):"
    docker service logs --tail 10 ${STACK_NAME}_communication-board 2>/dev/null || log_warn "Could not fetch logs"
}

# Main deployment flow
main() {
    echo "Communication Board Deployment"
    echo "=============================="
    
    # Parse command line arguments
    case "${1:-deploy}" in
        "backup")
            create_backup
            ;;
        "deploy")
            check_swarm
            create_backup
            deploy_stack
            wait_for_services
            show_status
            log_info "Deployment completed! 🎉"
            echo "Access at: https://aac.steinmetz.ltd"
            ;;
        "status")
            show_status
            ;;
        "logs")
            docker service logs -f ${STACK_NAME}_communication-board
            ;;
        "remove")
            log_warn "Removing stack..."
            docker stack rm $STACK_NAME
            log_info "Stack removed"
            ;;
        *)
            echo "Usage: $0 {deploy|backup|status|logs|remove}"
            echo ""
            echo "Commands:"
            echo "  deploy  - Deploy the application (default)"
            echo "  backup  - Create backup only"
            echo "  status  - Show service status"
            echo "  logs    - Show live logs"
            echo "  remove  - Remove the stack"
            exit 1
            ;;
    esac
}

main "$@"
EOF

cat > update.sh << 'EOF'
#!/bin/bash

# Communication Board Update Script
set -e

echo "🔄 Updating Communication Board from GitHub..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
STACK_NAME="communication-board"
BRANCH="${1:-main}"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if git repository
check_git() {
    if [ ! -d ".git" ]; then
        log_error "Not a git repository!"
        exit 1
    fi
}

# Backup current version
backup_current() {
    log_step "Creating backup of current version..."
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    mkdir -p "./backups"
    
    # Backup uploads and data
    if [ -d "uploads" ]; then
        tar -czf "./backups/uploads_pre_update_$TIMESTAMP.tar.gz" uploads/
    fi
    
    if [ -d "data" ]; then
        tar -czf "./backups/data_pre_update_$TIMESTAMP.tar.gz" data/
    fi
    
    log_info "Backup completed"
}

# Pull latest changes
pull_updates() {
    log_step "Pulling latest changes from GitHub..."
    
    # Stash any local changes
    if ! git diff-index --quiet HEAD --; then
        log_warn "Local changes detected, stashing..."
        git stash push -m "Auto-stash before update $(date)"
    fi
    
    # Pull latest changes
    git fetch origin
    git checkout $BRANCH
    git pull origin $BRANCH
    
    log_info "Code updated to latest version"
}

# Redeploy services
redeploy_services() {
    log_step "Redeploying services..."
    
    # Use the deployment script
    if [ -f "./deploy.sh" ]; then
        chmod +x ./deploy.sh
        ./deploy.sh deploy
    else
        log_warn "deploy.sh not found, deploying manually..."
        docker stack deploy -c docker-compose.yml $STACK_NAME
    fi
}

# Main update flow
main() {
    echo "Communication Board Update"
    echo "========================="
    echo "Branch: $BRANCH"
    echo ""
    
    check_git
    backup_current
    pull_updates
    redeploy_services
    
    echo ""
    log_info "Update completed successfully! 🎉"
    log_info "Access at: https://aac.steinmetz.ltd"
}

main "$@"
EOF

chmod +x deploy.sh update.sh

log_step "Creating frontend files..."

# This is where we'll create the HTML files - but the script is getting long
# Let me break this into a simpler approach

log_info "✅ Core backend and configuration files created!"
echo ""
echo "🎯 What's been created:"
echo "   ✅ app.js - Complete Node.js backend"
echo "   ✅ package.json - Dependencies and scripts"
echo "   ✅ init.sql - Database schema with sample data"
echo "   ✅ Dockerfile - Container configuration"
echo "   ✅ docker-compose.yml - Production deployment (steinmetz.ltd)"
echo "   ✅ docker-compose.override.yml - Development configuration"
echo "   ✅ .env - Environment with your passwords"
echo "   ✅ .gitignore - Git ignore rules"
echo "   ✅ deploy.sh - Deployment automation"
echo "   ✅ update.sh - Update automation"
echo ""
log_warn "📄 Still needed: Frontend HTML files"
echo "   - public/index.html (communication board)"
echo "   - public/dashboard.html (user-friendly dashboard)"
echo "   - public/admin.html (admin panel)"
echo ""
echo "📋 Next steps:"
echo "1. Copy the HTML files from the artifacts I provided earlier"
echo "2. Place them in the public/ directory"
echo "3. Run: git add . && git commit -m 'Complete Communication Board setup'"
echo "4. Run: git push"
echo "5. Deploy: ./deploy.sh deploy"
echo ""
log_info "🌐 Your app will be at: https://aac.steinmetz.ltd"
log_warn "🔐 Default login: admin / admin123 (CHANGE IMMEDIATELY!)"
EOF

chmod +x complete-setup.sh
