import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';
import {
  getDatabase,
  saveDatabase,
  logAudit,
  ProductItem,
  ReelItem,
  MediaItem
} from './src/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const isProd = process.env.NODE_ENV === 'production';

// Body parsers
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(cookieParser());

// Static uploads directory
const UPLOADS_DIR = path.join(process.cwd(), 'public', 'uploads');
const UPLOADS_IMAGES_DIR = path.join(UPLOADS_DIR, 'images');
const UPLOADS_VIDEOS_DIR = path.join(UPLOADS_DIR, 'videos');

[UPLOADS_DIR, UPLOADS_IMAGES_DIR, UPLOADS_VIDEOS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Serve uploads directly
app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/public/uploads', express.static(UPLOADS_DIR));

// Configure Multer for Images
const imageStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOADS_IMAGES_DIR);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const cleanName = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '_');
    const unique = `${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    cb(null, `${cleanName}_${unique}${ext}`);
  }
});

const uploadImages = multer({
  storage: imageStorage,
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB
  fileFilter: (_req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid image type. Allowed: JPG, JPEG, PNG, WEBP'));
    }
  }
});

// Configure Multer for Videos
const videoStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOADS_VIDEOS_DIR);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const cleanName = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '_');
    const unique = `${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    cb(null, `${cleanName}_${unique}${ext}`);
  }
});

const uploadVideos = multer({
  storage: videoStorage,
  limits: { fileSize: 200 * 1024 * 1024 }, // 200MB
  fileFilter: (_req, file, cb) => {
    const allowed = ['.mp4', '.webm'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid video type. Allowed: MP4, WEBM'));
    }
  }
});

// ============================================================================
// AUTHENTICATION & ACCESS CONTROL MIDDLEWARE
// ============================================================================
function getClientIp(req: Request): string {
  return (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';
}

function verifyAdminSession(req: Request): boolean {
  const authHeader = req.headers.authorization;
  const tokenFromHeader = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
  const tokenFromCookie = req.cookies?.kyorp_admin_session;
  const token = tokenFromHeader || tokenFromCookie;

  if (!token) return false;

  const db = getDatabase();
  const session = db.admin.sessions.find(s => s.token === token);
  if (!session) return false;

  const now = new Date();
  const expiresAt = new Date(session.expiresAt);
  if (now > expiresAt) {
    // Session expired, cleanup
    db.admin.sessions = db.admin.sessions.filter(s => s.token !== token);
    saveDatabase(db);
    return false;
  }

  return true;
}

function requireAdminAuth(req: Request, res: Response, next: NextFunction) {
  if (verifyAdminSession(req)) {
    return next();
  }
  return res.status(401).json({
    success: false,
    error: 'Unauthorized: Valid administrator session required.'
  });
}

// ============================================================================
// PUBLIC STOREFRONT APIS (FOR REAL-TIME WEBSITE UPDATES)
// ============================================================================
app.get('/api/content', (_req: Request, res: Response) => {
  const db = getDatabase();
  // Return live content with Cache-Control no-cache to avoid stale states
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.json({
    success: true,
    timestamp: new Date().toISOString(),
    settings: db.settings,
    reels: db.reels.filter(r => r.status === 'active'),
    categories: db.categories,
    products: db.products
  });
});

app.get('/api/products', (_req: Request, res: Response) => {
  const db = getDatabase();
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.json({ success: true, products: db.products });
});

app.get('/api/reels', (_req: Request, res: Response) => {
  const db = getDatabase();
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.json({ success: true, reels: db.reels });
});

app.get('/api/settings', (_req: Request, res: Response) => {
  const db = getDatabase();
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.json({ success: true, settings: db.settings });
});

// ============================================================================
// ADMIN AUTHENTICATION ROUTES
// ============================================================================
app.post('/api/admin/login', (req: Request, res: Response) => {
  const { password } = req.body;
  const ip = getClientIp(req);

  if (!password) {
    return res.status(400).json({ success: false, error: 'Password is required' });
  }

  const db = getDatabase();
  const isValid = bcrypt.compareSync(password, db.admin.passwordHash);

  if (!isValid) {
    logAudit('LOGIN_FAILED', 'Failed admin login attempt', ip);
    return res.status(401).json({ success: false, error: 'Invalid administrator password' });
  }

  // Generate secure cryptographic session token
  const token = crypto.randomBytes(32).toString('hex');
  const durationHours = db.admin.sessionDurationHours || 24;
  const expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000).toISOString();

  // Clean expired sessions and add new
  const now = new Date();
  db.admin.sessions = db.admin.sessions.filter(s => new Date(s.expiresAt) > now);
  db.admin.sessions.push({
    token,
    createdAt: new Date().toISOString(),
    expiresAt,
    userAgent: req.headers['user-agent'] || 'Unknown'
  });

  saveDatabase(db);
  logAudit('LOGIN_SUCCESS', 'Administrator logged in', ip);

  res.cookie('kyorp_admin_session', token, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    maxAge: durationHours * 60 * 60 * 1000
  });

  return res.json({
    success: true,
    token,
    expiresAt,
    message: 'Authentication successful'
  });
});

app.get('/api/admin/auth-check', (req: Request, res: Response) => {
  const isAuthenticated = verifyAdminSession(req);
  return res.json({ success: true, isAuthenticated });
});

app.post('/api/admin/logout', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const tokenFromHeader = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
  const token = tokenFromHeader || req.cookies?.kyorp_admin_session;

  if (token) {
    const db = getDatabase();
    db.admin.sessions = db.admin.sessions.filter(s => s.token !== token);
    saveDatabase(db);
    logAudit('LOGOUT', 'Administrator logged out', getClientIp(req));
  }

  res.clearCookie('kyorp_admin_session');
  return res.json({ success: true, message: 'Logged out successfully' });
});

app.post('/api/admin/change-password', requireAdminAuth, (req: Request, res: Response) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ success: false, error: 'Current and new passwords are required' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ success: false, error: 'New password must be at least 8 characters long' });
  }

  const db = getDatabase();
  const matches = bcrypt.compareSync(currentPassword, db.admin.passwordHash);
  if (!matches) {
    return res.status(400).json({ success: false, error: 'Current password is incorrect' });
  }

  const salt = bcrypt.genSaltSync(10);
  db.admin.passwordHash = bcrypt.hashSync(newPassword, salt);
  saveDatabase(db);
  logAudit('PASSWORD_CHANGED', 'Administrator password updated successfully', getClientIp(req));

  return res.json({ success: true, message: 'Password updated successfully' });
});

app.post('/api/admin/reset-password', (req: Request, res: Response) => {
  const { recoveryCode, newPassword } = req.body;
  if (!recoveryCode || !newPassword) {
    return res.status(400).json({ success: false, error: 'Recovery code and new password are required' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ success: false, error: 'New password must be at least 8 characters' });
  }

  const db = getDatabase();
  const codeValid = bcrypt.compareSync(recoveryCode.trim(), db.admin.recoveryCodeHash);
  if (!codeValid) {
    logAudit('RECOVERY_FAILED', 'Invalid recovery code attempt', getClientIp(req));
    return res.status(400).json({ success: false, error: 'Invalid recovery code' });
  }

  const salt = bcrypt.genSaltSync(10);
  db.admin.passwordHash = bcrypt.hashSync(newPassword, salt);
  // Invalidate all active sessions for security
  db.admin.sessions = [];
  saveDatabase(db);
  logAudit('PASSWORD_RESET', 'Administrator password reset via verified recovery code', getClientIp(req));

  return res.json({ success: true, message: 'Password has been successfully reset. Please log in with your new password.' });
});

// ============================================================================
// ADMIN DASHBOARD OVERVIEW METRICS
// ============================================================================
app.get('/api/admin/overview', requireAdminAuth, (_req: Request, res: Response) => {
  const db = getDatabase();

  const totalProducts = db.products.length;
  const activeProducts = db.products.filter(p => p.status === 'live' && p.inStock !== false).length;
  const outOfStockProducts = db.products.filter(p => p.inStock === false).length;
  const developmentProducts = db.products.filter(p => p.status === 'development').length;
  const totalImages = db.images.length;
  const totalVideos = db.videos.length;
  const totalReels = db.reels.length;

  // Calculate disk storage
  let storageBytes = 0;
  const calculateDirSize = (dirPath: string) => {
    if (fs.existsSync(dirPath)) {
      const files = fs.readdirSync(dirPath);
      files.forEach(f => {
        const full = path.join(dirPath, f);
        const stat = fs.statSync(full);
        if (stat.isFile()) storageBytes += stat.size;
      });
    }
  };
  calculateDirSize(UPLOADS_IMAGES_DIR);
  calculateDirSize(UPLOADS_VIDEOS_DIR);

  res.json({
    success: true,
    metrics: {
      totalProducts,
      activeProducts,
      outOfStockProducts,
      developmentProducts,
      totalImages,
      totalVideos,
      totalReels,
      storageBytes,
      storageFormatted: `${(storageBytes / (1024 * 1024)).toFixed(2)} MB`,
      googleSheets: db.googleSheets,
      recentUpdates: db.products.slice(0, 5),
      recentLogs: db.auditLogs.slice(0, 8)
    }
  });
});

// ============================================================================
// ADMIN PRODUCT MANAGEMENT ROUTES
// ============================================================================
app.get('/api/admin/products', requireAdminAuth, (req: Request, res: Response) => {
  const db = getDatabase();
  const { search, category, status } = req.query;

  let list = [...db.products];

  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    list = list.filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.sku.toLowerCase().includes(q) ||
      p.formulation.toLowerCase().includes(q)
    );
  }

  if (category && typeof category === 'string' && category !== 'all') {
    list = list.filter(p => p.divisionId === category);
  }

  if (status && typeof status === 'string' && status !== 'all') {
    list = list.filter(p => p.status === status);
  }

  res.json({ success: true, count: list.length, products: list });
});

app.post('/api/admin/products', requireAdminAuth, (req: Request, res: Response) => {
  const db = getDatabase();
  const { name, formulation, description, divisionId, type, priceINR, sellingPriceINR, originalPriceINR, status, inStock, featured, imageUrl, videoUrl } = req.body;
  const effectivePrice = priceINR !== undefined ? priceINR : sellingPriceINR;

  if (!name || !divisionId || effectivePrice === undefined) {
    return res.status(400).json({ success: false, error: 'Name, division, and price are required.' });
  }

  const div = db.categories.find(c => c.id === divisionId) || db.categories[0];
  const maxSkuNum = db.products.reduce((max, p) => Math.max(max, p.skuNum || 0), 429);
  const newSkuNum = maxSkuNum + 1;
  const newSku = String(newSkuNum).padStart(3, '0');

  const discountPct = originalPriceINR && originalPriceINR > effectivePrice
    ? Math.round(((originalPriceINR - effectivePrice) / originalPriceINR) * 100)
    : undefined;

  const newProduct: ProductItem = {
    sku: newSku,
    skuNum: newSkuNum,
    name: name.trim(),
    formulation: (formulation || description || 'Master botanical formulation.').trim(),
    divisionId: div.id,
    divisionName: div.name,
    type: type || 'treatment',
    status: status || 'live',
    priceINR: Number(effectivePrice),
    originalPriceINR: originalPriceINR ? Number(originalPriceINR) : undefined,
    discountPct,
    inStock: inStock !== false,
    featured: !!featured,
    imageUrl: imageUrl || undefined,
    videoUrl: videoUrl || undefined,
    tone: div.tone,
    lastUpdated: new Date().toISOString()
  };

  db.products.unshift(newProduct);
  saveDatabase(db);
  logAudit('PRODUCT_CREATED', `Added new formulation SKU ${newSku} - ${newProduct.name}`, getClientIp(req));

  return res.json({ success: true, product: newProduct });
});

app.put('/api/admin/products/:sku', requireAdminAuth, (req: Request, res: Response) => {
  const { sku } = req.params;
  const db = getDatabase();
  const index = db.products.findIndex(p => p.sku === sku);

  if (index === -1) {
    return res.status(404).json({ success: false, error: `Product with SKU ${sku} not found.` });
  }

  const p = db.products[index];
  const {
    name,
    formulation,
    description,
    divisionId,
    type,
    priceINR,
    sellingPriceINR,
    originalPriceINR,
    discountPercent,
    status,
    inStock,
    featured,
    imageUrl,
    videoUrl
  } = req.body;

  if (name) p.name = name.trim();
  const descVal = formulation !== undefined ? formulation : description;
  if (descVal !== undefined) p.formulation = descVal.trim();
  if (divisionId) {
    const div = db.categories.find(c => c.id === divisionId);
    if (div) {
      p.divisionId = div.id;
      p.divisionName = div.name;
      p.tone = div.tone;
    }
  }
  if (type) p.type = type;
  const effectivePrice = priceINR !== undefined ? priceINR : sellingPriceINR;
  if (effectivePrice !== undefined) p.priceINR = Number(effectivePrice);
  if (originalPriceINR !== undefined) {
    p.originalPriceINR = originalPriceINR ? Number(originalPriceINR) : undefined;
    p.discountPct = p.originalPriceINR && p.originalPriceINR > p.priceINR
      ? Math.round(((p.originalPriceINR - p.priceINR) / p.originalPriceINR) * 100)
      : (discountPercent !== undefined ? discountPercent : undefined);
  }
  if (status) p.status = status;
  if (inStock !== undefined) p.inStock = inStock;
  if (featured !== undefined) p.featured = featured;
  if (imageUrl !== undefined) p.imageUrl = imageUrl;
  if (videoUrl !== undefined) p.videoUrl = videoUrl;
  p.lastUpdated = new Date().toISOString();

  saveDatabase(db);
  logAudit('PRODUCT_UPDATED', `Updated product SKU ${sku} (${p.name})`, getClientIp(req));

  return res.json({ success: true, product: p });
});

app.delete('/api/admin/products/:sku', requireAdminAuth, (req: Request, res: Response) => {
  const { sku } = req.params;
  const db = getDatabase();
  const prod = db.products.find(p => p.sku === sku);

  if (!prod) {
    return res.status(404).json({ success: false, error: `Product SKU ${sku} not found.` });
  }

  db.products = db.products.filter(p => p.sku !== sku);
  saveDatabase(db);
  logAudit('PRODUCT_DELETED', `Deleted product SKU ${sku} (${prod.name})`, getClientIp(req));

  return res.json({ success: true, message: `Product ${sku} removed.` });
});

// Fast batch price updates
const handleBatchPrices = (req: Request, res: Response) => {
  const { updates } = req.body;
  if (!Array.isArray(updates)) {
    return res.status(400).json({ success: false, error: 'Updates array required.' });
  }

  const db = getDatabase();
  let updatedCount = 0;

  updates.forEach(u => {
    const p = db.products.find(x => x.sku === u.sku);
    if (p) {
      const sellPrice = u.sellingPriceINR !== undefined ? u.sellingPriceINR : u.priceINR;
      if (sellPrice !== undefined) p.priceINR = Number(sellPrice);
      if (u.originalPriceINR !== undefined) {
        p.originalPriceINR = u.originalPriceINR ? Number(u.originalPriceINR) : undefined;
        p.discountPct = p.originalPriceINR && p.originalPriceINR > p.priceINR
          ? Math.round(((p.originalPriceINR - p.priceINR) / p.originalPriceINR) * 100)
          : (u.discountPercent !== undefined ? u.discountPercent : undefined);
      }
      if (u.inStock !== undefined) p.inStock = !!u.inStock;
      p.lastUpdated = new Date().toISOString();
      updatedCount++;
    }
  });

  saveDatabase(db);
  logAudit('BATCH_PRICE_UPDATE', `Batch price updated for ${updatedCount} products`, getClientIp(req));

  return res.json({ success: true, updatedCount });
};

app.patch('/api/admin/products/batch-prices', requireAdminAuth, handleBatchPrices);
app.put('/api/admin/products/batch-prices', requireAdminAuth, handleBatchPrices);

// ============================================================================
// ADMIN MEDIA MANAGEMENT (IMAGES & VIDEOS)
// ============================================================================
app.post('/api/admin/upload-image', requireAdminAuth, uploadImages.any(), (req: Request, res: Response) => {
  const files = req.files as Express.Multer.File[];
  if (!files || files.length === 0) {
    return res.status(400).json({ success: false, error: 'No image files uploaded.' });
  }

  const db = getDatabase();
  const uploadedItems: MediaItem[] = [];

  files.forEach(file => {
    const item: MediaItem = {
      id: `img-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      type: 'image',
      originalName: file.originalname,
      fileName: file.filename,
      url: `/uploads/images/${file.filename}`,
      sizeBytes: file.size,
      mimeType: file.mimetype,
      title: path.basename(file.originalname, path.extname(file.originalname)),
      assignedProductSku: req.body.assignedProductSku || undefined,
      assignedDivisionId: req.body.assignedDivisionId || undefined,
      uploadedAt: new Date().toISOString()
    };
    db.images.unshift(item);
    uploadedItems.push(item);
  });

  saveDatabase(db);
  logAudit('IMAGES_UPLOADED', `Uploaded ${files.length} image(s)`, getClientIp(req));

  return res.json({ success: true, count: uploadedItems.length, images: uploadedItems });
});

app.post('/api/admin/upload-video', requireAdminAuth, uploadVideos.single('video'), (req: Request, res: Response) => {
  const file = req.file;
  if (!file) {
    return res.status(400).json({ success: false, error: 'No video file uploaded.' });
  }

  const db = getDatabase();
  const videoItem: MediaItem = {
    id: `vid-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    type: 'video',
    originalName: file.originalname,
    fileName: file.filename,
    url: `/uploads/videos/${file.filename}`,
    sizeBytes: file.size,
    mimeType: file.mimetype,
    title: req.body.title || path.basename(file.originalname, path.extname(file.originalname)),
    assignedProductSku: req.body.assignedProductSku || undefined,
    assignedDivisionId: req.body.assignedDivisionId || undefined,
    uploadedAt: new Date().toISOString()
  };

  db.videos.unshift(videoItem);
  saveDatabase(db);
  logAudit('VIDEO_UPLOADED', `Uploaded video: ${videoItem.originalName}`, getClientIp(req));

  return res.json({ success: true, video: videoItem });
});

app.get('/api/admin/media', requireAdminAuth, (_req: Request, res: Response) => {
  const db = getDatabase();
  return res.json({
    success: true,
    images: db.images,
    videos: db.videos
  });
});

app.put('/api/admin/media/:id', requireAdminAuth, (req: Request, res: Response) => {
  const { id } = req.params;
  const { title, assignedProductSku, assignedDivisionId } = req.body;
  const db = getDatabase();

  let found = false;
  const img = db.images.find(m => m.id === id);
  if (img) {
    if (title) img.title = title;
    img.assignedProductSku = assignedProductSku || undefined;
    img.assignedDivisionId = assignedDivisionId || undefined;
    found = true;
  }

  const vid = db.videos.find(m => m.id === id);
  if (vid) {
    if (title) vid.title = title;
    vid.assignedProductSku = assignedProductSku || undefined;
    vid.assignedDivisionId = assignedDivisionId || undefined;
    found = true;
  }

  if (!found) {
    return res.status(404).json({ success: false, error: 'Media not found' });
  }

  saveDatabase(db);
  return res.json({ success: true, message: 'Media metadata updated.' });
});

app.delete('/api/admin/media/:id', requireAdminAuth, (req: Request, res: Response) => {
  const { id } = req.params;
  const db = getDatabase();

  const img = db.images.find(m => m.id === id);
  if (img) {
    // Delete file from disk
    const filePath = path.join(UPLOADS_IMAGES_DIR, img.fileName);
    if (fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch (e) { console.error('Disk delete error:', e); }
    }
    db.images = db.images.filter(m => m.id !== id);
    saveDatabase(db);
    logAudit('IMAGE_DELETED', `Deleted image: ${img.originalName}`, getClientIp(req));
    return res.json({ success: true, message: 'Image deleted permanently.' });
  }

  const vid = db.videos.find(m => m.id === id);
  if (vid) {
    const filePath = path.join(UPLOADS_VIDEOS_DIR, vid.fileName);
    if (fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch (e) { console.error('Disk delete error:', e); }
    }
    db.videos = db.videos.filter(m => m.id !== id);
    saveDatabase(db);
    logAudit('VIDEO_DELETED', `Deleted video: ${vid.originalName}`, getClientIp(req));
    return res.json({ success: true, message: 'Video deleted permanently.' });
  }

  return res.status(404).json({ success: false, error: 'Media item not found' });
});

// ============================================================================
// ADMIN REELS MANAGEMENT
// ============================================================================
app.get('/api/admin/reels', requireAdminAuth, (_req: Request, res: Response) => {
  const db = getDatabase();
  res.json({ success: true, reels: db.reels });
});

app.put('/api/admin/reels/:id', requireAdminAuth, (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  const db = getDatabase();
  const reel = db.reels.find(r => r.id === id);

  if (!reel) {
    return res.status(404).json({ success: false, error: `Reel ${id} not found.` });
  }

  const { title, desc, tagline, videoUrl, posterUrl, divisionId, status } = req.body;

  if (title) reel.title = title.trim();
  if (desc) reel.desc = desc.trim();
  if (tagline) reel.tagline = tagline.trim();
  if (videoUrl) reel.videoUrl = videoUrl.trim();
  if (posterUrl) reel.posterUrl = posterUrl.trim();
  if (divisionId) reel.divisionId = divisionId;
  if (status) reel.status = status;
  reel.lastUpdated = new Date().toISOString();

  saveDatabase(db);
  logAudit('REEL_UPDATED', `Updated Reel ${id}: ${reel.title}`, getClientIp(req));

  return res.json({ success: true, reel });
});

// ============================================================================
// ADMIN CATEGORIES MANAGEMENT
// ============================================================================
app.get('/api/admin/categories', requireAdminAuth, (_req: Request, res: Response) => {
  const db = getDatabase();
  res.json({ success: true, categories: db.categories });
});

app.put('/api/admin/categories/:id', requireAdminAuth, (req: Request, res: Response) => {
  const { id } = req.params;
  const db = getDatabase();
  const cat = db.categories.find(c => c.id === id);

  if (!cat) {
    return res.status(404).json({ success: false, error: `Category ${id} not found.` });
  }

  const { name, desc, status, minPrice, maxPrice } = req.body;
  if (name) cat.name = name.trim();
  if (desc) cat.desc = desc.trim();
  if (status) cat.status = status;
  if (minPrice !== undefined) cat.minPrice = Number(minPrice);
  if (maxPrice !== undefined) cat.maxPrice = Number(maxPrice);

  saveDatabase(db);
  logAudit('CATEGORY_UPDATED', `Updated division: ${cat.name}`, getClientIp(req));

  return res.json({ success: true, category: cat });
});

// ============================================================================
// ADMIN WEBSITE SETTINGS
// ============================================================================
app.get('/api/admin/settings', requireAdminAuth, (_req: Request, res: Response) => {
  const db = getDatabase();
  res.json({ success: true, settings: db.settings });
});

app.put('/api/admin/settings', requireAdminAuth, (req: Request, res: Response) => {
  const db = getDatabase();
  const {
    announcementText,
    announcementActive,
    heroHeadline,
    heroSub,
    heroVideoUrl,
    freeShippingThresholdINR,
    flatShippingINR
  } = req.body;

  if (announcementText !== undefined) db.settings.announcementText = announcementText.trim();
  if (announcementActive !== undefined) db.settings.announcementActive = !!announcementActive;
  if (heroHeadline !== undefined) db.settings.heroHeadline = heroHeadline.trim();
  if (heroSub !== undefined) db.settings.heroSub = heroSub.trim();
  if (heroVideoUrl !== undefined) db.settings.heroVideoUrl = heroVideoUrl.trim();
  if (freeShippingThresholdINR !== undefined) db.settings.freeShippingThresholdINR = Number(freeShippingThresholdINR);
  if (flatShippingINR !== undefined) db.settings.flatShippingINR = Number(flatShippingINR);
  db.settings.lastUpdated = new Date().toISOString();

  saveDatabase(db);
  logAudit('SETTINGS_UPDATED', 'Website configuration settings updated', getClientIp(req));

  return res.json({ success: true, settings: db.settings });
});

// ============================================================================
// GOOGLE SHEETS INTEGRATION & SYNC
// ============================================================================
app.get('/api/admin/sheets/status', requireAdminAuth, (_req: Request, res: Response) => {
  const db = getDatabase();
  res.json({ success: true, config: db.googleSheets });
});

app.post('/api/admin/sheets/config', requireAdminAuth, (req: Request, res: Response) => {
  const db = getDatabase();
  const { sheetUrl, webhookUrl, autoSync } = req.body;

  if (sheetUrl !== undefined) {
    db.googleSheets.sheetUrl = sheetUrl.trim();
    // Extract sheet ID if full Google Sheets URL provided
    const match = sheetUrl.match(/\/d\/([a-zA-Z0-9-_]+)/);
    if (match) db.googleSheets.sheetId = match[1];
  }
  if (webhookUrl !== undefined) db.googleSheets.webhookUrl = webhookUrl.trim();
  if (autoSync !== undefined) db.googleSheets.autoSync = !!autoSync;

  saveDatabase(db);
  logAudit('SHEETS_CONFIG_UPDATED', 'Google Sheets connection parameters updated', getClientIp(req));

  return res.json({ success: true, config: db.googleSheets });
});

// Export catalog as CSV matching the exact 11 columns required by the user:
// | Product ID | Product Name | Category | Description | Original Price | Selling Price | Discount | Image URL | Video URL | Status | Last Updated |
app.get('/api/admin/sheets/export-csv', requireAdminAuth, (_req: Request, res: Response) => {
  const db = getDatabase();

  const headers = [
    'Product ID',
    'Product Name',
    'Category',
    'Description',
    'Original Price',
    'Selling Price',
    'Discount',
    'Image URL',
    'Video URL',
    'Status',
    'Last Updated'
  ];

  const escapeCsv = (str: any) => {
    if (str === null || str === undefined) return '""';
    const s = String(str).replace(/"/g, '""');
    return `"${s}"`;
  };

  const rows = db.products.map(p => [
    escapeCsv(p.sku),
    escapeCsv(p.name),
    escapeCsv(p.divisionName),
    escapeCsv(p.formulation),
    escapeCsv(p.originalPriceINR || p.priceINR),
    escapeCsv(p.priceINR),
    escapeCsv(p.discountPct ? `${p.discountPct}%` : '0%'),
    escapeCsv(p.imageUrl || ''),
    escapeCsv(p.videoUrl || ''),
    escapeCsv(p.status === 'live' ? (p.inStock === false ? 'Out of Stock' : 'Active') : 'In Development'),
    escapeCsv(p.lastUpdated || '')
  ].join(','));

  const csvContent = [headers.join(','), ...rows].join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="kyorp_products_catalog.csv"');
  return res.send(csvContent);
});

// Sync database with Google Sheets via Webhook or direct payload
app.post('/api/admin/sheets/sync', requireAdminAuth, async (req: Request, res: Response) => {
  const db = getDatabase();
  const webhookUrl = db.googleSheets.webhookUrl || req.body.webhookUrl;

  const payload = {
    action: 'SYNC_PRODUCTS',
    timestamp: new Date().toISOString(),
    columns: [
      'Product ID',
      'Product Name',
      'Category',
      'Description',
      'Original Price',
      'Selling Price',
      'Discount',
      'Image URL',
      'Video URL',
      'Status',
      'Last Updated'
    ],
    products: db.products.map(p => ({
      productId: p.sku,
      productName: p.name,
      category: p.divisionName,
      description: p.formulation,
      originalPrice: p.originalPriceINR || p.priceINR,
      sellingPrice: p.priceINR,
      discount: p.discountPct ? `${p.discountPct}%` : '0%',
      imageUrl: p.imageUrl || '',
      videoUrl: p.videoUrl || '',
      status: p.status === 'live' ? (p.inStock === false ? 'Out of Stock' : 'Active') : 'In Development',
      lastUpdated: p.lastUpdated || ''
    }))
  };

  if (!webhookUrl) {
    db.googleSheets.syncStatus = 'idle';
    db.googleSheets.syncMessage = 'CSV export ready. Enter Google Apps Script Webhook URL for direct automated syncing.';
    db.googleSheets.lastSyncedAt = new Date().toISOString();
    saveDatabase(db);
    return res.json({
      success: true,
      mode: 'csv_ready',
      message: 'Product catalog formatted with 11 columns ready for Google Sheets import.',
      data: payload
    });
  }

  try {
    const fetchRes = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (fetchRes.ok) {
      db.googleSheets.syncStatus = 'success';
      db.googleSheets.syncMessage = `Synchronized ${db.products.length} products with Google Sheets.`;
      db.googleSheets.lastSyncedAt = new Date().toISOString();
      saveDatabase(db);
      logAudit('SHEETS_SYNC_SUCCESS', `Synchronized ${db.products.length} products to Google Sheets`, getClientIp(req));
      return res.json({ success: true, message: db.googleSheets.syncMessage });
    } else {
      throw new Error(`Google Sheets Webhook returned HTTP ${fetchRes.status}`);
    }
  } catch (err: any) {
    db.googleSheets.syncStatus = 'failed';
    db.googleSheets.syncMessage = `Sync error: ${err.message}`;
    saveDatabase(db);
    logAudit('SHEETS_SYNC_FAILED', `Failed sync attempt: ${err.message}`, getClientIp(req));
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Audit logs
app.get('/api/admin/audit-logs', requireAdminAuth, (_req: Request, res: Response) => {
  const db = getDatabase();
  res.json({ success: true, logs: db.auditLogs });
});

// ============================================================================
// ADMIN PAGE ROUTE & FRONTEND INTEGRATION
// ============================================================================
// Explicit route for /admin to ensure clean access
app.get('/admin', (_req: Request, res: Response) => {
  res.sendFile(path.join(process.cwd(), 'index.html'));
});

// Setup Vite middleware in dev or static server in prod
async function startServer() {
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[KYORP Engine] Full-stack server running at http://localhost:${PORT}`);
    console.log(`[KYORP Engine] Private Admin Panel available at http://localhost:${PORT}/admin`);
  });
}

startServer();
