import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';

const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const UPLOADS_DIR = path.join(process.cwd(), 'public', 'uploads');
const UPLOADS_IMAGES_DIR = path.join(UPLOADS_DIR, 'images');
const UPLOADS_VIDEOS_DIR = path.join(UPLOADS_DIR, 'videos');

// Ensure directories exist
[DATA_DIR, UPLOADS_DIR, UPLOADS_IMAGES_DIR, UPLOADS_VIDEOS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

export interface ProductItem {
  sku: string;
  skuNum: number;
  name: string;
  formulation: string;
  divisionId: string;
  divisionName: string;
  type: string;
  status: 'live' | 'development';
  priceINR: number;
  originalPriceINR?: number;
  discountPct?: number;
  imageUrl?: string;
  videoUrl?: string;
  inStock?: boolean;
  featured?: boolean;
  tone?: string;
  lastUpdated?: string;
}

export interface ReelItem {
  id: number;
  title: string;
  desc: string;
  tagline: string;
  badge: string;
  videoUrl: string;
  posterUrl: string;
  divisionId: string;
  status: 'active' | 'disabled';
  lastUpdated?: string;
}

export interface MediaItem {
  id: string;
  type: 'image' | 'video';
  originalName: string;
  fileName: string;
  url: string;
  sizeBytes: number;
  mimeType: string;
  assignedProductSku?: string;
  assignedDivisionId?: string;
  title?: string;
  uploadedAt: string;
}

export interface SiteSettings {
  announcementText: string;
  announcementActive: boolean;
  heroHeadline: string;
  heroSub: string;
  heroVideoUrl: string;
  freeShippingThresholdINR: number;
  flatShippingINR: number;
  lastUpdated: string;
}

export interface GoogleSheetsConfig {
  sheetUrl: string;
  sheetId: string;
  webhookUrl: string;
  lastSyncedAt: string;
  syncStatus: 'idle' | 'success' | 'failed' | 'pending';
  syncMessage: string;
  autoSync: boolean;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  action: string;
  details: string;
  ip?: string;
}

export interface AdminSession {
  token: string;
  createdAt: string;
  expiresAt: string;
  userAgent?: string;
}

export interface DatabaseSchema {
  admin: {
    passwordHash: string;
    recoveryCodeHash: string;
    sessions: AdminSession[];
    sessionDurationHours: number;
  };
  settings: SiteSettings;
  reels: ReelItem[];
  images: MediaItem[];
  videos: MediaItem[];
  products: ProductItem[];
  categories: {
    id: string;
    num: string;
    name: string;
    range: string;
    count: number;
    status: string;
    desc: string;
    minPrice: number;
    maxPrice: number;
    tone: string;
  }[];
  googleSheets: GoogleSheetsConfig;
  auditLogs: AuditLog[];
}

// Initial divisions metadata
const INITIAL_DIVISIONS = [
  { id: "skin-science", num: "01", name: "Skin Science", range: "001–076", count: 76, status: "live", desc: "Treatment serums, barrier repair, cleansers, toners, essences, face masks, and facial oils.", minPrice: 899, maxPrice: 3499, tone: "#1B2A22" },
  { id: "body-science", num: "02", name: "Body Science", range: "077–100", count: 24, status: "live", desc: "Radiance body wash, polishing scrubs, rich body butters, dry oils, and syndet bars.", minPrice: 399, maxPrice: 1499, tone: "#7B5E3C" },
  { id: "hair-science", num: "03", name: "Hair Science", range: "101–118", count: 18, status: "live", desc: "Hair strengthening oils, deep repair shampoos, scalp growth serums, and masks.", minPrice: 499, maxPrice: 1999, tone: "#2D3E35" },
  { id: "beauty", num: "04", name: "KYORP Beauty", range: "119–158", count: 40, status: "live", desc: "Complexion skin tints, mineral foundations, cream blush, kajal, lip balms, and satin lipsticks.", minPrice: 499, maxPrice: 2499, tone: "#9A4B3A" },
  { id: "oral-science", num: "05", name: "Oral Science", range: "159–180", count: 22, status: "live", desc: "Botanical gum care, desensitizing formulas, charcoal toothbrushes, and oral rinses.", minPrice: 149, maxPrice: 799, tone: "#355B66" },
  { id: "baby", num: "06", name: "KYORP Baby", range: "181–204", count: 24, status: "live", desc: "Pediatric shampoos, diaper rash creams, massage oils, and talc-free soothing powders.", minPrice: 249, maxPrice: 1299, tone: "#A88D6A" },
  { id: "men", num: "07", name: "KYORP Men", range: "205–214", count: 10, status: "live", desc: "Beard oils, after-shave calming balms, charcoal cleansers, and scalp styling tonics.", minPrice: 499, maxPrice: 1799, tone: "#23262A" },
  { id: "femme", num: "08", name: "KYORP Femme", range: "215–230", count: 16, status: "live", desc: "Organic cotton menstrual pads, cramp relief roll-ons, and soothing herbal teas.", minPrice: 199, maxPrice: 999, tone: "#824652" },
  { id: "intimate", num: "09", name: "KYORP Intimate", range: "231–252", count: 22, status: "live", desc: "pH-balanced washes, pure botanical lubricants, post-intimacy soothing gels, and care kits.", minPrice: 249, maxPrice: 999, tone: "#8F5E4B" },
  { id: "sun-science", num: "10", name: "Sun Science", range: "253–262", count: 10, status: "live", desc: "Invisible daily fluids SPF 50+, mineral matte shields, and cooling after-sun gels.", minPrice: 599, maxPrice: 1499, tone: "#B37C2C" },
  { id: "clinical-dermatology", num: "11", name: "Clinical Dermatology", range: "263–274", count: 12, status: "development", desc: "Medical-grade actives, 10% Niacinamide, pure Retinol, Centella Cica balms, and BHA peels.", minPrice: 1199, maxPrice: 3899, tone: "#3E4957" },
  { id: "pharma-otc", num: "12", name: "KYORP Pharma (OTC)", range: "275–319", count: 45, status: "development", desc: "Ayurvedic cough syrups, throat lozenges, burn relief gels, and antiseptic ointments.", minPrice: 199, maxPrice: 899, tone: "#30523C" },
  { id: "nutrition", num: "13", name: "KYORP Nutrition", range: "320–364", count: 45, status: "development", desc: "Saffron Ashwagandha, marine collagen peptides, pure Shilajit, and vegan Omega-3 algal oil.", minPrice: 699, maxPrice: 2999, tone: "#5F6D38" },
  { id: "healthtech", num: "14", name: "KYORP HealthTech", range: "365–404", count: 40, status: "development", desc: "Sonic microcurrent sculptors, red light scalp therapy, pulse oximeters, and smart scales.", minPrice: 1999, maxPrice: 8999, tone: "#414756" },
  { id: "lifestyle", num: "15", name: "KYORP Lifestyle", range: "405–429", count: 25, status: "live", desc: "Mulberry silk sleep masks, handcrafted copper carafes, Kansa wands, and yoga mats.", minPrice: 799, maxPrice: 4999, tone: "#7F6756" }
];

// Initial 3 reels
const INITIAL_REELS: ReelItem[] = [
  {
    id: 1,
    title: "Saffron Harvest & Cold Extraction",
    desc: "Pampore terroir extraction of Grade A1 Mogra Crocus sativus preserving bioactive crocin.",
    tagline: "Div 01 • Dermalock™ & Facial Science",
    badge: "Reel 01 • Saffron Science",
    videoUrl: "https://assets.mixkit.co/videos/preview/mixkit-liquid-drops-splashing-in-slow-motion-42848-large.mp4",
    posterUrl: "https://images.unsplash.com/photo-1617897903246-719242758050?auto=format&fit=crop&w=720&q=80",
    divisionId: "skin-science",
    status: "active",
    lastUpdated: new Date().toISOString()
  },
  {
    id: 2,
    title: "72-Hour Barrier Lipid Matrix",
    desc: "Biomimetic ceramide-cholesterol infusion restoring stratum corneum micro-fissures.",
    tagline: "Div 03 • Dermato-Clinical Systems",
    badge: "Reel 02 • Clinical Barrier",
    videoUrl: "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4",
    posterUrl: "https://images.unsplash.com/photo-1556228720-195a672e8a03?auto=format&fit=crop&w=720&q=80",
    divisionId: "clinical-dermatology",
    status: "active",
    lastUpdated: new Date().toISOString()
  },
  {
    id: 3,
    title: "Kansa Wand Lymphatic Sculpt",
    desc: "Bio-thermal copper-tin alloy massage enhancing transdermal nutrient micro-circulation.",
    tagline: "Div 02 • Saffron & Rasayana Radiance",
    badge: "Reel 03 • Ritual & Sculpt",
    videoUrl: "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerEscapes.mp4",
    posterUrl: "https://images.unsplash.com/photo-1540555700478-4be289fbecef?auto=format&fit=crop&w=720&q=80",
    divisionId: "lifestyle",
    status: "active",
    lastUpdated: new Date().toISOString()
  }
];

import { generateSeedProducts } from './seedProducts.js';

export function getDatabase(): DatabaseSchema {
  if (fs.existsSync(DB_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
      // If products array is empty, populate from seed
      if (!data.products || data.products.length === 0) {
        data.products = generateSeedProducts(data.categories || INITIAL_DIVISIONS);
        saveDatabase(data);
      }
      return data;
    } catch (e) {
      console.error('Error reading db.json, generating default:', e);
    }
  }

  // Default credentials:
  // Password: AdminKYORP2026!
  // Recovery: KYORP-SECURE-2026-RECOVERY
  const defaultPass = process.env.ADMIN_PASSWORD || 'AdminKYORP2026!';
  const defaultRecovery = process.env.ADMIN_RECOVERY_CODE || 'KYORP-SECURE-2026-RECOVERY';

  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(defaultPass, salt);
  const recoveryCodeHash = bcrypt.hashSync(defaultRecovery, salt);

  const initialDb: DatabaseSchema = {
    admin: {
      passwordHash,
      recoveryCodeHash,
      sessions: [],
      sessionDurationHours: 24
    },
    settings: {
      announcementText: "Complimentary standard delivery on all orders above ₹1,999",
      announcementActive: true,
      heroHeadline: "Where Ancient Ayurveda unites with Modern Clinical Science.",
      heroSub: "KYORP is an umbrella consumer health ecosystem spanning 15 specialised divisions and 429 master formulations — rooted in original purity, biotechnology, and evidence-backed care.",
      heroVideoUrl: "video .mp4",
      freeShippingThresholdINR: 1999,
      flatShippingINR: 150,
      lastUpdated: new Date().toISOString()
    },
    reels: INITIAL_REELS,
    images: [
      {
        id: "img-logo-main",
        type: "image",
        originalName: "logo.jpeg",
        fileName: "logo.jpeg",
        url: "/logo.jpeg",
        sizeBytes: 15420,
        mimeType: "image/jpeg",
        title: "KYORP Master Brand Logo",
        uploadedAt: new Date().toISOString()
      }
    ],
    videos: [
      {
        id: "vid-hero-loop",
        type: "video",
        originalName: "video .mp4",
        fileName: "video .mp4",
        url: "video .mp4",
        sizeBytes: 8500000,
        mimeType: "video/mp4",
        title: "Hero Background Botanical Synthesis Loop",
        uploadedAt: new Date().toISOString()
      }
    ],
    products: generateSeedProducts(INITIAL_DIVISIONS),
    categories: INITIAL_DIVISIONS,
    googleSheets: {
      sheetUrl: "",
      sheetId: "",
      webhookUrl: "",
      lastSyncedAt: "",
      syncStatus: "idle",
      syncMessage: "Ready for synchronisation",
      autoSync: false
    },
    auditLogs: [
      {
        id: "log-init",
        timestamp: new Date().toISOString(),
        action: "SYSTEM_INITIALIZED",
        details: "KYORP Private Admin Management Engine initialized."
      }
    ]
  };

  saveDatabase(initialDb);
  return initialDb;
}

export function saveDatabase(db: DatabaseSchema): void {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to save db.json:', err);
  }
}

export function logAudit(action: string, details: string, ip?: string): void {
  const db = getDatabase();
  db.auditLogs.unshift({
    id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
    timestamp: new Date().toISOString(),
    action,
    details,
    ip
  });
  if (db.auditLogs.length > 200) {
    db.auditLogs = db.auditLogs.slice(0, 200);
  }
  saveDatabase(db);
}
