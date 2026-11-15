import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createServer as createViteServer, ViteDevServer } from 'vite';
import { WebSocketServer, WebSocket } from 'ws';
import {
  initialUsers,
  initialRolePermissions,
  initialOfficeDetails,
  initialCompanyLogo,
  defaultLoginBg
} from './src/data/appConfig';
import { MAIN_ADMIN_EMAIL, isMainAdmin, canManageBranding } from './src/utils/brandingAccess';
import type {
  User,
  UserRole,
  RolePermissions,
  OfficeDetails,
  PublicBrandingConfig,
  ChatGroup,
  ChatMessage,
  ChatAttachment,
  ChatReplyPreview,
  MessagingUserSummary
} from './src/types';

const PORT = 3000;
const ROOT_DIR = import.meta.dirname;
const DATA_DIR = path.join(ROOT_DIR, 'data');
const NOTIF_STORE_PATH = path.join(DATA_DIR, 'notifications-store.json');
const SECURITY_STORE_PATH = path.join(DATA_DIR, 'erp-security-store.json');
const CHAT_STORE_PATH = path.join(DATA_DIR, 'chat-store.json');
const CHAT_UPLOADS_DIR = path.join(DATA_DIR, 'chat-uploads');
const BRANDING_MEDIA_DIR = path.join(DATA_DIR, 'branding-media');
const BRANDING_LOGO_DIR = path.join(BRANDING_MEDIA_DIR, 'logo');
const BRANDING_BG_DIR = path.join(BRANDING_MEDIA_DIR, 'bg');
const BRANDING_BACKUP_DIR = path.join(DATA_DIR, 'branding-backups');
const SECRET_PATH = path.join(DATA_DIR, '.auth-secret');

function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

ensureDir(DATA_DIR);
ensureDir(CHAT_UPLOADS_DIR);
ensureDir(BRANDING_MEDIA_DIR);
ensureDir(BRANDING_LOGO_DIR);
ensureDir(BRANDING_BG_DIR);
ensureDir(BRANDING_BACKUP_DIR);

// =========================================================================
// CRYPTOGRAPHIC PASSWORD HASHING & HMAC SESSION TOKEN INFRASTRUCTURE
// =========================================================================

function getAuthSecret(): string {
  const envSecret = (process.env.AUTH_SECRET || '').trim();
  if (envSecret) return envSecret;
  try {
    if (fs.existsSync(SECRET_PATH)) {
      const saved = fs.readFileSync(SECRET_PATH, 'utf-8').trim();
      if (saved) return saved;
    }
    const generated = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(SECRET_PATH, generated, 'utf-8');
    return generated;
  } catch {
    return crypto.createHash('sha256').update(ROOT_DIR).digest('hex');
  }
}

const AUTH_SECRET = getAuthSecret();

function hashPassword(plain: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(plain: string, stored?: string): boolean {
  if (!stored) return false;
  if (stored.startsWith('scrypt$')) {
    const parts = stored.split('$');
    if (parts.length !== 3) return false;
    const [, salt, hexHash] = parts;
    const candidate = crypto.scryptSync(plain, salt, 64);
    const storedBuf = Buffer.from(hexHash, 'hex');
    if (candidate.length !== storedBuf.length) return false;
    return crypto.timingSafeEqual(candidate, storedBuf);
  }
  return plain === stored;
}

interface TokenPayload {
  userId: string;
  role: string;
  tokenVersion: number;
  exp: number;
}

function signToken(user: User): string {
  const payload: TokenPayload = {
    userId: user.id,
    role: user.role,
    tokenVersion: user.tokenVersion || 1,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

function verifyTokenString(token?: string | null): TokenPayload | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', AUTH_SECRET).update(encoded).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8')) as TokenPayload;
    if (!parsed?.userId || !parsed?.exp || parsed.exp < Date.now()) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function isAdminRole(role?: string): boolean {
  return role === 'Super Admin' || role === 'Admin';
}

function sanitizeUser(u: User): Omit<User, 'passwordHash'> {
  const { passwordHash: _removed, ...safe } = u;
  return {
    ...safe,
    messagingEnabled: u.messagingEnabled !== false,
    brandingAuthorized: isMainAdmin(u) ? true : Boolean(isAdminRole(u.role) && u.brandingAuthorized)
  };
}

function resolveUserPermissions(
  user: User,
  rolePermissions: Record<UserRole, RolePermissions>
): RolePermissions {
  const base = rolePermissions[user.role] || rolePermissions['Standard Staff'];
  if (isAdminRole(user.role)) {
    return {
      viewSalaries: true,
      editSalaries: true,
      viewExpenses: true,
      editExpenses: true,
      viewAttendance: true,
      editAttendance: true,
      manageVehicles: true,
      manageDrivers: true,
      manageFuel: true,
      adminPortal: true,
      exportReports: true
    };
  }
  return {
    ...base,
    ...(user.customPermissions || {}),
    adminPortal: false
  };
}

// =========================================================================
// SECURITY STORE (USERS, RBAC, CONFIDENTIAL COMPANY DETAILS, PUBLIC BRANDING)
// =========================================================================

interface SecurityStore {
  users: User[];
  rolePermissions: Record<UserRole, RolePermissions>;
  officeDetails: OfficeDetails;
  publicBranding: PublicBrandingConfig;
  seededBootstrapped?: boolean;
}

function readSecurityStore(): SecurityStore {
  try {
    ensureDir(DATA_DIR);
    let store: Partial<SecurityStore> = {};
    const storeExists = fs.existsSync(SECURITY_STORE_PATH);
    if (storeExists) {
      store = JSON.parse(fs.readFileSync(SECURITY_STORE_PATH, 'utf-8'));
    }

    const existingUsers: User[] = Array.isArray(store.users) ? store.users : [];
    const byEmail = new Map(existingUsers.map(u => [u.email.toLowerCase(), u]));
    let dirty = !storeExists || !store.seededBootstrapped;

    // Seed all demo users ONLY on initial bootstrap; thereafter ALWAYS preserve the permanent Main Admin account
    for (const seed of initialUsers) {
      const key = seed.email.toLowerCase();
      const shouldEnsure = key === MAIN_ADMIN_EMAIL || !store.seededBootstrapped;
      if (!shouldEnsure) continue;
      const found = byEmail.get(key);
      if (!found) {
        byEmail.set(key, {
          ...seed,
          tokenVersion: 1,
          messagingEnabled: seed.messagingEnabled !== false,
          passwordHash: seed.passwordHash ? hashPassword(seed.passwordHash) : hashPassword('Stranz@2819')
        });
        dirty = true;
      } else if (found.passwordHash && !found.passwordHash.startsWith('scrypt$')) {
        found.passwordHash = hashPassword(found.passwordHash);
        dirty = true;
      }
    }

    // Migrate any leftover plaintext user passwords and enforce permanent Main Admin invariants
    const users = Array.from(byEmail.values()).map(u => {
      let next: User = {
        ...u,
        tokenVersion: u.tokenVersion || 1,
        messagingEnabled: u.messagingEnabled !== false
      };
      if (next.passwordHash && !next.passwordHash.startsWith('scrypt$')) {
        dirty = true;
        next = { ...next, passwordHash: hashPassword(next.passwordHash) };
      }
      if (next.email.toLowerCase() === MAIN_ADMIN_EMAIL) {
        if (next.role !== 'Super Admin' || next.status !== 'Active' || !next.brandingAuthorized) {
          dirty = true;
          next = {
            ...next,
            role: 'Super Admin',
            status: 'Active',
            brandingAuthorized: true
          };
        }
      }
      return next;
    });

    const officeDetails: OfficeDetails = store.officeDetails || initialOfficeDetails;
    const rolePermissions: Record<UserRole, RolePermissions> = {
      ...initialRolePermissions,
      ...(store.rolePermissions || {})
    };
    const publicBranding: PublicBrandingConfig = store.publicBranding || {
      companyName: officeDetails.companyName || initialOfficeDetails.companyName,
      companyLogo: officeDetails.companyLogo || initialOfficeDetails.companyLogo,
      loginBg: defaultLoginBg,
      loginBgType: 'image'
    };

    const normalized: SecurityStore = {
      users,
      rolePermissions,
      officeDetails,
      publicBranding,
      seededBootstrapped: true
    };

    if (dirty) {
      fs.writeFileSync(SECURITY_STORE_PATH, JSON.stringify(normalized, null, 2), 'utf-8');
    }
    return normalized;
  } catch (err) {
    console.error('Security store read error:', err);
    return {
      users: initialUsers.map(u => ({
        ...u,
        tokenVersion: 1,
        messagingEnabled: true,
        passwordHash: hashPassword(u.passwordHash || 'Stranz@2819')
      })),
      rolePermissions: initialRolePermissions,
      officeDetails: initialOfficeDetails,
      publicBranding: {
        companyName: initialOfficeDetails.companyName,
        companyLogo: initialOfficeDetails.companyLogo,
        loginBg: defaultLoginBg,
        loginBgType: 'image'
      },
      seededBootstrapped: true
    };
  }
}

function writeSecurityStore(store: SecurityStore): void {
  ensureDir(DATA_DIR);
  fs.writeFileSync(SECURITY_STORE_PATH, JSON.stringify(store, null, 2), 'utf-8');
}

// =========================================================================
// NOTIFICATION STORE & WHATSAPP CLOUD API
// =========================================================================

export type NotificationChannel = 'website' | 'whatsapp' | 'both';
export type NotificationPriority = 'Low' | 'Normal' | 'High' | 'Urgent';
export type NotificationCategory =
  | 'maintenance'
  | 'service'
  | 'compliance'
  | 'driver'
  | 'announcement'
  | 'general';
export type WhatsAppDeliveryStatus =
  | 'Not Applicable'
  | 'Pending'
  | 'Sent'
  | 'Failed'
  | 'Skipped (No Consent)'
  | 'Skipped (Invalid Phone)'
  | 'Skipped (Missing API Config)';

export interface StoredNotificationRecord {
  id: string;
  batchId: string;
  title: string;
  message: string;
  priority: NotificationPriority;
  category: NotificationCategory;
  channel: NotificationChannel;
  senderId: string;
  senderName: string;
  recipientUserId: string;
  recipientName: string;
  recipientRole: string;
  recipientMobile: string;
  read: boolean;
  readAt?: string;
  whatsappStatus: WhatsAppDeliveryStatus;
  whatsappMessageId?: string;
  whatsappError?: string;
  createdAt: string;
  linkModule?: string;
}

interface NotificationStore {
  notifications: StoredNotificationRecord[];
}

function ensureStore(): NotificationStore {
  try {
    ensureDir(DATA_DIR);
    if (!fs.existsSync(NOTIF_STORE_PATH)) {
      const empty: NotificationStore = { notifications: [] };
      fs.writeFileSync(NOTIF_STORE_PATH, JSON.stringify(empty, null, 2), 'utf-8');
      return empty;
    }
    const raw = fs.readFileSync(NOTIF_STORE_PATH, 'utf-8');
    const parsed = JSON.parse(raw);
    return {
      notifications: Array.isArray(parsed?.notifications) ? parsed.notifications : []
    };
  } catch (err) {
    console.error('Failed to read notifications store:', err);
    return { notifications: [] };
  }
}

function writeStore(store: NotificationStore): void {
  try {
    ensureDir(DATA_DIR);
    fs.writeFileSync(NOTIF_STORE_PATH, JSON.stringify(store, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to persist notifications store:', err);
  }
}

function normalizeWhatsAppPhone(rawPhone?: string): string | null {
  if (!rawPhone) return null;
  const digits = rawPhone.replace(/\D/g, '');
  if (!digits) return null;
  if (digits.length === 10) return `91${digits}`;
  if (digits.length === 11 && digits.startsWith('0')) return `91${digits.slice(1)}`;
  if (digits.length >= 11 && digits.length <= 15) return digits;
  return null;
}

function getWhatsAppEnvConfig() {
  const accessToken = (process.env.WHATSAPP_ACCESS_TOKEN || '').trim();
  const phoneNumberId = (process.env.WHATSAPP_PHONE_NUMBER_ID || '').trim();
  const businessAccountId = (process.env.WHATSAPP_BUSINESS_ACCOUNT_ID || '').trim();
  const apiVersion = (process.env.WHATSAPP_API_VERSION || 'v21.0').trim() || 'v21.0';
  const configured = Boolean(accessToken && phoneNumberId);
  return {
    accessToken,
    phoneNumberId,
    businessAccountId,
    apiVersion,
    configured
  };
}

async function sendRealWhatsAppTextMessage(
  toPhone: string,
  title: string,
  message: string,
  priority: NotificationPriority
): Promise<{ ok: boolean; messageId?: string; error?: string }> {
  const cfg = getWhatsAppEnvConfig();
  if (!cfg.configured) {
    return {
      ok: false,
      error:
        'WhatsApp Cloud API credentials (WHATSAPP_ACCESS_TOKEN, WHATSAPP_PHONE_NUMBER_ID) are not configured on the server.'
    };
  }

  const endpoint = `https://graph.facebook.com/${cfg.apiVersion}/${cfg.phoneNumberId}/messages`;
  const priorityPrefix = priority === 'Urgent' || priority === 'High' ? `[${priority.toUpperCase()}] ` : '';
  const bodyText = `${priorityPrefix}S-TRANZ LOGISTIC ERP\n*${title}*\n\n${message}`.slice(0, 4096);

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${cfg.accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        recipient_type: 'individual',
        to: toPhone,
        type: 'text',
        text: {
          preview_url: false,
          body: bodyText
        }
      })
    });

    const data: any = await response.json().catch(() => ({}));
    if (!response.ok) {
      const apiErr =
        data?.error?.message ||
        data?.error?.error_user_msg ||
        `Meta Graph API responded with HTTP ${response.status}`;
      return { ok: false, error: apiErr };
    }
    return { ok: true, messageId: data?.messages?.[0]?.id };
  } catch (err: any) {
    return {
      ok: false,
      error: err?.message || 'Network error while reaching Meta WhatsApp Cloud API.'
    };
  }
}

// =========================================================================
// INTERNAL WHATSAPP-STYLE MESSAGING STORE & HELPERS
// =========================================================================

interface StoredAttachmentMeta {
  id: string;
  storedFileName: string;
  fileName: string;
  mimeType: string;
  size: number;
  conversationKey: string;
  uploadedBy: string;
  createdAt: string;
}

interface ChatStore {
  groups: ChatGroup[];
  messages: ChatMessage[];
  attachments: Record<string, StoredAttachmentMeta>;
}

function readChatStore(): ChatStore {
  try {
    ensureDir(DATA_DIR);
    if (!fs.existsSync(CHAT_STORE_PATH)) {
      const initial: ChatStore = { groups: [], messages: [], attachments: {} };
      fs.writeFileSync(CHAT_STORE_PATH, JSON.stringify(initial, null, 2), 'utf-8');
      return initial;
    }
    const parsed = JSON.parse(fs.readFileSync(CHAT_STORE_PATH, 'utf-8'));
    return {
      groups: Array.isArray(parsed?.groups) ? parsed.groups : [],
      messages: Array.isArray(parsed?.messages) ? parsed.messages : [],
      attachments: parsed?.attachments && typeof parsed.attachments === 'object' ? parsed.attachments : {}
    };
  } catch (err) {
    console.error('Chat store read error:', err);
    return { groups: [], messages: [], attachments: {} };
  }
}

function writeChatStore(store: ChatStore): void {
  ensureDir(DATA_DIR);
  fs.writeFileSync(CHAT_STORE_PATH, JSON.stringify(store, null, 2), 'utf-8');
}

function getPrivateConversationKey(userA: string, userB: string): string {
  const [first, second] = [userA, userB].sort();
  return `private:${first}__${second}`;
}

function getGroupConversationKey(groupId: string): string {
  return `group:${groupId}`;
}

function canUserAccessConversation(
  user: User,
  conversationKey: string,
  groups: ChatGroup[]
): boolean {
  if (conversationKey.startsWith('private:')) {
    const pair = conversationKey.slice('private:'.length).split('__');
    return pair.includes(user.id);
  }
  if (conversationKey.startsWith('group:')) {
    const groupId = conversationKey.slice('group:'.length);
    const group = groups.find(g => g.id === groupId);
    if (!group) return false;
    return group.members.includes(user.id);
  }
  return false;
}

const ALLOWED_ATTACHMENT_EXTS = new Set([
  '.jpg',
  '.jpeg',
  '.png',
  '.gif',
  '.webp',
  '.bmp',
  '.mp4',
  '.webm',
  '.mov',
  '.m4v',
  '.3gp',
  '.pdf',
  '.xls',
  '.xlsx',
  '.csv',
  '.doc',
  '.docx',
  '.txt',
  '.ppt',
  '.pptx',
  '.zip'
]);

// =========================================================================
// AUTH MIDDLEWARE
// =========================================================================

interface AuthedRequest extends Request {
  authUser?: User;
}

function extractBearerToken(req: Request): string | null {
  const authHeader = req.header('authorization') || '';
  if (authHeader.toLowerCase().startsWith('bearer ')) {
    return authHeader.slice(7).trim();
  }
  if (typeof req.query.token === 'string' && req.query.token.trim()) {
    return req.query.token.trim();
  }
  return null;
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): void {
  const token = extractBearerToken(req);
  const payload = verifyTokenString(token);
  if (!payload) {
    res.status(401).json({ error: 'Unauthorized: Valid session token required.' });
    return;
  }
  const store = readSecurityStore();
  const user = store.users.find(u => u.id === payload.userId);
  if (
    !user ||
    user.status !== 'Active' ||
    (payload.tokenVersion !== undefined && payload.tokenVersion !== (user.tokenVersion || 1))
  ) {
    res.status(401).json({ error: 'Unauthorized: Session revoked or user account inactive.' });
    return;
  }
  req.authUser = user;
  next();
}

function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction): void {
  requireAuth(req, res, () => {
    if (!req.authUser || !isAdminRole(req.authUser.role)) {
      res.status(403).json({
        error: '403 Forbidden: Administrative privileges are strictly required for this resource.'
      });
      return;
    }
    next();
  });
}

function requireBrandingAdmin(req: AuthedRequest, res: Response, next: NextFunction): void {
  requireAuth(req, res, () => {
    if (!req.authUser || !canManageBranding(req.authUser)) {
      res.status(403).json({
        error:
          '403 Forbidden: Company Logo and Login Background settings are restricted exclusively to the permanent Main Admin account or explicitly authorized Admins.'
      });
      return;
    }
    next();
  });
}

function backupDirFiles(sourceDir: string, prefix: string) {
  try {
    ensureDir(BRANDING_BACKUP_DIR);
    if (!fs.existsSync(sourceDir)) return;
    const files = fs.readdirSync(sourceDir);
    for (const f of files) {
      const src = path.join(sourceDir, f);
      if (!fs.statSync(src).isFile()) continue;
      const dest = path.join(BRANDING_BACKUP_DIR, `${prefix}-${Date.now()}-${f}`);
      fs.copyFileSync(src, dest);
      fs.unlinkSync(src);
    }
  } catch (err) {
    console.warn('Branding backup warning:', err);
  }
}

function parseValidatedImageUpload(
  req: Request,
  options: { allowSvg: boolean; maxBytes: number }
): { ok: true; buffer: Buffer; ext: string; mimeType: string } | { ok: false; status: number; error: string } {
  let buffer: Buffer | null = null;
  let declaredMime = String(req.header('content-type') || '').split(';')[0].trim().toLowerCase();
  const headerName = String(req.header('x-file-name') || '').toLowerCase();

  if (Buffer.isBuffer(req.body) && req.body.length > 0) {
    buffer = req.body;
  } else if (req.body && typeof req.body === 'object' && typeof req.body.mediaDataUrl === 'string') {
    const dataUrl = req.body.mediaDataUrl;
    const base64Match = dataUrl.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/);
    const utf8SvgMatch = dataUrl.match(/^data:(image\/svg\+xml)(?:;charset=[^;,]+)?,(.+)$/i);
    if (base64Match) {
      declaredMime = base64Match[1].toLowerCase();
      buffer = Buffer.from(base64Match[2], 'base64');
    } else if (utf8SvgMatch && options.allowSvg) {
      declaredMime = 'image/svg+xml';
      buffer = Buffer.from(decodeURIComponent(utf8SvgMatch[2]), 'utf-8');
    }
  }

  if (!buffer || buffer.length === 0) {
    return { ok: false, status: 400, error: 'Please select a valid image file to upload.' };
  }
  if (buffer.length > options.maxBytes) {
    const maxMb = Math.round(options.maxBytes / (1024 * 1024));
    return { ok: false, status: 413, error: `File size exceeds the ${maxMb} MB limit.` };
  }

  // Magic-byte signature detection
  const isPng =
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47;
  const isJpg = buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  const isWebp =
    buffer.length >= 12 &&
    buffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buffer.subarray(8, 12).toString('ascii') === 'WEBP';

  if (isPng) return { ok: true, buffer, ext: 'png', mimeType: 'image/png' };
  if (isJpg) return { ok: true, buffer, ext: 'jpg', mimeType: 'image/jpeg' };
  if (isWebp) return { ok: true, buffer, ext: 'webp', mimeType: 'image/webp' };

  if (
    options.allowSvg &&
    (declaredMime === 'image/svg+xml' || headerName.endsWith('.svg'))
  ) {
    const text = buffer.toString('utf-8').trim();
    if (/<svg[\s>]/i.test(text)) {
      // Strip potential inline scripts / event handlers from SVG for XSS safety
      const sanitizedSvg = text
        .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
        .replace(/\son\w+\s*=\s*(".*?"|'.*?'|[^\s>]+)/gi, '');
      return {
        ok: true,
        buffer: Buffer.from(sanitizedSvg, 'utf-8'),
        ext: 'svg',
        mimeType: 'image/svg+xml'
      };
    }
  }

  const allowedList = options.allowSvg ? 'PNG, JPG, JPEG, WEBP, or SVG' : 'JPG, JPEG, PNG, or WEBP';
  return {
    ok: false,
    status: 415,
    error: `Unsupported or corrupted image file. Please upload a valid ${allowedList} file.`
  };
}

// =========================================================================
// EXPRESS + WEBSOCKET SERVER BOOTSTRAP
// =========================================================================

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '45mb' }));

  const httpServer = http.createServer(app);

  // Real-Time WebSocket Hub on dedicated path /ws/chat
  const wss = new WebSocketServer({ server: httpServer, path: '/ws/chat' });
  const onlineSockets = new Map<string, Set<WebSocket>>();

  function getOnlineUserIds(): string[] {
    return Array.from(onlineSockets.entries())
      .filter(([, sockets]) => sockets.size > 0)
      .map(([uid]) => uid);
  }

  function sendToUsers(userIds: string[], event: string, data: unknown) {
    const payload = JSON.stringify({ event, data });
    for (const uid of new Set(userIds)) {
      const sockets = onlineSockets.get(uid);
      if (!sockets) continue;
      for (const ws of sockets) {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(payload);
        }
      }
    }
  }

  function broadcastAllAuthenticated(event: string, data: unknown) {
    const payload = JSON.stringify({ event, data });
    for (const sockets of onlineSockets.values()) {
      for (const ws of sockets) {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(payload);
        }
      }
    }
  }

  function disconnectUserSockets(userId: string, reason = 'Access revoked') {
    const sockets = onlineSockets.get(userId);
    if (!sockets) return;
    for (const ws of sockets) {
      try {
        ws.close(4003, reason);
      } catch {
        // ignore close error
      }
    }
    onlineSockets.delete(userId);
    broadcastAllAuthenticated('presence:update', { onlineUserIds: getOnlineUserIds() });
  }

  wss.on('connection', (ws: WebSocket, req: http.IncomingMessage) => {
    try {
      const urlObj = new URL(req.url || '/ws/chat', `http://localhost:${PORT}`);
      const token = urlObj.searchParams.get('token');
      const payload = verifyTokenString(token);
      if (!payload) {
        ws.close(4001, 'Unauthorized');
        return;
      }

      const store = readSecurityStore();
      const user = store.users.find(u => u.id === payload.userId);
      if (
        !user ||
        user.status !== 'Active' ||
        user.messagingEnabled === false ||
        (payload.tokenVersion !== undefined && payload.tokenVersion !== (user.tokenVersion || 1))
      ) {
        ws.close(4003, 'Session revoked or messaging access disabled');
        return;
      }

      const userId = user.id;
      let userSet = onlineSockets.get(userId);
      if (!userSet) {
        userSet = new Set();
        onlineSockets.set(userId, userSet);
      }
      userSet.add(ws);

      // Mark any pending incoming messages to this user as delivered
      const chatStore = readChatStore();
      const newlyDeliveredIds: string[] = [];
      const notifySenderIds = new Set<string>();
      for (const msg of chatStore.messages) {
        const isRecipient =
          (msg.type === 'private' && msg.recipientId === userId) ||
          (msg.type === 'group' &&
            msg.senderId !== userId &&
            chatStore.groups.some(g => g.id === msg.groupId && g.members.includes(userId)));
        if (isRecipient && !msg.deliveredTo.includes(userId)) {
          msg.deliveredTo.push(userId);
          newlyDeliveredIds.push(msg.id);
          notifySenderIds.add(msg.senderId);
        }
      }
      if (newlyDeliveredIds.length > 0) {
        writeChatStore(chatStore);
        sendToUsers(Array.from(notifySenderIds), 'chat:delivery_receipt', {
          userId,
          messageIds: newlyDeliveredIds
        });
      }

      broadcastAllAuthenticated('presence:update', { onlineUserIds: getOnlineUserIds() });

      ws.on('message', raw => {
        try {
          const parsed = JSON.parse(raw.toString());
          const ev = parsed?.event;
          const data = parsed?.data || {};

          if (ev === 'typing:start' || ev === 'typing:stop') {
            const isTyping = ev === 'typing:start';
            const conversationKey = String(data.conversationKey || '');
            const cStore = readChatStore();
            if (!canUserAccessConversation(user, conversationKey, cStore.groups)) {
              return;
            }
            let targets: string[] = [];
            if (conversationKey.startsWith('private:')) {
              const pair = conversationKey.slice('private:'.length).split('__');
              targets = pair.filter(id => id !== userId);
            } else if (conversationKey.startsWith('group:')) {
              const gid = conversationKey.slice('group:'.length);
              const grp = cStore.groups.find(g => g.id === gid);
              if (grp) targets = grp.members.filter(id => id !== userId);
            }
            sendToUsers(targets, 'typing:update', {
              conversationKey,
              userId,
              userName: user.name,
              isTyping
            });
          } else if (ev === 'chat:read') {
            const conversationKey = String(data.conversationKey || '');
            const cStore = readChatStore();
            if (!canUserAccessConversation(user, conversationKey, cStore.groups)) {
              return;
            }
            const readIds: string[] = [];
            const senderIds = new Set<string>();
            for (const m of cStore.messages) {
              if (m.conversationKey === conversationKey && !m.readBy.includes(userId)) {
                m.readBy.push(userId);
                if (!m.deliveredTo.includes(userId)) m.deliveredTo.push(userId);
                readIds.push(m.id);
                senderIds.add(m.senderId);
              }
            }
            if (readIds.length > 0) {
              writeChatStore(cStore);
              sendToUsers([userId, ...Array.from(senderIds)], 'chat:read_receipt', {
                conversationKey,
                userId,
                messageIds: readIds
              });
            }
          }
        } catch {
          // ignore malformed ws message
        }
      });

      ws.on('close', () => {
        const set = onlineSockets.get(userId);
        if (set) {
          set.delete(ws);
          if (set.size === 0) {
            onlineSockets.delete(userId);
          }
        }
        broadcastAllAuthenticated('presence:update', { onlineUserIds: getOnlineUserIds() });
      });
    } catch {
      ws.close(4000, 'Connection error');
    }
  });

  // =========================================================================
  // HEALTH & PUBLIC BRANDING ENDPOINTS
  // =========================================================================

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', port: PORT });
  });

  // Public Login Screen Branding ONLY (zero confidential GST/phone/email/owner info leaked)
  app.get('/api/auth/public-branding', (_req: Request, res: Response) => {
    const store = readSecurityStore();
    res.json({ publicBranding: store.publicBranding });
  });

  // Serve permanently uploaded company logo safely
  app.get('/api/branding/logo-media/:filename', (req: Request, res: Response) => {
    const safeName = path.basename(req.params.filename || '');
    const fullPath = path.join(BRANDING_LOGO_DIR, safeName);
    if (!safeName || !fs.existsSync(fullPath)) {
      res.status(404).json({ error: 'Company logo asset not found.' });
      return;
    }
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.sendFile(fullPath);
  });

  // Serve permanently uploaded login background media safely
  app.get('/api/branding/bg-media/:filename', (req: Request, res: Response) => {
    const safeName = path.basename(req.params.filename || '');
    const primaryPath = path.join(BRANDING_BG_DIR, safeName);
    const legacyPath = path.join(BRANDING_MEDIA_DIR, safeName);
    const fullPath = fs.existsSync(primaryPath) ? primaryPath : legacyPath;
    if (!safeName || !fs.existsSync(fullPath)) {
      res.status(404).json({ error: 'Background asset not found.' });
      return;
    }
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.sendFile(fullPath);
  });

  // =========================================================================
  // AUTHENTICATION ENDPOINTS (PASSWORD HASHING + SIGN UP + RBAC)
  // =========================================================================

  app.post('/api/auth/login', (req: Request, res: Response) => {
    const { email, password } = req.body || {};
    const normEmail = String(email || '').trim().toLowerCase();
    const plainPass = String(password || '');

    if (!normEmail || !plainPass) {
      res.status(400).json({ success: false, message: 'Email ID and Password are required.' });
      return;
    }

    const store = readSecurityStore();
    const idx = store.users.findIndex(u => u.email.toLowerCase() === normEmail);
    if (idx === -1) {
      res.status(401).json({ success: false, message: 'No registered user found with this Email ID.' });
      return;
    }

    const user = store.users[idx];
    if (user.status === 'Inactive') {
      res.status(403).json({
        success: false,
        message: 'Account has been deactivated. Contact Administrator.'
      });
      return;
    }

    if (!verifyPassword(plainPass, user.passwordHash)) {
      res.status(401).json({ success: false, message: 'Incorrect password. Please verify credentials.' });
      return;
    }

    const updatedUser: User = {
      ...user,
      lastLogin: new Date().toLocaleString()
    };
    store.users[idx] = updatedUser;
    writeSecurityStore(store);

    const token = signToken(updatedUser);
    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: sanitizeUser(updatedUser),
      canManageBranding: canManageBranding(updatedUser),
      permissions: resolveUserPermissions(updatedUser, store.rolePermissions)
    });
  });

  // Public Sign Up: accepts ONLY Company Name, User Email ID, Password; NEVER grants Admin role
  app.post('/api/auth/signup', (req: Request, res: Response) => {
    const { companyName, email, password } = req.body || {};
    const cleanCompany = String(companyName || '').trim();
    const normEmail = String(email || '').trim().toLowerCase();
    const plainPass = String(password || '');

    if (!cleanCompany || !normEmail || !plainPass) {
      res.status(400).json({
        success: false,
        message: 'Company Name, User Email ID, and Password are required.'
      });
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normEmail)) {
      res.status(400).json({ success: false, message: 'Please enter a valid Email ID.' });
      return;
    }

    if (plainPass.length < 6) {
      res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long.'
      });
      return;
    }

    const store = readSecurityStore();
    if (store.users.some(u => u.email.toLowerCase() === normEmail)) {
      res.status(409).json({
        success: false,
        message: 'An account with this Email ID already exists.'
      });
      return;
    }

    const emailPrefix = normEmail.split('@')[0] || 'staff';
    const newUser: User = {
      id: `usr_${Date.now()}_${crypto.randomBytes(2).toString('hex')}`,
      name: `${emailPrefix} (${cleanCompany})`,
      email: normEmail,
      username: emailPrefix,
      mobile: '',
      whatsappConsent: false,
      messagingEnabled: true,
      companyName: cleanCompany,
      role: 'Standard Staff', // Strict security: Public Sign Up can NEVER create an Admin
      status: 'Active',
      passwordHash: hashPassword(plainPass),
      createdAt: new Date().toISOString().split('T')[0]
    };

    store.users.push(newUser);
    writeSecurityStore(store);

    broadcastAllAuthenticated('chat:user_updated', { user: sanitizeUser(newUser) });

    res.status(201).json({
      success: true,
      message: 'Account created successfully! Please sign in with your Email ID and Password.',
      user: sanitizeUser(newUser)
    });
  });

  app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res: Response) => {
    const store = readSecurityStore();
    const freshUser = req.authUser!;
    res.json({
      user: sanitizeUser(freshUser),
      canManageBranding: canManageBranding(freshUser),
      permissions: resolveUserPermissions(freshUser, store.rolePermissions)
    });
  });

  // =========================================================================
  // ADMIN-ONLY ENDPOINTS (CONFIDENTIAL COMPANY DETAILS, USERS, RBAC, BRANDING)
  // =========================================================================

  // Confidential Company Details (Strictly Admin Only - blocked for Staff with 403)
  app.get('/api/company/details', requireAdmin, (_req: AuthedRequest, res: Response) => {
    const store = readSecurityStore();
    res.json({ officeDetails: store.officeDetails });
  });

  app.put('/api/company/details', requireAdmin, (req: AuthedRequest, res: Response) => {
    const store = readSecurityStore();
    const updates = { ...(req.body || {}) };
    // Only Main Admin or explicitly branding-authorized Admin may modify companyLogo
    if (!canManageBranding(req.authUser)) {
      delete updates.companyLogo;
    }
    store.officeDetails = {
      ...store.officeDetails,
      ...updates
    };
    store.publicBranding = {
      ...store.publicBranding,
      companyName: store.officeDetails.companyName || store.publicBranding.companyName,
      companyLogo:
        updates.companyLogo !== undefined
          ? updates.companyLogo
          : store.officeDetails.companyLogo ?? store.publicBranding.companyLogo
    };
    writeSecurityStore(store);
    res.json({
      officeDetails: store.officeDetails,
      publicBranding: store.publicBranding
    });
  });

  // =========================================================================
  // MAIN ADMIN ONLY: COMPANY LOGO MANAGEMENT (PNG, JPG, JPEG, WEBP, SVG)
  // =========================================================================
  const uploadLogoRawMiddleware = express.raw({
    type: ['image/*', 'application/octet-stream'],
    limit: '6mb'
  });

  app.post(
    '/api/admin/branding/logo',
    requireBrandingAdmin,
    uploadLogoRawMiddleware,
    (req: AuthedRequest, res: Response) => {
      const parsed = parseValidatedImageUpload(req, {
        allowSvg: true,
        maxBytes: 5 * 1024 * 1024
      });
      if (!parsed.ok) {
        res.status(parsed.status).json({ error: parsed.error });
        return;
      }

      // Back up existing logo before replacing
      backupDirFiles(BRANDING_LOGO_DIR, 'logo');

      const fileName = `company-logo-${Date.now()}.${parsed.ext}`;
      fs.writeFileSync(path.join(BRANDING_LOGO_DIR, fileName), parsed.buffer);

      const logoUrl = `/api/branding/logo-media/${fileName}`;
      const store = readSecurityStore();
      store.officeDetails = {
        ...store.officeDetails,
        companyLogo: logoUrl
      };
      store.publicBranding = {
        ...store.publicBranding,
        companyLogo: logoUrl
      };
      writeSecurityStore(store);

      res.json({
        success: true,
        logoUrl,
        officeDetails: store.officeDetails,
        publicBranding: store.publicBranding
      });
    }
  );

  app.delete('/api/admin/branding/logo', requireBrandingAdmin, (req: AuthedRequest, res: Response) => {
    backupDirFiles(BRANDING_LOGO_DIR, 'logo');
    const mode = String(req.query.mode || 'delete');
    const nextLogo = mode === 'restore' ? initialCompanyLogo : '';

    const store = readSecurityStore();
    store.officeDetails = {
      ...store.officeDetails,
      companyLogo: nextLogo
    };
    store.publicBranding = {
      ...store.publicBranding,
      companyLogo: nextLogo
    };
    writeSecurityStore(store);

    res.json({
      success: true,
      officeDetails: store.officeDetails,
      publicBranding: store.publicBranding
    });
  });

  // =========================================================================
  // MAIN ADMIN ONLY: LOGIN BACKGROUND PHOTO MANAGEMENT (JPG, JPEG, PNG, WEBP)
  // =========================================================================
  const uploadBgRawMiddleware = express.raw({
    type: ['image/*', 'application/octet-stream'],
    limit: '16mb'
  });

  const handleUploadLoginBg = (req: AuthedRequest, res: Response) => {
    const parsed = parseValidatedImageUpload(req, {
      allowSvg: false,
      maxBytes: 15 * 1024 * 1024
    });
    if (!parsed.ok) {
      res.status(parsed.status).json({ error: parsed.error });
      return;
    }

    // Back up existing background files before replacing
    backupDirFiles(BRANDING_BG_DIR, 'bg');

    const fileName = `login-bg-${Date.now()}.${parsed.ext}`;
    fs.writeFileSync(path.join(BRANDING_BG_DIR, fileName), parsed.buffer);

    const store = readSecurityStore();
    store.publicBranding = {
      ...store.publicBranding,
      loginBg: `/api/branding/bg-media/${fileName}`,
      loginBgType: 'image'
    };
    writeSecurityStore(store);

    res.json({ success: true, loginBg: store.publicBranding.loginBg, publicBranding: store.publicBranding });
  };

  const handleDeleteOrRestoreLoginBg = (req: AuthedRequest, res: Response) => {
    backupDirFiles(BRANDING_BG_DIR, 'bg');
    const mode = String(req.query.mode || 'delete');
    const nextBg = mode === 'restore' ? defaultLoginBg : '';

    const store = readSecurityStore();
    store.publicBranding = {
      ...store.publicBranding,
      loginBg: nextBg,
      loginBgType: 'image'
    };
    writeSecurityStore(store);

    res.json({ success: true, publicBranding: store.publicBranding });
  };

  app.post('/api/admin/branding/login-bg', requireBrandingAdmin, uploadBgRawMiddleware, handleUploadLoginBg);
  app.post('/api/admin/login-bg', requireBrandingAdmin, uploadBgRawMiddleware, handleUploadLoginBg);

  app.delete('/api/admin/branding/login-bg', requireBrandingAdmin, handleDeleteOrRestoreLoginBg);
  app.delete('/api/admin/login-bg', requireBrandingAdmin, handleDeleteOrRestoreLoginBg);

  app.post('/api/admin/branding/login-bg/restore', requireBrandingAdmin, (_req: AuthedRequest, res: Response) => {
    backupDirFiles(BRANDING_BG_DIR, 'bg');
    const store = readSecurityStore();
    store.publicBranding = {
      ...store.publicBranding,
      loginBg: defaultLoginBg,
      loginBgType: 'image'
    };
    writeSecurityStore(store);
    res.json({ success: true, publicBranding: store.publicBranding });
  });

  // Admin User Management & Messaging Auto-Sync
  app.get('/api/admin/users', requireAdmin, (_req: AuthedRequest, res: Response) => {
    const store = readSecurityStore();
    res.json({ users: store.users.map(sanitizeUser) });
  });

  app.post('/api/admin/users', requireAdmin, (req: AuthedRequest, res: Response) => {
    const {
      name,
      email,
      role = 'Standard Staff',
      username,
      mobile = '',
      whatsappConsent = true,
      messagingEnabled = true,
      brandingAuthorized = false,
      customPermissions,
      status = 'Active',
      password
    } = req.body || {};

    const normEmail = String(email || '').trim().toLowerCase();
    if (!name || !normEmail) {
      res.status(400).json({ error: 'Name and Email ID are required.' });
      return;
    }

    const store = readSecurityStore();
    if (store.users.some(u => u.email.toLowerCase() === normEmail)) {
      res.status(409).json({ error: 'A user with this Email ID already exists.' });
      return;
    }

    const actorIsMain = isMainAdmin(req.authUser);
    const assignedRole = role as UserRole;
    const allowBranding = actorIsMain && isAdminRole(assignedRole) && Boolean(brandingAuthorized);

    const plainPass = String(password || 'Pass@1234');
    const newUser: User = {
      id: `usr_${Date.now()}_${crypto.randomBytes(2).toString('hex')}`,
      name: String(name).trim(),
      email: normEmail,
      role: assignedRole,
      username: String(username || normEmail.split('@')[0]).trim(),
      mobile: String(mobile).trim(),
      whatsappConsent: Boolean(whatsappConsent),
      messagingEnabled: Boolean(messagingEnabled),
      brandingAuthorized: allowBranding,
      customPermissions: customPermissions || undefined,
      status: status === 'Inactive' ? 'Inactive' : 'Active',
      passwordHash: hashPassword(plainPass),
      createdAt: new Date().toISOString().split('T')[0]
    };

    store.users.push(newUser);
    writeSecurityStore(store);

    broadcastAllAuthenticated('chat:user_updated', { user: sanitizeUser(newUser) });
    res.status(201).json({ user: sanitizeUser(newUser) });
  });

  app.put('/api/admin/users/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
    const { id } = req.params;
    const updates = req.body || {};
    const store = readSecurityStore();
    const idx = store.users.findIndex(u => u.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const existing = store.users[idx];
    const actorIsMain = isMainAdmin(req.authUser);

    if (isMainAdmin(existing) && !actorIsMain) {
      res.status(403).json({
        error: '403 Forbidden: Only the permanent Main Admin account can modify its own profile.'
      });
      return;
    }

    const nextRole = updates.role !== undefined ? (updates.role as UserRole) : existing.role;
    let nextBrandingAuth = Boolean(existing.brandingAuthorized);
    if (actorIsMain && updates.brandingAuthorized !== undefined) {
      nextBrandingAuth = isAdminRole(nextRole) && Boolean(updates.brandingAuthorized);
    } else if (!isAdminRole(nextRole)) {
      nextBrandingAuth = false;
    }

    const passwordChanged =
      typeof updates.password === 'string' && updates.password.trim().length > 0 && !isMainAdmin(existing);

    const nextPasswordHash = passwordChanged
      ? hashPassword(String(updates.password).trim())
      : existing.passwordHash;

    const updatedUser: User = {
      ...existing,
      name: updates.name !== undefined ? String(updates.name).trim() : existing.name,
      email:
        updates.email !== undefined && !isMainAdmin(existing)
          ? String(updates.email).trim().toLowerCase()
          : existing.email,
      role: isMainAdmin(existing) ? 'Super Admin' : nextRole,
      username: updates.username !== undefined ? String(updates.username).trim() : existing.username,
      mobile: updates.mobile !== undefined ? String(updates.mobile).trim() : existing.mobile,
      whatsappConsent:
        updates.whatsappConsent !== undefined
          ? Boolean(updates.whatsappConsent)
          : existing.whatsappConsent,
      messagingEnabled:
        isMainAdmin(existing)
          ? true
          : updates.messagingEnabled !== undefined
          ? Boolean(updates.messagingEnabled)
          : existing.messagingEnabled,
      brandingAuthorized: isMainAdmin(existing) ? true : nextBrandingAuth,
      customPermissions:
        updates.customPermissions !== undefined
          ? updates.customPermissions
          : existing.customPermissions,
      status: isMainAdmin(existing)
        ? 'Active'
        : updates.status !== undefined
        ? updates.status
        : existing.status,
      passwordHash: nextPasswordHash,
      tokenVersion:
        passwordChanged || updates.status === 'Inactive'
          ? (existing.tokenVersion || 1) + 1
          : existing.tokenVersion || 1
    };

    store.users[idx] = updatedUser;
    writeSecurityStore(store);

    if (updatedUser.status === 'Inactive' || updatedUser.messagingEnabled === false || passwordChanged) {
      disconnectUserSockets(updatedUser.id, 'Session updated by Administrator');
    }
    broadcastAllAuthenticated('chat:user_updated', { user: sanitizeUser(updatedUser) });

    res.json({ user: sanitizeUser(updatedUser) });
  });

  // Helper to clean up chat groups, disconnect sockets, and broadcast deletions while preserving historical records
  function cleanupDeletedUsers(deletedIds: string[]) {
    if (deletedIds.length === 0) return;
    const deletedSet = new Set(deletedIds);

    for (const uid of deletedIds) {
      disconnectUserSockets(uid, 'Account deleted');
    }

    const chatStore = readChatStore();
    let groupsChanged = false;
    const updatedGroups: ChatGroup[] = [];

    for (const grp of chatStore.groups) {
      const hadDeleted =
        grp.members.some(m => deletedSet.has(m)) ||
        (grp.admins || []).some(a => deletedSet.has(a)) ||
        deletedSet.has(grp.createdBy);
      if (hadDeleted) {
        groupsChanged = true;
        const nextMembers = grp.members.filter(m => !deletedSet.has(m));
        const nextAdmins = (grp.admins || [grp.createdBy]).filter(
          a => !deletedSet.has(a) && nextMembers.includes(a)
        );
        const nextMuted = (grp.mutedBy || []).filter(m => !deletedSet.has(m));
        const nextCreator = !deletedSet.has(grp.createdBy)
          ? grp.createdBy
          : nextAdmins[0] || nextMembers[0] || grp.createdBy;
        if (nextMembers.length > 0) {
          updatedGroups.push({
            ...grp,
            createdBy: nextCreator,
            admins: nextAdmins.length > 0 ? nextAdmins : [nextMembers[0]],
            members: nextMembers,
            mutedBy: nextMuted
          });
        }
        // If 0 members remain, remove empty active group shell while keeping historical messages intact
      } else {
        updatedGroups.push(grp);
      }
    }

    if (groupsChanged) {
      chatStore.groups = updatedGroups;
      writeChatStore(chatStore);
      for (const grp of updatedGroups) {
        sendToUsers(grp.members, 'chat:group_updated', { group: grp });
      }
    }

    broadcastAllAuthenticated('chat:user_updated', { deletedUserIds: deletedIds });
  }

  // Secure Password Reset (Invalidates existing tokens immediately)
  app.post('/api/admin/users/:id/reset-password', requireAdmin, (req: AuthedRequest, res: Response) => {
    const { id } = req.params;
    const newPassword = String(req.body?.newPassword || '').trim();
    if (newPassword.length < 6) {
      res.status(400).json({ error: 'New password must be at least 6 characters long.' });
      return;
    }

    const store = readSecurityStore();
    const idx = store.users.findIndex(u => u.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const target = store.users[idx];
    if (isMainAdmin(target)) {
      res.status(403).json({
        error: '403 Forbidden: Protected Main Admin account credentials cannot be overwritten via reset.'
      });
      return;
    }

    const updatedUser: User = {
      ...target,
      passwordHash: hashPassword(newPassword),
      tokenVersion: (target.tokenVersion || 1) + 1
    };
    store.users[idx] = updatedUser;
    writeSecurityStore(store);

    disconnectUserSockets(updatedUser.id, 'Password reset by Admin');
    res.json({ success: true, user: sanitizeUser(updatedUser) });
  });

  app.delete('/api/admin/users/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
    const { id } = req.params;
    const store = readSecurityStore();
    const target = store.users.find(u => u.id === id);
    if (!target) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }
    if (isMainAdmin(target)) {
      res.status(403).json({ error: 'Protected Main Admin account cannot be deleted.' });
      return;
    }
    if (target.id === req.authUser?.id) {
      res.status(400).json({ error: 'You cannot delete your own active session account.' });
      return;
    }
    if (isAdminRole(target.role) && !isMainAdmin(req.authUser)) {
      res.status(403).json({ error: 'Only the permanent Main Admin can delete Admin accounts.' });
      return;
    }

    store.users = store.users.filter(u => u.id !== id);
    writeSecurityStore(store);

    cleanupDeletedUsers([id]);
    res.json({ success: true, deletedId: id });
  });

  // Bulk Delete Selected Multiple Users (Never deletes Protected Main Admin)
  app.post('/api/admin/users/bulk-delete', requireAdmin, (req: AuthedRequest, res: Response) => {
    const ids: string[] = Array.isArray(req.body?.ids) ? req.body.ids.map(String) : [];
    if (ids.length === 0) {
      res.status(400).json({ error: 'Select at least one user account to delete.' });
      return;
    }

    const store = readSecurityStore();
    const actorIsMain = isMainAdmin(req.authUser);
    const idSet = new Set(ids);
    const deletedIds: string[] = [];

    for (const u of store.users) {
      if (!idSet.has(u.id)) continue;
      if (isMainAdmin(u)) continue; // Strict permanent protection
      if (u.id === req.authUser?.id) continue; // Cannot self-delete
      if (isAdminRole(u.role) && !actorIsMain) continue; // Non-main admins cannot delete other admins
      deletedIds.push(u.id);
    }

    if (deletedIds.length === 0) {
      res.status(403).json({ error: 'No eligible user accounts can be deleted with your authorization.' });
      return;
    }

    const deletedSet = new Set(deletedIds);
    store.users = store.users.filter(u => !deletedSet.has(u.id));
    writeSecurityStore(store);

    cleanupDeletedUsers(deletedIds);
    res.json({
      success: true,
      deletedCount: deletedIds.length,
      deletedIds,
      users: store.users.map(sanitizeUser)
    });
  });

  // Delete ALL Users Except Protected Main Admin (Main Admin Only)
  app.post('/api/admin/users/delete-all-other', requireAuth, (req: AuthedRequest, res: Response) => {
    if (!isMainAdmin(req.authUser)) {
      res.status(403).json({
        error: '403 Forbidden: Only the permanent Main Admin account can execute Delete All Users.'
      });
      return;
    }

    const confirmation = String(req.body?.confirmPhrase || '').trim().toUpperCase();
    if (confirmation !== 'DELETE ALL USERS') {
      res.status(400).json({
        error: 'Explicit confirmation phrase "DELETE ALL USERS" is required.'
      });
      return;
    }

    const store = readSecurityStore();
    const deletedIds = store.users.filter(u => !isMainAdmin(u)).map(u => u.id);
    store.users = store.users.filter(u => isMainAdmin(u));
    writeSecurityStore(store);

    cleanupDeletedUsers(deletedIds);
    res.json({
      success: true,
      deletedCount: deletedIds.length,
      deletedIds,
      users: store.users.map(sanitizeUser)
    });
  });

  // Automatically sync Office Staff Management entries with Messaging & Login accounts
  app.post('/api/admin/sync-staff', requireAdmin, (req: AuthedRequest, res: Response) => {
    const staffList = Array.isArray(req.body?.staffList) ? req.body.staffList : [];
    const store = readSecurityStore();
    let changed = false;

    for (const s of staffList) {
      const email = String(s?.email || '').trim().toLowerCase();
      if (!email) continue;
      const desiredStatus: 'Active' | 'Inactive' = s.status === 'Active' ? 'Active' : 'Inactive';
      const idx = store.users.findIndex(u => u.email.toLowerCase() === email);

      if (idx === -1) {
        const newStaffUser: User = {
          id: `usr_stf_${s.id || Date.now()}`,
          name: String(s.staffName || email.split('@')[0]),
          email,
          role: 'Office Staff',
          username: email.split('@')[0],
          mobile: String(s.mobileNumber || ''),
          whatsappConsent: true,
          messagingEnabled: desiredStatus === 'Active',
          status: desiredStatus,
          passwordHash: hashPassword('Staff@1234'),
          createdAt: new Date().toISOString().split('T')[0]
        };
        store.users.push(newStaffUser);
        changed = true;
      } else if (!isAdminRole(store.users[idx].role)) {
        const current = store.users[idx];
        if (
          current.name !== String(s.staffName || current.name) ||
          current.mobile !== String(s.mobileNumber || current.mobile) ||
          current.status !== desiredStatus
        ) {
          store.users[idx] = {
            ...current,
            name: String(s.staffName || current.name),
            mobile: String(s.mobileNumber || current.mobile),
            status: desiredStatus,
            messagingEnabled: desiredStatus === 'Active' ? current.messagingEnabled !== false : false
          };
          if (desiredStatus === 'Inactive') {
            disconnectUserSockets(current.id, 'Staff deactivated');
          }
          changed = true;
        }
      }
    }

    if (changed) {
      writeSecurityStore(store);
      broadcastAllAuthenticated('chat:user_updated', { synced: true });
    }
    res.json({ users: store.users.map(sanitizeUser) });
  });

  app.get('/api/admin/permissions', requireAdmin, (_req: AuthedRequest, res: Response) => {
    const store = readSecurityStore();
    res.json({ rolePermissions: store.rolePermissions });
  });

  app.put('/api/admin/permissions', requireAdmin, (req: AuthedRequest, res: Response) => {
    const { role, perms } = req.body || {};
    if (!role || !perms) {
      res.status(400).json({ error: 'Role and permissions payload required.' });
      return;
    }
    const store = readSecurityStore();
    store.rolePermissions = {
      ...store.rolePermissions,
      [role as UserRole]: {
        ...(store.rolePermissions[role as UserRole] || store.rolePermissions['Standard Staff']),
        ...perms
      }
    };
    writeSecurityStore(store);
    res.json({ rolePermissions: store.rolePermissions });
  });

  // =========================================================================
  // INTERNAL WHATSAPP-STYLE MESSAGING API (SERVER-AUTHORITATIVE & STRICT PRIVACY)
  // =========================================================================

  function getConversationParticipants(
    conversationKey: string,
    groups: ChatGroup[]
  ): string[] {
    if (conversationKey.startsWith('private:')) {
      return conversationKey.slice('private:'.length).split('__').filter(Boolean);
    }
    if (conversationKey.startsWith('group:')) {
      const gid = conversationKey.slice('group:'.length);
      const grp = groups.find(g => g.id === gid);
      return grp ? grp.members : [];
    }
    return [];
  }

  app.get('/api/chat/bootstrap', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    if (me.messagingEnabled === false) {
      res.status(403).json({ error: 'Your messaging access has been deactivated by Admin.' });
      return;
    }

    const secStore = readSecurityStore();
    const chatStore = readChatStore();
    const onlineSet = new Set(getOnlineUserIds());

    const messagingUsers: MessagingUserSummary[] = secStore.users
      .filter(u => u.status === 'Active' && u.messagingEnabled !== false)
      .map(u => ({
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.role,
        status: u.status,
        messagingEnabled: u.messagingEnabled !== false,
        online: onlineSet.has(u.id) || u.id === me.id
      }));

    // Strictly return only groups where this user is a member
    const visibleGroups = chatStore.groups
      .filter(g => g.members.includes(me.id))
      .map(g => ({
        ...g,
        admins: Array.isArray(g.admins) && g.admins.length > 0 ? g.admins : [g.createdBy]
      }));

    // Strictly return only messages for private chats involving me or groups I belong to,
    // excluding messages this user explicitly chose "Delete for Me" on.
    const visibleMessages = chatStore.messages.filter(
      m =>
        canUserAccessConversation(me, m.conversationKey, chatStore.groups) &&
        !(m.deletedFor || []).includes(me.id)
    );

    // Mark incoming messages as delivered
    let deliveredChanged = false;
    const deliveredIds: string[] = [];
    const senderIds = new Set<string>();
    for (const m of visibleMessages) {
      if (m.senderId !== me.id && !m.deliveredTo.includes(me.id)) {
        m.deliveredTo.push(me.id);
        deliveredIds.push(m.id);
        senderIds.add(m.senderId);
        deliveredChanged = true;
      }
    }
    if (deliveredChanged) {
      writeChatStore(chatStore);
      sendToUsers(Array.from(senderIds), 'chat:delivery_receipt', {
        userId: me.id,
        messageIds: deliveredIds
      });
    }

    res.json({
      users: messagingUsers,
      groups: visibleGroups,
      messages: visibleMessages,
      onlineUserIds: Array.from(onlineSet)
    });
  });

  app.post('/api/chat/attachments', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    if (me.messagingEnabled === false) {
      res.status(403).json({ error: 'Your messaging access has been deactivated by Admin.' });
      return;
    }

    const { fileName, mimeType, base64Data, conversationKey } = req.body || {};
    const cleanName = path.basename(String(fileName || 'attachment')).replace(/[^\w.\- ()]/g, '_');
    const ext = path.extname(cleanName).toLowerCase();

    if (!ALLOWED_ATTACHMENT_EXTS.has(ext)) {
      res.status(400).json({
        error:
          'Unsupported attachment file type. Permitted: Images, Videos (MP4/WEBM/MOV), PDF, Excel, Word, PowerPoint, CSV, TXT, ZIP.'
      });
      return;
    }

    const chatStore = readChatStore();
    if (!canUserAccessConversation(me, String(conversationKey || ''), chatStore.groups)) {
      res.status(403).json({ error: 'Forbidden: You are not a participant in this conversation.' });
      return;
    }

    const rawBase64 = String(base64Data || '').includes(',')
      ? String(base64Data).split(',')[1]
      : String(base64Data || '');
    const buffer = Buffer.from(rawBase64, 'base64');
    if (buffer.length === 0 || buffer.length > 25 * 1024 * 1024) {
      res.status(400).json({ error: 'Attachment must be between 1 byte and 25MB.' });
      return;
    }

    const fileId = `att_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const storedFileName = `${fileId}${ext}`;
    fs.writeFileSync(path.join(CHAT_UPLOADS_DIR, storedFileName), buffer);

    const meta: StoredAttachmentMeta = {
      id: fileId,
      storedFileName,
      fileName: cleanName,
      mimeType: String(mimeType || 'application/octet-stream'),
      size: buffer.length,
      conversationKey: String(conversationKey),
      uploadedBy: me.id,
      createdAt: new Date().toISOString()
    };

    chatStore.attachments[fileId] = meta;
    writeChatStore(chatStore);

    const attachment: ChatAttachment = {
      id: fileId,
      fileName: cleanName,
      mimeType: meta.mimeType,
      size: meta.size,
      url: `/api/chat/attachments/${fileId}`
    };

    res.status(201).json({ attachment });
  });

  app.get('/api/chat/attachments/:fileId', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const { fileId } = req.params;
    const chatStore = readChatStore();
    const meta = chatStore.attachments[fileId];
    if (!meta) {
      res.status(404).json({ error: 'Attachment not found.' });
      return;
    }

    // Strict participant verification on backend (Admin cannot read private attachments unless participant)
    if (!canUserAccessConversation(me, meta.conversationKey, chatStore.groups)) {
      res.status(403).json({ error: '403 Forbidden: You do not have permission to access this file.' });
      return;
    }

    const fullPath = path.join(CHAT_UPLOADS_DIR, meta.storedFileName);
    if (!fs.existsSync(fullPath)) {
      res.status(404).json({ error: 'File missing on server.' });
      return;
    }

    res.setHeader('Content-Type', meta.mimeType);
    res.setHeader('Content-Disposition', `inline; filename="${meta.fileName}"`);
    res.sendFile(fullPath);
  });

  app.post('/api/chat/messages', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    if (me.messagingEnabled === false) {
      res.status(403).json({ error: 'Messaging access has been disabled for your account.' });
      return;
    }

    const { type, recipientId, groupId, text = '', attachment, replyToId } = req.body || {};
    const cleanText = String(text || '').trim();
    if (!cleanText && !attachment) {
      res.status(400).json({ error: 'Message text or attachment is required.' });
      return;
    }

    const secStore = readSecurityStore();
    const chatStore = readChatStore();
    const onlineSet = new Set(getOnlineUserIds());
    let conversationKey = '';
    let targetUserIds: string[] = [];

    if (type === 'private') {
      const targetUser = secStore.users.find(
        u => u.id === recipientId && u.status === 'Active' && u.messagingEnabled !== false
      );
      if (!targetUser) {
        res.status(404).json({ error: 'Recipient user is inactive or unavailable.' });
        return;
      }
      conversationKey = getPrivateConversationKey(me.id, targetUser.id);
      targetUserIds = [me.id, targetUser.id];
    } else if (type === 'group') {
      const group = chatStore.groups.find(g => g.id === groupId);
      if (!group) {
        res.status(404).json({ error: 'Group not found.' });
        return;
      }
      if (!group.members.includes(me.id)) {
        res.status(403).json({ error: 'Forbidden: You are not a member of this group.' });
        return;
      }
      conversationKey = getGroupConversationKey(group.id);
      targetUserIds = group.members;
    } else {
      res.status(400).json({ error: 'Invalid conversation type.' });
      return;
    }

    let replyTo: ChatReplyPreview | undefined;
    if (replyToId) {
      const refMsg = chatStore.messages.find(
        m =>
          m.id === String(replyToId) &&
          m.conversationKey === conversationKey &&
          !(m.deletedFor || []).includes(me.id)
      );
      if (refMsg) {
        replyTo = {
          id: refMsg.id,
          senderId: refMsg.senderId,
          senderName: refMsg.senderName,
          text: refMsg.deletedForEveryone ? 'This message was deleted' : refMsg.text,
          attachmentName: refMsg.deletedForEveryone ? undefined : refMsg.attachment?.fileName,
          attachmentMimeType: refMsg.deletedForEveryone ? undefined : refMsg.attachment?.mimeType
        };
      }
    }

    const deliveredTo = [me.id];
    for (const uid of targetUserIds) {
      if (uid !== me.id && onlineSet.has(uid)) {
        deliveredTo.push(uid);
      }
    }

    const newMessage: ChatMessage = {
      id: `msg_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      conversationKey,
      type,
      senderId: me.id,
      senderName: me.name,
      recipientId: type === 'private' ? String(recipientId) : undefined,
      groupId: type === 'group' ? String(groupId) : undefined,
      text: cleanText,
      attachment: attachment || undefined,
      replyTo,
      createdAt: new Date().toISOString(),
      deliveredTo,
      readBy: [me.id]
    };

    chatStore.messages.push(newMessage);
    if (chatStore.messages.length > 5000) {
      chatStore.messages = chatStore.messages.slice(-5000);
    }
    writeChatStore(chatStore);

    // Real-time push STRICTLY to participants of this private chat or group (ZERO Admin surveillance copies)
    sendToUsers(targetUserIds, 'chat:message', newMessage);

    res.status(201).json({ message: newMessage });
  });

  // Edit own message
  app.patch('/api/chat/messages/:id', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const { id } = req.params;
    const cleanText = String(req.body?.text || '').trim();
    if (!cleanText) {
      res.status(400).json({ error: 'Edited message text cannot be empty.' });
      return;
    }

    const chatStore = readChatStore();
    const idx = chatStore.messages.findIndex(m => m.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'Message not found.' });
      return;
    }

    const msg = chatStore.messages[idx];
    if (!canUserAccessConversation(me, msg.conversationKey, chatStore.groups)) {
      res.status(403).json({ error: 'Forbidden.' });
      return;
    }
    if (msg.senderId !== me.id) {
      res.status(403).json({ error: 'You can only edit your own messages.' });
      return;
    }
    if (msg.deletedForEveryone) {
      res.status(400).json({ error: 'Cannot edit a deleted message.' });
      return;
    }

    const updatedMsg: ChatMessage = {
      ...msg,
      text: cleanText,
      editedAt: new Date().toISOString()
    };
    chatStore.messages[idx] = updatedMsg;
    writeChatStore(chatStore);

    const participants = getConversationParticipants(updatedMsg.conversationKey, chatStore.groups);
    sendToUsers(participants, 'chat:message_updated', updatedMsg);
    res.json({ message: updatedMsg });
  });

  // Delete for Me OR Delete for Everyone
  app.delete('/api/chat/messages/:id', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const { id } = req.params;
    const scope = req.query.scope === 'everyone' ? 'everyone' : 'me';

    const chatStore = readChatStore();
    const idx = chatStore.messages.findIndex(m => m.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'Message not found.' });
      return;
    }

    const msg = chatStore.messages[idx];
    if (!canUserAccessConversation(me, msg.conversationKey, chatStore.groups)) {
      res.status(403).json({ error: 'Forbidden.' });
      return;
    }

    if (scope === 'everyone') {
      if (msg.senderId !== me.id) {
        res.status(403).json({ error: 'Only the message sender can Delete for Everyone.' });
        return;
      }
      const updatedMsg: ChatMessage = {
        ...msg,
        text: '',
        attachment: undefined,
        replyTo: undefined,
        deletedForEveryone: true,
        deletedAt: new Date().toISOString()
      };
      chatStore.messages[idx] = updatedMsg;
      writeChatStore(chatStore);

      const participants = getConversationParticipants(updatedMsg.conversationKey, chatStore.groups);
      sendToUsers(participants, 'chat:message_updated', updatedMsg);
      res.json({ success: true, scope: 'everyone', message: updatedMsg });
      return;
    }

    // Scope: Delete for Me (strictly local to caller; zero notifications to others)
    const currentDeletedFor = Array.isArray(msg.deletedFor) ? msg.deletedFor : [];
    if (!currentDeletedFor.includes(me.id)) {
      chatStore.messages[idx] = {
        ...msg,
        deletedFor: [...currentDeletedFor, me.id]
      };
      writeChatStore(chatStore);
    }

    sendToUsers([me.id], 'chat:message_deleted_for_me', { messageId: id, userId: me.id });
    res.json({ success: true, scope: 'me', messageId: id });
  });

  // Multi-Recipient Forwarding (Users & Groups) — strict authorization & zero Admin snooping
  app.post('/api/chat/messages/forward', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    if (me.messagingEnabled === false) {
      res.status(403).json({ error: 'Messaging access disabled for your account.' });
      return;
    }

    const { sourceMessageId, targets } = req.body || {};
    if (!sourceMessageId || !Array.isArray(targets) || targets.length === 0) {
      res.status(400).json({ error: 'Source message ID and at least one target recipient/group are required.' });
      return;
    }
    if (targets.length > 25) {
      res.status(400).json({ error: 'Cannot forward to more than 25 recipients at once.' });
      return;
    }

    const chatStore = readChatStore();
    const secStore = readSecurityStore();
    const source = chatStore.messages.find(m => m.id === String(sourceMessageId));
    if (!source) {
      res.status(404).json({ error: 'Original message not found.' });
      return;
    }
    if (
      !canUserAccessConversation(me, source.conversationKey, chatStore.groups) ||
      (source.deletedFor || []).includes(me.id) ||
      source.deletedForEveryone
    ) {
      res.status(403).json({ error: 'Forbidden: Cannot forward this message.' });
      return;
    }

    const onlineSet = new Set(getOnlineUserIds());
    const createdMessages: ChatMessage[] = [];
    const dispatches: { userIds: string[]; message: ChatMessage }[] = [];

    for (const target of targets) {
      const tType = target?.type;
      const tId = String(target?.id || '');
      let conversationKey = '';
      let participantIds: string[] = [];

      if (tType === 'private') {
        const peer = secStore.users.find(
          u => u.id === tId && u.status === 'Active' && u.messagingEnabled !== false
        );
        if (!peer) continue;
        conversationKey = getPrivateConversationKey(me.id, peer.id);
        participantIds = [me.id, peer.id];
      } else if (tType === 'group') {
        const grp = chatStore.groups.find(g => g.id === tId);
        if (!grp || !grp.members.includes(me.id)) continue;
        conversationKey = getGroupConversationKey(grp.id);
        participantIds = grp.members;
      } else {
        continue;
      }

      // Clone attachment permission metadata scoped to the target conversation (same stored binary)
      let clonedAttachment: ChatAttachment | undefined;
      if (source.attachment) {
        const origMeta = chatStore.attachments[source.attachment.id];
        if (origMeta) {
          const newAttId = `att_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
          chatStore.attachments[newAttId] = {
            ...origMeta,
            id: newAttId,
            conversationKey,
            uploadedBy: me.id,
            createdAt: new Date().toISOString()
          };
          clonedAttachment = {
            ...source.attachment,
            id: newAttId,
            url: `/api/chat/attachments/${newAttId}`
          };
        }
      }

      const deliveredTo = [me.id];
      for (const uid of participantIds) {
        if (uid !== me.id && onlineSet.has(uid)) deliveredTo.push(uid);
      }

      const fwdMsg: ChatMessage = {
        id: `msg_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
        conversationKey,
        type: tType,
        senderId: me.id,
        senderName: me.name,
        recipientId: tType === 'private' ? tId : undefined,
        groupId: tType === 'group' ? tId : undefined,
        text: source.text,
        attachment: clonedAttachment,
        isForwarded: true,
        forwardedFrom: {
          messageId: source.id,
          senderName: source.senderName
        },
        createdAt: new Date().toISOString(),
        deliveredTo,
        readBy: [me.id]
      };

      chatStore.messages.push(fwdMsg);
      createdMessages.push(fwdMsg);
      dispatches.push({ userIds: participantIds, message: fwdMsg });
    }

    if (createdMessages.length === 0) {
      res.status(400).json({ error: 'No valid authorized targets selected for forwarding.' });
      return;
    }

    if (chatStore.messages.length > 5000) {
      chatStore.messages = chatStore.messages.slice(-5000);
    }
    writeChatStore(chatStore);

    // Push strictly to chosen target participants only
    for (const d of dispatches) {
      sendToUsers(d.userIds, 'chat:message', d.message);
    }

    res.status(201).json({ messages: createdMessages });
  });

  app.post('/api/chat/read', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const conversationKey = String(req.body?.conversationKey || '');
    const chatStore = readChatStore();

    if (!canUserAccessConversation(me, conversationKey, chatStore.groups)) {
      res.status(403).json({ error: 'Forbidden.' });
      return;
    }

    const readIds: string[] = [];
    const senderIds = new Set<string>();
    for (const m of chatStore.messages) {
      if (m.conversationKey === conversationKey && !m.readBy.includes(me.id)) {
        m.readBy.push(me.id);
        if (!m.deliveredTo.includes(me.id)) m.deliveredTo.push(me.id);
        readIds.push(m.id);
        senderIds.add(m.senderId);
      }
    }

    if (readIds.length > 0) {
      writeChatStore(chatStore);
      sendToUsers([me.id, ...Array.from(senderIds)], 'chat:read_receipt', {
        conversationKey,
        userId: me.id,
        messageIds: readIds
      });
    }

    res.json({ success: true, readCount: readIds.length });
  });

  // =========================================================================
  // USER GROUP CHAT MANAGEMENT (ANY REGISTERED USER CAN CREATE & MANAGE OWN GROUPS)
  // =========================================================================

  app.post('/api/chat/groups', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    if (me.messagingEnabled === false) {
      res.status(403).json({ error: 'Messaging access disabled.' });
      return;
    }

    const { name, description = '', members = [] } = req.body || {};
    const cleanName = String(name || '').trim();
    if (!cleanName) {
      res.status(400).json({ error: 'Group name is required.' });
      return;
    }

    const secStore = readSecurityStore();
    const activeUserIds = new Set(
      secStore.users.filter(u => u.status === 'Active' && u.messagingEnabled !== false).map(u => u.id)
    );
    const memberSet = new Set<string>([me.id]);
    if (Array.isArray(members)) {
      for (const m of members) {
        if (activeUserIds.has(String(m))) memberSet.add(String(m));
      }
    }

    const group: ChatGroup = {
      id: `grp_${Date.now()}_${crypto.randomBytes(2).toString('hex')}`,
      name: cleanName,
      description: String(description).trim(),
      createdBy: me.id,
      admins: [me.id],
      members: Array.from(memberSet),
      mutedBy: [],
      createdAt: new Date().toISOString()
    };

    const chatStore = readChatStore();
    chatStore.groups.unshift(group);
    writeChatStore(chatStore);

    // Notify ONLY the group's members (NEVER Main Admin unless selected)
    sendToUsers(group.members, 'chat:group_updated', { group });
    res.status(201).json({ group });
  });

  app.patch('/api/chat/groups/:id', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const { id } = req.params;
    const { name, description, members, admins } = req.body || {};
    const chatStore = readChatStore();
    const secStore = readSecurityStore();

    const idx = chatStore.groups.findIndex(g => g.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'Group not found.' });
      return;
    }

    const grp = chatStore.groups[idx];
    const currentAdmins = Array.isArray(grp.admins) && grp.admins.length > 0 ? grp.admins : [grp.createdBy];
    if (!grp.members.includes(me.id) || (grp.createdBy !== me.id && !currentAdmins.includes(me.id))) {
      res.status(403).json({
        error: '403 Forbidden: Only authorized group admins or creator can manage this group.'
      });
      return;
    }

    const activeUserIds = new Set(
      secStore.users.filter(u => u.status === 'Active' && u.messagingEnabled !== false).map(u => u.id)
    );
    const prevMembers = grp.members;
    const nextMembers = Array.isArray(members)
      ? Array.from(new Set(members.map(String).filter(uid => activeUserIds.has(uid) || uid === me.id)))
      : prevMembers;

    if (nextMembers.length === 0) {
      res.status(400).json({ error: 'A group must have at least one active member.' });
      return;
    }

    const nextAdminsRaw = Array.isArray(admins) ? admins.map(String) : currentAdmins;
    const nextAdmins = Array.from(new Set(nextAdminsRaw.filter(uid => nextMembers.includes(uid))));
    if (nextAdmins.length === 0) nextAdmins.push(nextMembers[0]);

    const updatedGroup: ChatGroup = {
      ...grp,
      name: name !== undefined && String(name).trim() ? String(name).trim() : grp.name,
      description: description !== undefined ? String(description).trim() : grp.description,
      members: nextMembers,
      admins: nextAdmins
    };

    chatStore.groups[idx] = updatedGroup;
    writeChatStore(chatStore);

    const affectedUsers = Array.from(new Set([...prevMembers, ...updatedGroup.members]));
    sendToUsers(affectedUsers, 'chat:group_updated', { group: updatedGroup });
    res.json({ group: updatedGroup });
  });

  app.post('/api/chat/groups/:id/leave', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const { id } = req.params;
    const chatStore = readChatStore();
    const idx = chatStore.groups.findIndex(g => g.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'Group not found.' });
      return;
    }
    const grp = chatStore.groups[idx];
    if (!grp.members.includes(me.id)) {
      res.status(403).json({ error: 'You are not a member of this group.' });
      return;
    }

    const nextMembers = grp.members.filter(m => m !== me.id);
    if (nextMembers.length === 0) {
      chatStore.groups = chatStore.groups.filter(g => g.id !== id);
      writeChatStore(chatStore);
      sendToUsers([me.id], 'chat:group_deleted', { groupId: id });
      res.json({ success: true, deleted: true });
      return;
    }

    const nextAdmins = (grp.admins || [grp.createdBy]).filter(a => a !== me.id && nextMembers.includes(a));
    if (nextAdmins.length === 0) nextAdmins.push(nextMembers[0]);
    const updatedGroup: ChatGroup = {
      ...grp,
      createdBy: grp.createdBy === me.id ? nextAdmins[0] : grp.createdBy,
      admins: nextAdmins,
      members: nextMembers,
      mutedBy: (grp.mutedBy || []).filter(m => m !== me.id)
    };
    chatStore.groups[idx] = updatedGroup;
    writeChatStore(chatStore);

    sendToUsers([me.id, ...updatedGroup.members], 'chat:group_updated', { group: updatedGroup });
    res.json({ success: true, group: updatedGroup });
  });

  app.patch('/api/chat/groups/:id/notifications', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const { id } = req.params;
    const muted = Boolean(req.body?.muted);
    const chatStore = readChatStore();
    const idx = chatStore.groups.findIndex(g => g.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'Group not found.' });
      return;
    }
    const grp = chatStore.groups[idx];
    if (!grp.members.includes(me.id)) {
      res.status(403).json({ error: 'Forbidden.' });
      return;
    }
    const mutedSet = new Set(grp.mutedBy || []);
    if (muted) mutedSet.add(me.id);
    else mutedSet.delete(me.id);
    const updatedGroup: ChatGroup = { ...grp, mutedBy: Array.from(mutedSet) };
    chatStore.groups[idx] = updatedGroup;
    writeChatStore(chatStore);
    res.json({ group: updatedGroup });
  });

  app.delete('/api/chat/groups/:id', requireAuth, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const { id } = req.params;
    const chatStore = readChatStore();
    const existing = chatStore.groups.find(g => g.id === id);
    if (!existing) {
      res.status(404).json({ error: 'Group not found.' });
      return;
    }
    const admins = Array.isArray(existing.admins) && existing.admins.length > 0 ? existing.admins : [existing.createdBy];
    if (!existing.members.includes(me.id) || (existing.createdBy !== me.id && !admins.includes(me.id))) {
      res.status(403).json({ error: 'Only the group creator or group admins can delete this group.' });
      return;
    }

    chatStore.groups = chatStore.groups.filter(g => g.id !== id);
    chatStore.messages = chatStore.messages.filter(m => m.groupId !== id);
    writeChatStore(chatStore);

    sendToUsers(existing.members, 'chat:group_deleted', { groupId: id });
    res.json({ success: true });
  });

  // Messaging Admin Control Endpoints (Strictly User Access & Official Group Provisioning — ZERO private message snooping)
  app.get('/api/chat/admin/overview', requireAdmin, (_req: AuthedRequest, res: Response) => {
    const secStore = readSecurityStore();
    const chatStore = readChatStore();
    const onlineSet = new Set(getOnlineUserIds());

    res.json({
      users: secStore.users.map(u => ({
        ...sanitizeUser(u),
        online: onlineSet.has(u.id)
      })),
      // Only return groups where caller is a member to enforce strict privacy
      groups: chatStore.groups.filter(g => g.members.includes(_req.authUser!.id)),
      totalUsers: secStore.users.length
    });
  });

  app.patch('/api/chat/admin/users/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
    const { id } = req.params;
    const { messagingEnabled } = req.body || {};
    const secStore = readSecurityStore();
    const idx = secStore.users.findIndex(u => u.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }
    if (isMainAdmin(secStore.users[idx]) && !messagingEnabled) {
      res.status(403).json({ error: 'Protected Main Admin messaging access cannot be disabled.' });
      return;
    }
    secStore.users[idx] = {
      ...secStore.users[idx],
      messagingEnabled: Boolean(messagingEnabled)
    };
    writeSecurityStore(secStore);

    if (!messagingEnabled) {
      disconnectUserSockets(id, 'Messaging deactivated by Admin');
    }
    broadcastAllAuthenticated('chat:user_updated', { user: sanitizeUser(secStore.users[idx]) });

    res.json({ user: sanitizeUser(secStore.users[idx]) });
  });

  app.post('/api/chat/admin/groups', requireAdmin, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const { name, description = '', members = [] } = req.body || {};
    const cleanName = String(name || '').trim();
    if (!cleanName) {
      res.status(400).json({ error: 'Group name is required.' });
      return;
    }

    const memberSet = new Set<string>([me.id, ...(Array.isArray(members) ? members.map(String) : [])]);
    const group: ChatGroup = {
      id: `grp_${Date.now()}_${crypto.randomBytes(2).toString('hex')}`,
      name: cleanName,
      description: String(description).trim(),
      createdBy: me.id,
      admins: [me.id],
      members: Array.from(memberSet),
      mutedBy: [],
      createdAt: new Date().toISOString()
    };

    const chatStore = readChatStore();
    chatStore.groups.unshift(group);
    writeChatStore(chatStore);

    sendToUsers(group.members, 'chat:group_updated', { group });
    res.status(201).json({ group });
  });

  app.patch('/api/chat/admin/groups/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const { id } = req.params;
    const { name, description, members } = req.body || {};
    const chatStore = readChatStore();
    const idx = chatStore.groups.findIndex(g => g.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'Group not found.' });
      return;
    }

    const existing = chatStore.groups[idx];
    if (!existing.members.includes(me.id)) {
      res.status(403).json({ error: 'Forbidden: Only group members can modify this group.' });
      return;
    }

    const prevMembers = existing.members;
    const updatedGroup: ChatGroup = {
      ...existing,
      name: name !== undefined ? String(name).trim() : existing.name,
      description: description !== undefined ? String(description).trim() : existing.description,
      members: Array.isArray(members) ? Array.from(new Set(members.map(String))) : prevMembers
    };

    chatStore.groups[idx] = updatedGroup;
    writeChatStore(chatStore);

    const affectedUsers = Array.from(new Set([...prevMembers, ...updatedGroup.members]));
    sendToUsers(affectedUsers, 'chat:group_updated', { group: updatedGroup });

    res.json({ group: updatedGroup });
  });

  app.delete('/api/chat/admin/groups/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
    const me = req.authUser!;
    const { id } = req.params;
    const chatStore = readChatStore();
    const existing = chatStore.groups.find(g => g.id === id);
    if (!existing) {
      res.status(404).json({ error: 'Group not found.' });
      return;
    }
    if (!existing.members.includes(me.id)) {
      res.status(403).json({ error: 'Forbidden: Only group members can delete this group.' });
      return;
    }

    chatStore.groups = chatStore.groups.filter(g => g.id !== id);
    chatStore.messages = chatStore.messages.filter(m => m.groupId !== id);
    writeChatStore(chatStore);

    sendToUsers(existing.members, 'chat:group_deleted', { groupId: id });
    res.json({ success: true });
  });

  // =========================================================================
  // LEGACY NOTIFICATIONS ENDPOINTS (RBAC-HARDENED WITH BEARER TOKEN)
  // =========================================================================

  app.get('/api/notifications/whatsapp/status', requireAdmin, (_req: AuthedRequest, res: Response) => {
    const cfg = getWhatsAppEnvConfig();
    res.json({
      configured: cfg.configured,
      phoneNumberIdConfigured: Boolean(cfg.phoneNumberId),
      accessTokenConfigured: Boolean(cfg.accessToken),
      businessAccountIdConfigured: Boolean(cfg.businessAccountId),
      apiVersion: cfg.apiVersion
    });
  });

  app.get('/api/notifications/inbox', requireAuth, (req: AuthedRequest, res: Response) => {
    const userId = req.authUser!.id;
    const store = ensureStore();
    const userNotifications = store.notifications
      .filter(n => n.recipientUserId === userId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    res.json({ notifications: userNotifications });
  });

  app.get('/api/notifications/admin/history', requireAdmin, (_req: AuthedRequest, res: Response) => {
    const store = ensureStore();
    const sorted = [...store.notifications].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    res.json({ history: sorted });
  });

  app.post('/api/notifications/send', requireAdmin, async (req: AuthedRequest, res: Response) => {
    const sender = req.authUser!;
    const {
      title,
      message,
      priority = 'Normal',
      category = 'general',
      channel = 'website',
      recipients,
      linkModule
    } = req.body || {};

    if (!title || !message || !Array.isArray(recipients) || recipients.length === 0) {
      res.status(400).json({ error: 'Title, message, and at least one target recipient are required.' });
      return;
    }

    const validChannel: NotificationChannel =
      channel === 'whatsapp' || channel === 'both' ? channel : 'website';
    const validPriority: NotificationPriority =
      priority === 'Low' || priority === 'High' || priority === 'Urgent' ? priority : 'Normal';

    const cfg = getWhatsAppEnvConfig();
    const batchId = `batch_${Date.now()}`;
    const createdAt = new Date().toISOString();
    const createdRecords: StoredNotificationRecord[] = [];

    for (const r of recipients) {
      if (!r?.id || !r?.name) continue;
      const recipientMobile = String(r.mobile || '').trim();
      let whatsappStatus: WhatsAppDeliveryStatus = 'Not Applicable';
      let whatsappMessageId: string | undefined;
      let whatsappError: string | undefined;

      if (validChannel === 'whatsapp' || validChannel === 'both') {
        if (!r.whatsappConsent) {
          whatsappStatus = 'Skipped (No Consent)';
          whatsappError = 'Recipient has not opted in to WhatsApp notifications.';
        } else {
          const normalizedPhone = normalizeWhatsAppPhone(recipientMobile);
          if (!normalizedPhone) {
            whatsappStatus = 'Skipped (Invalid Phone)';
            whatsappError = 'Recipient phone number is missing or invalid.';
          } else if (!cfg.configured) {
            whatsappStatus = 'Skipped (Missing API Config)';
            whatsappError =
              'WhatsApp Business Cloud API credentials (WHATSAPP_ACCESS_TOKEN & WHATSAPP_PHONE_NUMBER_ID) are not configured.';
          } else {
            const waRes = await sendRealWhatsAppTextMessage(
              normalizedPhone,
              String(title).trim(),
              String(message).trim(),
              validPriority
            );
            if (waRes.ok) {
              whatsappStatus = 'Sent';
              whatsappMessageId = waRes.messageId;
            } else {
              whatsappStatus = 'Failed';
              whatsappError = waRes.error;
            }
          }
        }
      }

      const record: StoredNotificationRecord = {
        id: `pnotif_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        batchId,
        title: String(title).trim(),
        message: String(message).trim(),
        priority: validPriority,
        category: category as NotificationCategory,
        channel: validChannel,
        senderId: sender.id,
        senderName: sender.name,
        recipientUserId: String(r.id),
        recipientName: String(r.name),
        recipientRole: String(r.role || 'Staff'),
        recipientMobile,
        read: false,
        whatsappStatus,
        whatsappMessageId,
        whatsappError,
        createdAt,
        linkModule: linkModule ? String(linkModule) : undefined
      };
      createdRecords.push(record);
    }

    const store = ensureStore();
    store.notifications = [...createdRecords, ...store.notifications].slice(0, 1500);
    writeStore(store);

    res.status(201).json({
      success: true,
      batchId,
      summary: {
        totalRecipients: createdRecords.length,
        whatsappSent: createdRecords.filter(r => r.whatsappStatus === 'Sent').length,
        whatsappFailed: createdRecords.filter(r => r.whatsappStatus === 'Failed').length,
        whatsappSkipped: createdRecords.filter(r => r.whatsappStatus.startsWith('Skipped')).length
      },
      records: createdRecords
    });
  });

  app.patch('/api/notifications/:id/read', requireAuth, (req: AuthedRequest, res: Response) => {
    const userId = req.authUser!.id;
    const { id } = req.params;
    const store = ensureStore();
    const idx = store.notifications.findIndex(n => n.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'Notification not found.' });
      return;
    }
    if (store.notifications[idx].recipientUserId !== userId) {
      res.status(403).json({ error: 'Forbidden: Cannot modify another user notification.' });
      return;
    }

    store.notifications[idx] = {
      ...store.notifications[idx],
      read: true,
      readAt: new Date().toISOString()
    };
    writeStore(store);
    res.json({ success: true, notification: store.notifications[idx] });
  });

  app.patch('/api/notifications/read-all', requireAuth, (req: AuthedRequest, res: Response) => {
    const userId = req.authUser!.id;
    const now = new Date().toISOString();
    const store = ensureStore();
    let updatedCount = 0;
    store.notifications = store.notifications.map(n => {
      if (n.recipientUserId === userId && !n.read) {
        updatedCount += 1;
        return { ...n, read: true, readAt: now };
      }
      return n;
    });
    writeStore(store);
    res.json({ success: true, updatedCount });
  });

  // Mount Vite in dev or serve built assets in production
  if (process.env.NODE_ENV !== 'production') {
    const vitePromise: Promise<ViteDevServer> = createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR === 'true' ? false : { server: httpServer }
      },
      appType: 'spa'
    });

    app.use(async (req: Request, res: Response, next: NextFunction) => {
      try {
        const vite = await vitePromise;
        vite.middlewares(req, res, next);
      } catch (err) {
        next(err);
      }
    });
  } else {
    const distDir = path.join(ROOT_DIR, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`S-TRANZ Fleet ERP server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
