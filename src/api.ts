import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import WebSocket from 'ws';
import * as db from './database';
import { encodeGuacArray, vmConnections } from './index';

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const JWT_EXPIRY = '7d';

let apiSecret: string = '';

function verifyApiSecret(req: express.Request, res: express.Response, next: express.NextFunction) {
  const secret = req.headers['x-api-secret'] as string;

  if (!secret || secret !== apiSecret) {
    return res.status(401).json({ error: 'Invalid or missing API secret' });
  }
  next();
}

interface AuthRequest extends express.Request {
  user?: {
    id: number;
    username: string;
    is_admin: boolean;
    is_moderator: boolean;
  };
}

function authenticateToken(req: AuthRequest, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user as { id: number; username: string; is_admin: boolean; is_moderator: boolean };
    next();
  });
}

function requireAdmin(req: AuthRequest, res: express.Response, next: express.NextFunction) {
  if (!req.user || !req.user.is_admin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

function requireAdminOrMod(req: AuthRequest, res: express.Response, next: express.NextFunction) {
  if (!req.user || (!req.user.is_admin && !req.user.is_moderator)) {
    return res.status(403).json({ error: 'Admin or moderator access required' });
  }
  next();
}

app.post('/api/register', verifyApiSecret, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const existingUser = await db.getUserByUsername(username) || await db.getUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await db.createUser(username, email, passwordHash);

    const { password_hash, ...userWithoutPassword } = user;
    res.status(201).json({ user: userWithoutPassword });
  } catch (error: any) {
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message || 'Registration failed' });
  }
});

app.post('/api/login', verifyApiSecret, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Missing username or password' });
    }

    const user = await db.getUserByUsername(username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.is_blocked) {
      return res.status(403).json({ error: 'Account is blocked' });
    }

    if (!user.is_verified) {
      return res.status(403).json({ error: 'Account not verified. Please wait for an administrator to verify your account.' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, is_admin: user.is_admin, is_moderator: user.is_moderator },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    const { password_hash, ...userWithoutPassword } = user;
    res.json({ token, user: userWithoutPassword });
  } catch (error: any) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message || 'Login failed' });
  }
});

app.get('/api/me', verifyApiSecret, authenticateToken, async (req: AuthRequest, res) => {
  try {
    const user = await db.getUserById(req.user!.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const { password_hash, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword });
  } catch (error: any) {
    console.error('Get user error:', error);
    res.status(500).json({ error: error.message || 'Failed to get user' });
  }
});

app.get('/api/users', verifyApiSecret, authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await db.getAllUsers();
    res.json({ users });
  } catch (error: any) {
    console.error('Get users error:', error);
    res.status(500).json({ error: error.message || 'Failed to get users' });
  }
});

app.patch('/api/users/:id', verifyApiSecret, authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { is_admin, is_moderator, is_verified, is_blocked } = req.body;

    const updates: any = {};
    if (is_admin !== undefined) updates.is_admin = is_admin;
    if (is_moderator !== undefined) updates.is_moderator = is_moderator;
    if (is_verified !== undefined) updates.is_verified = is_verified;
    if (is_blocked !== undefined) updates.is_blocked = is_blocked;

    await db.updateUser(userId, updates);
    const user = await db.getUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const { password_hash, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword });
  } catch (error: any) {
    console.error('Update user error:', error);
    res.status(500).json({ error: error.message || 'Failed to update user' });
  }
});

app.delete('/api/users/:id', verifyApiSecret, authenticateToken, async (req: AuthRequest, res) => {
  try {
    const userId = parseInt(req.params.id);
    const currentUser = await db.getUserById(req.user!.id);

    if (!currentUser) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!currentUser.is_admin && currentUser.id !== userId) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    if (currentUser.is_admin && currentUser.id === userId) {
      const allUsers = await db.getAllUsers();
      const adminCount = allUsers.filter(u => u.is_admin && u.id !== userId).length;
      if (adminCount === 0) {
        return res.status(400).json({ error: 'Cannot delete the last admin' });
      }
    }

    await db.deleteUser(userId);
    res.json({ success: true });
  } catch (error: any) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: error.message || 'Failed to delete user' });
  }
});

app.get('/api/vms', verifyApiSecret, authenticateToken, async (req, res) => {
  try {
    const vms = await db.getAllVMs();
    res.json({ vms });
  } catch (error: any) {
    console.error('Get VMs error:', error);
    res.status(500).json({ error: error.message || 'Failed to get VMs' });
  }
});

app.post('/api/vms', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const { websocket_uri, node_id, display_name, admin_password, bot_name } = req.body;

    if (!websocket_uri || !node_id || !display_name || !admin_password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const existingVM = await db.getVMByNodeId(node_id);
    if (existingVM) {
      return res.status(400).json({ error: 'VM with this node ID already exists' });
    }

    const vm = await db.createVM(websocket_uri, node_id, display_name, admin_password, bot_name || null);
    
    if ((global as any).connectVM) {
      (global as any).connectVM(vm);
    }
    
    res.status(201).json({ vm });
  } catch (error: any) {
    console.error('Create VM error:', error);
    res.status(500).json({ error: error.message || 'Failed to create VM' });
  }
});

app.patch('/api/vms/:id', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const vmId = parseInt(req.params.id);
    const { websocket_uri, node_id, display_name, admin_password, bot_name } = req.body;

    const updates: any = {};
    if (websocket_uri !== undefined) updates.websocket_uri = websocket_uri;
    if (node_id !== undefined) updates.node_id = node_id;
    if (display_name !== undefined) updates.display_name = display_name;
    if (admin_password !== undefined) updates.admin_password = admin_password;
    if (bot_name !== undefined) updates.bot_name = bot_name;

    await db.updateVM(vmId, updates);
    const vm = await db.getAllVMs().then(vms => vms.find(v => v.id === vmId));
    if (!vm) {
      return res.status(404).json({ error: 'VM not found' });
    }
    res.json({ vm });
  } catch (error: any) {
    console.error('Update VM error:', error);
    res.status(500).json({ error: error.message || 'Failed to update VM' });
  }
});

app.delete('/api/vms/:id', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const vmId = parseInt(req.params.id);
    await db.deleteVM(vmId);
    res.json({ success: true });
  } catch (error: any) {
    console.error('Delete VM error:', error);
    res.status(500).json({ error: error.message || 'Failed to delete VM' });
  }
});

app.get('/api/emojis', verifyApiSecret, authenticateToken, async (req, res) => {
  try {
    const emojis = await db.getAllEmojis();
    res.json({ emojis });
  } catch (error: any) {
    console.error('Get emojis error:', error);
    res.status(500).json({ error: error.message || 'Failed to get emojis' });
  }
});

app.post('/api/emojis', verifyApiSecret, authenticateToken, async (req: AuthRequest, res) => {
  try {
    const user = await db.getUserById(req.user!.id);
    if (!user || !user.is_verified) {
      return res.status(403).json({ error: 'Verified account required to create emojis' });
    }

    const { name, web_address, description, vm_node_ids } = req.body;

    if (!name || !web_address || !description || !Array.isArray(vm_node_ids) || vm_node_ids.length === 0) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const isBlocked = await db.isDomainBlocked(web_address);
    if (isBlocked) {
      return res.status(400).json({ error: 'This domain is blocked. Please use a different image URL.' });
    }

    const emoji = await db.createEmoji(name, web_address, description, req.user!.id, vm_node_ids);

    if ((global as any).refreshEmojiCache) {
      (global as any).refreshEmojiCache();
    }

    res.status(201).json({ emoji });
  } catch (error: any) {
    console.error('Create emoji error:', error);
    res.status(500).json({ error: error.message || 'Failed to create emoji' });
  }
});

app.delete('/api/emojis/:id', verifyApiSecret, authenticateToken, async (req: AuthRequest, res) => {
  try {
    const emojiId = parseInt(req.params.id);
    const emoji = await db.getEmojiById(emojiId);

    if (!emoji) {
      return res.status(404).json({ error: 'Emoji not found' });
    }

    const user = await db.getUserById(req.user!.id);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!user.is_admin && !user.is_moderator && emoji.created_by !== user.id) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    await db.deleteEmoji(emojiId);

    if ((global as any).refreshEmojiCache) {
      (global as any).refreshEmojiCache();
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error('Delete emoji error:', error);
    res.status(500).json({ error: error.message || 'Failed to delete emoji' });
  }
});

app.get('/api/gifs', verifyApiSecret, authenticateToken, async (req, res) => {
  try {
    const gifs = await db.getAllGIFs();
    res.json({ gifs });
  } catch (error: any) {
    console.error('Get GIFs error:', error);
    res.status(500).json({ error: error.message || 'Failed to get GIFs' });
  }
});

app.post('/api/gifs', verifyApiSecret, authenticateToken, async (req: AuthRequest, res) => {
  try {
    const user = await db.getUserById(req.user!.id);
    if (!user || !user.is_verified) {
      return res.status(403).json({ error: 'Verified account required to create GIFs' });
    }

    const { name, web_address, description, vm_node_ids } = req.body;

    if (!name || !web_address || !description || !Array.isArray(vm_node_ids) || vm_node_ids.length === 0) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const isBlocked = await db.isDomainBlocked(web_address);
    if (isBlocked) {
      return res.status(400).json({ error: 'This domain is blocked. Please use a different image URL.' });
    }

    const gif = await db.createGIF(name, web_address, description, req.user!.id, vm_node_ids);

    if ((global as any).refreshGIFCache) {
      (global as any).refreshGIFCache();
    }

    res.status(201).json({ gif });
  } catch (error: any) {
    console.error('Create GIF error:', error);
    res.status(500).json({ error: error.message || 'Failed to create GIF' });
  }
});

app.delete('/api/gifs/:id', verifyApiSecret, authenticateToken, async (req: AuthRequest, res) => {
  try {
    const gifId = parseInt(req.params.id);
    const gif = await db.getGIFById(gifId);

    if (!gif) {
      return res.status(404).json({ error: 'GIF not found' });
    }

    const user = await db.getUserById(req.user!.id);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!user.is_admin && !user.is_moderator && gif.created_by !== user.id) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    await db.deleteGIF(gifId);

    if ((global as any).refreshGIFCache) {
      (global as any).refreshGIFCache();
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error('Delete GIF error:', error);
    res.status(500).json({ error: error.message || 'Failed to delete GIF' });
  }
});

app.get('/api/commands', verifyApiSecret, authenticateToken, requireAdmin, async (req, res) => {
  try {
    const commands = await db.getAllCommands();
    res.json({ commands });
  } catch (error: any) {
    console.error('Get commands error:', error);
    res.status(500).json({ error: error.message || 'Failed to get commands' });
  }
});

app.post('/api/commands', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const { name, type, help_text, response_text, enabled, mod_only } = req.body;

    if (!name || !type || !help_text || !response_text) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (type !== 'text' && type !== 'xss' && type !== 'qemu') {
      return res.status(400).json({ error: 'Type must be "text", "xss", or "qemu"' });
    }

    const existingCommand = await db.getCommand(name);
    if (existingCommand) {
      return res.status(400).json({ error: 'Command with this name already exists' });
    }

    const command = await db.createCommand(name, type, help_text, response_text, enabled !== false, mod_only === true);
    res.status(201).json({ command });
  } catch (error: any) {
    console.error('Create command error:', error);
    res.status(500).json({ error: error.message || 'Failed to create command' });
  }
});

app.patch('/api/commands/:id', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const commandId = parseInt(req.params.id);
    const { enabled, mod_only, help_text, response_text, type } = req.body;

    const commands = await db.getAllCommands();
    const command = commands.find(c => c.id === commandId);
    if (!command) {
      return res.status(404).json({ error: 'Command not found' });
    }

    if (command.type === 'builtin' && (type !== undefined || help_text !== undefined || response_text !== undefined)) {
      return res.status(400).json({ error: 'Cannot modify built-in commands' });
    }

    const updates: any = {};
    if (enabled !== undefined) updates.enabled = enabled;
    if (mod_only !== undefined) updates.mod_only = mod_only;
    if (help_text !== undefined) updates.help_text = help_text;
    if (response_text !== undefined) updates.response_text = response_text;
    if (type !== undefined && command.type !== 'builtin') {
      updates.type = type;
    }

    await db.updateCommand(commandId, updates);
    const updatedCommands = await db.getAllCommands();
    const updatedCommand = updatedCommands.find(c => c.id === commandId);
    if (!updatedCommand) {
      return res.status(404).json({ error: 'Command not found' });
    }
    res.json({ command: updatedCommand });
  } catch (error: any) {
    console.error('Update command error:', error);
    res.status(500).json({ error: error.message || 'Failed to update command' });
  }
});

app.delete('/api/commands/:id', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const commandId = parseInt(req.params.id);
    const commands = await db.getAllCommands();
    const command = commands.find(c => c.id === commandId);
    
    if (!command) {
      return res.status(404).json({ error: 'Command not found' });
    }

    if (command.type === 'builtin') {
      return res.status(400).json({ error: 'Cannot delete builtin commands' });
    }

    await db.deleteCommand(commandId);
    res.json({ success: true });
  } catch (error: any) {
    console.error('Delete command error:', error);
    res.status(500).json({ error: error.message || 'Failed to delete command' });
  }
});

app.get('/api/settings', verifyApiSecret, authenticateToken, requireAdmin, async (req, res) => {
  try {
    const defaultBotName = await db.getSetting('default_bot_name') || 'enixBot';
    const prefix = await db.getSetting('prefix') || '-';
    const panelUrl = await db.getSetting('panel_url') || '';
    res.json({ default_bot_name: defaultBotName, prefix, panel_url: panelUrl });
  } catch (error: any) {
    console.error('Get settings error:', error);
    res.status(500).json({ error: error.message || 'Failed to get settings' });
  }
});

app.post('/api/settings', verifyApiSecret, authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { default_bot_name, prefix, panel_url } = req.body;

    if (default_bot_name !== undefined) {
      await db.setSetting('default_bot_name', default_bot_name);
    }
    if (prefix !== undefined) {
      await db.setSetting('prefix', prefix);
    }
    if (panel_url !== undefined) {
      await db.setSetting('panel_url', panel_url);
    }

    if ((global as any).reconnectAllVMs) {
      (global as any).reconnectAllVMs();
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error('Update settings error:', error);
    res.status(500).json({ error: error.message || 'Failed to update settings' });
  }
});

app.post('/api/emojis/refresh', verifyApiSecret, authenticateToken, requireAdmin, async (req, res) => {
  try {
    if ((global as any).refreshEmojiCache) {
      await (global as any).refreshEmojiCache();
      res.json({ success: true, message: 'Emoji cache refreshed' });
    } else {
      res.status(500).json({ error: 'Refresh function not available' });
    }
  } catch (error: any) {
    console.error('Refresh cache error:', error);
    res.status(500).json({ error: error.message || 'Failed to refresh cache' });
  }
});

// vmConnections is now imported from index.ts
export function setVMConnections(connections: Map<string, any>) {
  // This function is kept for backward compatibility but vmConnections is now imported from index.ts
  // The connections are managed directly in index.ts
}

app.get('/api/emoji-requests', verifyApiSecret, authenticateToken, requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit as string) || 100;
    const requests = await db.getEmojiRequests(limit);
    res.json({ requests });
  } catch (error: any) {
    console.error('Get emoji requests error:', error);
    res.status(500).json({ error: error.message || 'Failed to get emoji requests' });
  }
});

app.get('/api/blocked-domains', verifyApiSecret, authenticateToken, requireAdmin, async (req, res) => {
  try {
    const domains = await db.getAllBlockedDomains();
    res.json({ domains });
  } catch (error: any) {
    console.error('Get blocked domains error:', error);
    res.status(500).json({ error: error.message || 'Failed to get blocked domains' });
  }
});

app.post('/api/blocked-domains', verifyApiSecret, authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }
    await db.addBlockedDomain(domain);
    res.json({ success: true });
  } catch (error: any) {
    console.error('Add blocked domain error:', error);
    res.status(500).json({ error: error.message || 'Failed to add blocked domain' });
  }
});

app.delete('/api/blocked-domains/:domain', verifyApiSecret, authenticateToken, requireAdmin, async (req, res) => {
  try {
    const domain = decodeURIComponent(req.params.domain);
    await db.removeBlockedDomain(domain);
    res.json({ success: true });
  } catch (error: any) {
    console.error('Remove blocked domain error:', error);
    res.status(500).json({ error: error.message || 'Failed to remove blocked domain' });
  }
});

app.get('/api/reports', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const reports = await db.getAllReports();
    res.json({ reports });
  } catch (error: any) {
    console.error('Get reports error:', error);
    res.status(500).json({ error: error.message || 'Failed to get reports' });
  }
});

app.post('/api/reports/:id/resolve', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const reportId = parseInt(req.params.id);
    const userId = (req as any).user.id;
    await db.markReportResolved(reportId, userId);
    const report = await db.getReportById(reportId);
    res.json({ report });
  } catch (error: any) {
    console.error('Resolve report error:', error);
    res.status(500).json({ error: error.message || 'Failed to resolve report' });
  }
});

app.delete('/api/reports/:id', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const reportId = parseInt(req.params.id);
    await db.deleteReport(reportId);
    res.json({ success: true });
  } catch (error: any) {
    console.error('Delete report error:', error);
    res.status(500).json({ error: error.message || 'Failed to delete report' });
  }
});

app.post('/api/reports/:id/ban', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const reportId = parseInt(req.params.id);
    const report = await db.getReportById(reportId);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    const { node_id } = req.body;
    if (!node_id) {
      return res.status(400).json({ error: 'node_id is required' });
    }
    
    const ws = vmConnections.get(node_id);
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return res.status(400).json({ error: 'VM not connected' });
    }
    
    ws.send(encodeGuacArray(['admin', '12', report.reported_username]));
    await db.markReportResolved(reportId, (req as any).user.id);
    const updatedReport = await db.getReportById(reportId);
    res.json({ report: updatedReport, message: `Banned ${report.reported_username}` });
  } catch (error: any) {
    console.error('Ban from report error:', error);
    res.status(500).json({ error: error.message || 'Failed to ban user' });
  }
});

app.get('/api/extensions', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const extensions = await db.getAllExtensions();
    const extensionsWithCommands = await Promise.all(extensions.map(async (ext) => {
      const commands = await db.getExtensionCommands(ext.extension_id);
      return { ...ext, commands };
    }));
    res.json({ extensions: extensionsWithCommands });
  } catch (error: any) {
    console.error('Get extensions error:', error);
    res.status(500).json({ error: error.message || 'Failed to get extensions' });
  }
});

app.post('/api/extensions', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const { websocket_uri } = req.body;
    if (!websocket_uri) {
      return res.status(400).json({ error: 'websocket_uri is required' });
    }

    // Try to connect and get extension details
    const ws = new WebSocket(websocket_uri);
    let handshakeReceived = false;
    let extensionData: any = null;

    const timeout = setTimeout(() => {
      if (!handshakeReceived) {
        ws.close();
        return res.status(400).json({ error: 'Extension did not send handshake in time' });
      }
    }, 5000);

    ws.on('message', (data: WebSocket.RawData) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'handshake') {
          handshakeReceived = true;
          extensionData = msg;
          ws.close();
        }
      } catch (e) {
        // Ignore invalid JSON
      }
    });

    ws.on('open', () => {
      // Wait for handshake
    });

    ws.on('close', () => {
      clearTimeout(timeout);
      if (handshakeReceived && extensionData) {
        const extensionId = extensionData.extension_id || `ext-${Date.now()}`;
        db.createExtension(
          extensionId,
          extensionData.display_name || 'Unknown Extension',
          extensionData.description || '',
          extensionData.version || '1.0.0',
          websocket_uri,
          extensionData.permissions || [],
          (extensionData.commands || []).map((c: any) => ({
            extension_id: extensionId,
            name: c.name,
            help_text: c.help_text || '',
            mod_only: c.mod_only || false
          }))
        ).then((extension) => {
          res.status(201).json({ extension });
        }).catch((error: any) => {
          res.status(500).json({ error: error.message || 'Failed to create extension' });
        });
      } else if (!handshakeReceived) {
        res.status(400).json({ error: 'Extension did not send handshake' });
      }
    });

    ws.on('error', (error) => {
      clearTimeout(timeout);
      res.status(400).json({ error: `Failed to connect to extension: ${error.message}` });
    });
  } catch (error: any) {
    console.error('Create extension error:', error);
    res.status(500).json({ error: error.message || 'Failed to create extension' });
  }
});

app.patch('/api/extensions/:id', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const extensionId = req.params.id;
    const { enabled, config } = req.body;

    await db.updateExtension(extensionId, { enabled, config: config ? JSON.stringify(config) : undefined });
    
    const extension = await db.getExtensionById(extensionId);
    if (!extension) {
      return res.status(404).json({ error: 'Extension not found' });
    }

    // Send config update to extension if connected
    const { sendToExtension } = await import('./index');
    sendToExtension(extensionId, {
      type: 'config_update',
      extension_id: extensionId,
      config: config || {}
    });

    res.json({ extension });
  } catch (error: any) {
    console.error('Update extension error:', error);
    res.status(500).json({ error: error.message || 'Failed to update extension' });
  }
});

app.delete('/api/extensions/:id', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const extensionId = req.params.id;
    await db.deleteExtension(extensionId);
    res.json({ success: true });
  } catch (error: any) {
    console.error('Delete extension error:', error);
    res.status(500).json({ error: error.message || 'Failed to delete extension' });
  }
});

app.get('/api/extensions/:id/config', verifyApiSecret, authenticateToken, requireAdminOrMod, async (req, res) => {
  try {
    const extensionId = req.params.id;
    const extension = await db.getExtensionById(extensionId);
    if (!extension) {
      return res.status(404).json({ error: 'Extension not found' });
    }

    const { sendToExtension } = await import('./index');
    sendToExtension(extensionId, {
      type: 'config_request',
      extension_id: extensionId
    });

    res.json({ config: extension.config ? JSON.parse(extension.config) : {} });
  } catch (error: any) {
    console.error('Get extension config error:', error);
    res.status(500).json({ error: error.message || 'Failed to get extension config' });
  }
});

export function startAPI(port: number, secret: string) {
  apiSecret = secret;
  app.listen(port, () => {
    console.log(`API server running on port ${port}`);
  });
}

