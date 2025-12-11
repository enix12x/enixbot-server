import mysql from 'mysql2/promise';

export interface User {
  id: number;
  username: string;
  email: string;
  password_hash: string;
  is_admin: boolean;
  is_moderator: boolean;
  is_verified: boolean;
  is_blocked: boolean;
  created_at: Date;
}

export interface Emoji {
  id: number;
  name: string;
  web_address: string;
  description: string;
  created_by: number;
  created_at: Date;
}

export interface GIF {
  id: number;
  name: string;
  web_address: string;
  description: string;
  created_by: number;
  created_at: Date;
}

export interface VM {
  id: number;
  websocket_uri: string;
  node_id: string;
  display_name: string;
  admin_password: string;
  bot_name: string | null;
  created_at: Date;
}

export interface Command {
  id: number;
  name: string;
  enabled: boolean;
  mod_only: boolean;
  type: 'builtin' | 'text' | 'xss' | 'qemu' | null;
  help_text: string | null;
  response_text: string | null;
  created_at: Date;
}

export interface Report {
  id: number;
  reported_username: string;
  reported_ip: string | null;
  reporter_username: string;
  reason: string;
  resolved: boolean;
  resolved_by: number | null;
  created_at: Date;
  resolved_at: Date | null;
}

export interface Extension {
  id: number;
  extension_id: string;
  display_name: string;
  description: string;
  version: string;
  websocket_uri: string;
  enabled: boolean;
  permissions: string;
  config: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface ExtensionCommand {
  extension_id: string;
  name: string;
  help_text: string;
  mod_only: boolean;
}

export interface VMEmoji {
  emoji_id: number;
  vm_node_id: string;
}

export interface VMGIF {
  gif_id: number;
  vm_node_id: string;
}

let pool: mysql.Pool | null = null;

export function getConnection() {
  return pool ? pool.getConnection() : null;
}

export async function initDatabase(config: {
  host: string;
  user: string;
  password: string;
  database: string;
  port?: number;
}) {
  pool = mysql.createPool({
    host: config.host,
    user: config.user,
    password: config.password,
    database: config.database,
    port: config.port || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  await createTables();
  console.log('Database initialized successfully');
}

async function createTables() {
  if (!pool) throw new Error('Database not initialized');

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      is_admin BOOLEAN DEFAULT FALSE,
      is_moderator BOOLEAN DEFAULT FALSE,
      is_verified BOOLEAN DEFAULT FALSE,
      is_blocked BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  try {
    await pool.execute('ALTER TABLE users ADD COLUMN is_moderator BOOLEAN DEFAULT FALSE');
  } catch (e: any) {
    if (!e.message.includes('Duplicate column name')) {
      console.warn('Could not add is_moderator column:', e.message);
    }
  }

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS emojis (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) UNIQUE NOT NULL,
      web_address VARCHAR(512) NOT NULL,
      description TEXT,
      created_by INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS gifs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) UNIQUE NOT NULL,
      web_address VARCHAR(512) NOT NULL,
      description TEXT,
      created_by INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS vms (
      id INT AUTO_INCREMENT PRIMARY KEY,
      websocket_uri VARCHAR(512) NOT NULL,
      node_id VARCHAR(255) UNIQUE NOT NULL,
      display_name VARCHAR(255) NOT NULL,
      admin_password VARCHAR(255) NOT NULL,
      bot_name VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS commands (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) UNIQUE NOT NULL,
      enabled BOOLEAN DEFAULT TRUE,
      mod_only BOOLEAN DEFAULT FALSE,
      type VARCHAR(20),
      help_text TEXT,
      response_text TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  try {
    await pool.execute('ALTER TABLE commands DROP COLUMN admin_only');
  } catch (e: any) {
    if (!e.message.includes("doesn't exist") && !e.message.includes('Unknown column') && !e.message.includes("Can't DROP COLUMN")) {
      console.warn('Could not remove admin_only column:', e.message);
    }
  }

  try {
    await pool.execute('ALTER TABLE commands ADD COLUMN type VARCHAR(20)');
  } catch (e: any) {
    if (!e.message.includes('Duplicate column name')) {
      console.warn('Could not add type column:', e.message);
    }
  }

  try {
    await pool.execute('ALTER TABLE commands ADD COLUMN help_text TEXT');
  } catch (e: any) {
    if (!e.message.includes('Duplicate column name')) {
      console.warn('Could not add help_text column:', e.message);
    }
  }

  try {
    await pool.execute('ALTER TABLE commands ADD COLUMN response_text TEXT');
  } catch (e: any) {
    if (!e.message.includes('Duplicate column name')) {
      console.warn('Could not add response_text column:', e.message);
    }
  }

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS vm_emojis (
      emoji_id INT NOT NULL,
      vm_node_id VARCHAR(255) NOT NULL,
      PRIMARY KEY (emoji_id, vm_node_id),
      FOREIGN KEY (emoji_id) REFERENCES emojis(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS vm_gifs (
      gif_id INT NOT NULL,
      vm_node_id VARCHAR(255) NOT NULL,
      PRIMARY KEY (gif_id, vm_node_id),
      FOREIGN KEY (gif_id) REFERENCES gifs(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS settings (
      key_name VARCHAR(255) PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS emoji_requests (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      emoji_id INT NOT NULL,
      vm_node_id VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (emoji_id) REFERENCES emojis(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS blocked_domains (
      id INT AUTO_INCREMENT PRIMARY KEY,
      domain VARCHAR(255) UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS reports (
      id INT AUTO_INCREMENT PRIMARY KEY,
      reported_username VARCHAR(255) NOT NULL,
      reported_ip VARCHAR(45),
      reporter_username VARCHAR(255) NOT NULL,
      reason TEXT NOT NULL,
      resolved BOOLEAN DEFAULT FALSE,
      resolved_by INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      resolved_at TIMESTAMP NULL,
      FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS extensions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      extension_id VARCHAR(255) UNIQUE NOT NULL,
      display_name VARCHAR(255) NOT NULL,
      description TEXT,
      version VARCHAR(50),
      websocket_uri VARCHAR(500) NOT NULL,
      enabled BOOLEAN DEFAULT TRUE,
      permissions TEXT,
      config TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS extension_commands (
      id INT AUTO_INCREMENT PRIMARY KEY,
      extension_id VARCHAR(255) NOT NULL,
      name VARCHAR(255) NOT NULL,
      help_text TEXT,
      mod_only BOOLEAN DEFAULT FALSE,
      FOREIGN KEY (extension_id) REFERENCES extensions(extension_id) ON DELETE CASCADE,
      UNIQUE KEY unique_extension_command (extension_id, name)
    )
  `);

  await initializeDefaultCommands();
}

async function initializeDefaultCommands() {
  if (!pool) return;
  const defaultCommands = [
    { name: 'help', enabled: true, mod_only: false },
    { name: 'emojilist', enabled: true, mod_only: false },
    { name: 'emoji', enabled: true, mod_only: false },
    { name: 'giflist', enabled: true, mod_only: false },
    { name: 'gif', enabled: true, mod_only: false },
    { name: 'reboot', enabled: true, mod_only: false },
    { name: 'nmi', enabled: true, mod_only: false },
    { name: 'lock', enabled: true, mod_only: false },
    { name: 'ban', enabled: true, mod_only: true },
    { name: 'panel', enabled: true, mod_only: false },
    { name: 'report', enabled: true, mod_only: false },
  ];

  for (const cmd of defaultCommands) {
    try {
      await pool.execute(
        'INSERT IGNORE INTO commands (name, enabled, mod_only, type) VALUES (?, ?, ?, ?)',
        [cmd.name, cmd.enabled, cmd.mod_only, 'builtin']
      );
    } catch (e: any) {
      if (!e.message.includes('Duplicate entry')) {
        console.warn(`Could not insert command ${cmd.name}:`, e.message);
      }
    }
  }
}

export async function getFirstUser(): Promise<User | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM users ORDER BY id ASC LIMIT 1');
  const users = rows as User[];
  return users.length > 0 ? users[0] : null;
}

export async function createUser(
  username: string,
  email: string,
  passwordHash: string
): Promise<User> {
  if (!pool) throw new Error('Database not initialized');

  const isFirstUser = (await getFirstUser()) === null;

  const [result] = await pool.execute(
    'INSERT INTO users (username, email, password_hash, is_admin, is_moderator, is_verified) VALUES (?, ?, ?, ?, ?, ?)',
    [username, email, passwordHash, isFirstUser, false, isFirstUser]
  );

  const insertResult = result as mysql.ResultSetHeader;
  const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [insertResult.insertId]);
  const users = rows as User[];
  return users[0];
}

export async function getUserByUsername(username: string): Promise<User | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
  const users = rows as User[];
  return users.length > 0 ? users[0] : null;
}

export async function getUserByEmail(email: string): Promise<User | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
  const users = rows as User[];
  return users.length > 0 ? users[0] : null;
}

export async function getUserById(id: number): Promise<User | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [id]);
  const users = rows as User[];
  return users.length > 0 ? users[0] : null;
}

export async function getAllUsers(): Promise<User[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT id, username, email, is_admin, is_moderator, is_verified, is_blocked, created_at FROM users');
  return rows as User[];
}

export async function deleteUser(id: number): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute('DELETE FROM users WHERE id = ?', [id]);
}

export async function updateUser(
  id: number,
  updates: Partial<{ is_admin: boolean; is_moderator: boolean; is_verified: boolean; is_blocked: boolean }>
): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  const fields: string[] = [];
  const values: any[] = [];

  if (updates.is_admin !== undefined) {
    fields.push('is_admin = ?');
    values.push(updates.is_admin);
    if (updates.is_admin) {
      fields.push('is_moderator = ?');
      values.push(false);
    }
  }
  if (updates.is_moderator !== undefined) {
    fields.push('is_moderator = ?');
    values.push(updates.is_moderator);
    if (updates.is_moderator) {
      fields.push('is_admin = ?');
      values.push(false);
    }
  }
  if (updates.is_verified !== undefined) {
    fields.push('is_verified = ?');
    values.push(updates.is_verified);
  }
  if (updates.is_blocked !== undefined) {
    fields.push('is_blocked = ?');
    values.push(updates.is_blocked);
  }

  if (fields.length === 0) return;

  values.push(id);
  await pool.execute(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, values);
}

export async function createEmoji(
  name: string,
  webAddress: string,
  description: string,
  createdBy: number,
  vmNodeIds: string[]
): Promise<Emoji> {
  if (!pool) throw new Error('Database not initialized');

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [result] = await connection.execute(
      'INSERT INTO emojis (name, web_address, description, created_by) VALUES (?, ?, ?, ?)',
      [name, webAddress, description, createdBy]
    );

    const insertResult = result as mysql.ResultSetHeader;
    const emojiId = insertResult.insertId;

    for (const vmNodeId of vmNodeIds) {
      await connection.execute(
        'INSERT INTO vm_emojis (emoji_id, vm_node_id) VALUES (?, ?)',
        [emojiId, vmNodeId]
      );
    }

    await connection.commit();

    const [rows] = await connection.execute('SELECT * FROM emojis WHERE id = ?', [emojiId]);
    const emojis = rows as Emoji[];
    return emojis[0];
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

export async function createGIF(
  name: string,
  webAddress: string,
  description: string,
  createdBy: number,
  vmNodeIds: string[]
): Promise<GIF> {
  if (!pool) throw new Error('Database not initialized');

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [result] = await connection.execute(
      'INSERT INTO gifs (name, web_address, description, created_by) VALUES (?, ?, ?, ?)',
      [name, webAddress, description, createdBy]
    );

    const insertResult = result as mysql.ResultSetHeader;
    const gifId = insertResult.insertId;

    for (const vmNodeId of vmNodeIds) {
      await connection.execute(
        'INSERT INTO vm_gifs (gif_id, vm_node_id) VALUES (?, ?)',
        [gifId, vmNodeId]
      );
    }

    await connection.commit();

    const [rows] = await connection.execute('SELECT * FROM gifs WHERE id = ?', [gifId]);
    const gifs = rows as GIF[];
    return gifs[0];
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

export async function getEmojisForVM(vmNodeId: string): Promise<Emoji[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute(
    `SELECT e.* FROM emojis e
     INNER JOIN vm_emojis ve ON e.id = ve.emoji_id
     WHERE ve.vm_node_id = ?`,
    [vmNodeId]
  );
  return rows as Emoji[];
}

export async function getGIFsForVM(vmNodeId: string): Promise<GIF[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute(
    `SELECT g.* FROM gifs g
     INNER JOIN vm_gifs vg ON g.id = vg.gif_id
     WHERE vg.vm_node_id = ?`,
    [vmNodeId]
  );
  return rows as GIF[];
}

export async function getAllEmojis(): Promise<(Emoji & { created_by_username: string; vm_node_ids: string[] })[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute(
    `SELECT e.*, u.username as created_by_username,
     GROUP_CONCAT(ve.vm_node_id) as vm_node_ids
     FROM emojis e
     LEFT JOIN users u ON e.created_by = u.id
     LEFT JOIN vm_emojis ve ON e.id = ve.emoji_id
     GROUP BY e.id`
  );

  const emojis = rows as any[];
  return emojis.map(e => ({
    ...e,
    vm_node_ids: e.vm_node_ids ? e.vm_node_ids.split(',') : []
  }));
}

export async function getAllGIFs(): Promise<(GIF & { created_by_username: string; vm_node_ids: string[] })[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute(
    `SELECT g.*, u.username as created_by_username,
     GROUP_CONCAT(vg.vm_node_id) as vm_node_ids
     FROM gifs g
     LEFT JOIN users u ON g.created_by = u.id
     LEFT JOIN vm_gifs vg ON g.id = vg.gif_id
     GROUP BY g.id`
  );

  const gifs = rows as any[];
  return gifs.map(g => ({
    ...g,
    vm_node_ids: g.vm_node_ids ? g.vm_node_ids.split(',') : []
  }));
}

export async function deleteEmoji(id: number): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute('DELETE FROM emojis WHERE id = ?', [id]);
}

export async function deleteGIF(id: number): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute('DELETE FROM gifs WHERE id = ?', [id]);
}

export async function getEmojiById(id: number): Promise<Emoji | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM emojis WHERE id = ?', [id]);
  const emojis = rows as Emoji[];
  return emojis.length > 0 ? emojis[0] : null;
}

export async function getGIFById(id: number): Promise<GIF | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM gifs WHERE id = ?', [id]);
  const gifs = rows as GIF[];
  return gifs.length > 0 ? gifs[0] : null;
}

export async function getAllVMs(): Promise<VM[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM vms ORDER BY id ASC');
  return rows as VM[];
}

export async function getVMByNodeId(nodeId: string): Promise<VM | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM vms WHERE node_id = ?', [nodeId]);
  const vms = rows as VM[];
  return vms.length > 0 ? vms[0] : null;
}

export async function createVM(
  websocketUri: string,
  nodeId: string,
  displayName: string,
  adminPassword: string,
  botName: string | null
): Promise<VM> {
  if (!pool) throw new Error('Database not initialized');
  const [result] = await pool.execute(
    'INSERT INTO vms (websocket_uri, node_id, display_name, admin_password, bot_name) VALUES (?, ?, ?, ?, ?)',
    [websocketUri, nodeId, displayName, adminPassword, botName]
  );
  const insertResult = result as mysql.ResultSetHeader;
  const [rows] = await pool.execute('SELECT * FROM vms WHERE id = ?', [insertResult.insertId]);
  const vms = rows as VM[];
  return vms[0];
}

export async function updateVM(
  id: number,
  updates: Partial<{ websocket_uri: string; node_id: string; display_name: string; admin_password: string; bot_name: string | null }>
): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  const fields: string[] = [];
  const values: any[] = [];

  if (updates.websocket_uri !== undefined) {
    fields.push('websocket_uri = ?');
    values.push(updates.websocket_uri);
  }
  if (updates.node_id !== undefined) {
    fields.push('node_id = ?');
    values.push(updates.node_id);
  }
  if (updates.display_name !== undefined) {
    fields.push('display_name = ?');
    values.push(updates.display_name);
  }
  if (updates.admin_password !== undefined) {
    fields.push('admin_password = ?');
    values.push(updates.admin_password);
  }
  if (updates.bot_name !== undefined) {
    fields.push('bot_name = ?');
    values.push(updates.bot_name);
  }

  if (fields.length === 0) return;

  values.push(id);
  await pool.execute(`UPDATE vms SET ${fields.join(', ')} WHERE id = ?`, values);
}

export async function deleteVM(id: number): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute('DELETE FROM vms WHERE id = ?', [id]);
}

export async function getAllCommands(): Promise<Command[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT id, name, enabled, mod_only, type, help_text, response_text, created_at FROM commands ORDER BY name ASC');
  return rows as Command[];
}

export async function getCommand(name: string): Promise<Command | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT id, name, enabled, mod_only, type, help_text, response_text, created_at FROM commands WHERE name = ?', [name]);
  const commands = rows as Command[];
  return commands.length > 0 ? commands[0] : null;
}

export async function createCommand(
  name: string,
  type: 'text' | 'xss' | 'qemu',
  helpText: string,
  responseText: string,
  enabled: boolean,
  modOnly: boolean
): Promise<Command> {
  if (!pool) throw new Error('Database not initialized');
  const [result] = await pool.execute(
    'INSERT INTO commands (name, type, help_text, response_text, enabled, mod_only) VALUES (?, ?, ?, ?, ?, ?)',
    [name, type, helpText, responseText, enabled, modOnly]
  );
  const insertResult = result as mysql.ResultSetHeader;
  const [rows] = await pool.execute('SELECT id, name, enabled, mod_only, type, help_text, response_text, created_at FROM commands WHERE id = ?', [insertResult.insertId]);
  const commands = rows as Command[];
  return commands[0];
}

export async function updateCommand(
  id: number,
  updates: Partial<{ enabled: boolean; mod_only: boolean; help_text: string; response_text: string; type: string }>
): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  const fields: string[] = [];
  const values: any[] = [];

  if (updates.enabled !== undefined) {
    fields.push('enabled = ?');
    values.push(updates.enabled);
  }
  if (updates.mod_only !== undefined) {
    fields.push('mod_only = ?');
    values.push(updates.mod_only);
  }
  if (updates.help_text !== undefined) {
    fields.push('help_text = ?');
    values.push(updates.help_text);
  }
  if (updates.response_text !== undefined) {
    fields.push('response_text = ?');
    values.push(updates.response_text);
  }
  if (updates.type !== undefined) {
    fields.push('type = ?');
    values.push(updates.type);
  }

  if (fields.length === 0) return;

  values.push(id);
  await pool.execute(`UPDATE commands SET ${fields.join(', ')} WHERE id = ?`, values);
}

export async function deleteCommand(id: number): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute('DELETE FROM commands WHERE id = ?', [id]);
}

export async function getSetting(key: string): Promise<string | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT value FROM settings WHERE key_name = ?', [key]);
  const settings = rows as { value: string }[];
  return settings.length > 0 ? settings[0].value : null;
}

export async function setSetting(key: string, value: string): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute(
    'INSERT INTO settings (key_name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?',
    [key, value, value]
  );
}

export interface EmojiRequest {
  id: number;
  user_id: number;
  emoji_id: number;
  vm_node_id: string;
  created_at: Date;
  username?: string;
  emoji_name?: string;
}

export async function logEmojiRequest(userId: number, emojiId: number, vmNodeId: string): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute(
    'INSERT INTO emoji_requests (user_id, emoji_id, vm_node_id) VALUES (?, ?, ?)',
    [userId, emojiId, vmNodeId]
  );
}

export async function getEmojiRequests(limit: number = 100): Promise<EmojiRequest[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute(
    `SELECT er.*, u.username, e.name as emoji_name
     FROM emoji_requests er
     LEFT JOIN users u ON er.user_id = u.id
     LEFT JOIN emojis e ON er.emoji_id = e.id
     ORDER BY er.created_at DESC
     LIMIT ?`,
    [limit]
  );
  return rows as EmojiRequest[];
}

export async function getAllBlockedDomains(): Promise<string[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT domain FROM blocked_domains');
  const domains = rows as { domain: string }[];
  return domains.map(d => d.domain);
}

export async function addBlockedDomain(domain: string): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  try {
    await pool.execute('INSERT INTO blocked_domains (domain) VALUES (?)', [domain]);
  } catch (error: any) {
    if (error.code === 'ER_DUP_ENTRY') {
      throw new Error('Domain already blocked');
    }
    throw error;
  }
}

export async function removeBlockedDomain(domain: string): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute('DELETE FROM blocked_domains WHERE domain = ?', [domain]);
}

export async function isDomainBlocked(url: string): Promise<boolean> {
  if (!pool) throw new Error('Database not initialized');
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    const blockedDomains = await getAllBlockedDomains();
    return blockedDomains.some(blocked => {
      const blockedLower = blocked.toLowerCase();
      return domain === blockedLower || domain.endsWith('.' + blockedLower);
    });
  } catch (e) {
    return true;
  }
}

export async function createReport(
  reportedUsername: string,
  reportedIp: string | null,
  reporterUsername: string,
  reason: string
): Promise<Report> {
  if (!pool) throw new Error('Database not initialized');
  const [result] = await pool.execute(
    'INSERT INTO reports (reported_username, reported_ip, reporter_username, reason) VALUES (?, ?, ?, ?)',
    [reportedUsername, reportedIp, reporterUsername, reason]
  );
  const insertResult = result as mysql.ResultSetHeader;
  const [rows] = await pool.execute('SELECT * FROM reports WHERE id = ?', [insertResult.insertId]);
  const reports = rows as Report[];
  return reports[0];
}

export async function getAllReports(): Promise<Report[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM reports ORDER BY created_at DESC');
  return rows as Report[];
}

export async function getReportById(id: number): Promise<Report | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM reports WHERE id = ?', [id]);
  const reports = rows as Report[];
  return reports.length > 0 ? reports[0] : null;
}

export async function markReportResolved(id: number, resolvedBy: number): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute(
    'UPDATE reports SET resolved = TRUE, resolved_by = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?',
    [resolvedBy, id]
  );
}

export async function deleteReport(id: number): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute('DELETE FROM reports WHERE id = ?', [id]);
}

export async function createExtension(
  extensionId: string,
  displayName: string,
  description: string,
  version: string,
  websocketUri: string,
  permissions: string[],
  commands: ExtensionCommand[]
): Promise<Extension> {
  if (!pool) throw new Error('Database not initialized');
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [result] = await connection.execute(
      'INSERT INTO extensions (extension_id, display_name, description, version, websocket_uri, permissions) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE display_name = ?, description = ?, version = ?, websocket_uri = ?, permissions = ?',
      [extensionId, displayName, description, version, websocketUri, JSON.stringify(permissions), displayName, description, version, websocketUri, JSON.stringify(permissions)]
    );

    await connection.execute('DELETE FROM extension_commands WHERE extension_id = ?', [extensionId]);

    for (const cmd of commands) {
      await connection.execute(
        'INSERT INTO extension_commands (extension_id, name, help_text, mod_only) VALUES (?, ?, ?, ?)',
        [extensionId, cmd.name, cmd.help_text, cmd.mod_only]
      );
    }

    await connection.commit();

    const [rows] = await connection.execute('SELECT * FROM extensions WHERE extension_id = ?', [extensionId]);
    const extensions = rows as Extension[];
    return extensions[0];
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

export async function getAllExtensions(): Promise<Extension[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM extensions ORDER BY created_at DESC');
  return rows as Extension[];
}

export async function getExtensionById(extensionId: string): Promise<Extension | null> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT * FROM extensions WHERE extension_id = ?', [extensionId]);
  const extensions = rows as Extension[];
  return extensions.length > 0 ? extensions[0] : null;
}

export async function getExtensionCommands(extensionId: string): Promise<ExtensionCommand[]> {
  if (!pool) throw new Error('Database not initialized');
  const [rows] = await pool.execute('SELECT name, help_text, mod_only FROM extension_commands WHERE extension_id = ?', [extensionId]);
  return rows as ExtensionCommand[];
}

export async function updateExtension(
  extensionId: string,
  updates: Partial<{ enabled: boolean; config: string }>
): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  const fields: string[] = [];
  const values: any[] = [];

  if (updates.enabled !== undefined) {
    fields.push('enabled = ?');
    values.push(updates.enabled);
  }
  if (updates.config !== undefined) {
    fields.push('config = ?');
    values.push(updates.config);
  }

  if (fields.length === 0) return;

  values.push(extensionId);
  await pool.execute(`UPDATE extensions SET ${fields.join(', ')} WHERE extension_id = ?`, values);
}

export async function deleteExtension(extensionId: string): Promise<void> {
  if (!pool) throw new Error('Database not initialized');
  await pool.execute('DELETE FROM extensions WHERE extension_id = ?', [extensionId]);
}

export async function closeDatabase() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

