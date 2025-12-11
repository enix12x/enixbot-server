import fs from 'fs';
import path from 'path';
import WebSocket from 'ws';
import * as db from './database';
import * as api from './api';

export function encodeGuacArray(arr: string[]): string {
  return arr.map(s => `${Buffer.byteLength(s, 'utf8')}.${s}`).join(',') + ';';
}

function parseGuacArray(msg: string): string[] {
  const arr: string[] = [];
  let i = 0;
  while (i < msg.length) {
    const dot = msg.indexOf('.', i);
    if (dot === -1) break;
    const len = parseInt(msg.substring(i, dot), 10);
    const str = msg.substr(dot + 1, len);
    arr.push(str);
    i = dot + 1 + len;
    if (msg[i] === ',') i++;
    else if (msg[i] === ';') break;
  }
  return arr;
}

function isEmoji(str: string): boolean {
  const emojiRegex = /[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]|[\u{1F600}-\u{1F64F}]|[\u{1F680}-\u{1F6FF}]|[\u{1F1E0}-\u{1F1FF}]|[\u{1F900}-\u{1F9FF}]|[\u{1FA00}-\u{1FA6F}]|[\u{1FA70}-\u{1FAFF}]/u;
  return emojiRegex.test(str);
}

interface Config {
  database: {
    host: string;
    user: string;
    password: string;
    database: string;
    port?: number;
  };
  apiPort: number;
  apiSecret: string;
}

const configPath = path.resolve(__dirname, '../config.json');
if (!fs.existsSync(configPath)) {
  console.error('config.json not found. Please copy config.example.json to config.json and fill it in.');
  process.exit(1);
}
const config: Config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

const emojiCache: Map<string, db.Emoji[]> = new Map();
const gifCache: Map<string, db.GIF[]> = new Map();
export const vmConnections: Map<string, WebSocket> = new Map();
const userRanks: Map<string, Map<string, number>> = new Map();
const userIPs: Map<string, Map<string, string>> = new Map();
const extensionConnections: Map<string, WebSocket> = new Map();
const extensionCommands: Map<string, db.ExtensionCommand[]> = new Map();
let cachedPrefix = '-';
let cachedDefaultBotName = 'enixBot';

export function connectVM(vm: db.VM) {
  connectToVM(vm);
}

export function reconnectAllVMs() {
  vmConnections.forEach((ws, nodeId) => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.close();
    }
  });
  vmConnections.clear();
  
  setTimeout(async () => {
    const vmsList = await db.getAllVMs();
    vmsList.forEach((vm, index) => {
      setTimeout(() => {
        connectToVM(vm);
      }, index * 1000);
    });
  }, 1000);
}

async function loadEmojisForVM(nodeId: string) {
  try {
    const emojis = await db.getEmojisForVM(nodeId);
    emojiCache.set(nodeId, emojis);
    console.log(`[${nodeId}] Loaded ${emojis.length} emojis.`);
  } catch (e) {
    console.error(`[${nodeId}] Failed to load emoji list:`, e);
    emojiCache.set(nodeId, []);
  }
}

async function loadGIFsForVM(nodeId: string) {
  try {
    const gifs = await db.getGIFsForVM(nodeId);
    gifCache.set(nodeId, gifs);
    console.log(`[${nodeId}] Loaded ${gifs.length} GIFs.`);
  } catch (e) {
    console.error(`[${nodeId}] Failed to load GIF list:`, e);
    gifCache.set(nodeId, []);
  }
}

async function refreshEmojiCache() {
  const vms = await db.getAllVMs();
  for (const vm of vms) {
    await loadEmojisForVM(vm.node_id);
  }
}

async function refreshGIFCache() {
  const vms = await db.getAllVMs();
  for (const vm of vms) {
    await loadGIFsForVM(vm.node_id);
  }
}

function getUserRank(username: string, nodeId: string): number {
  if (!userRanks.has(nodeId)) {
    userRanks.set(nodeId, new Map());
    return 0;
  }
  const rankMap = userRanks.get(nodeId)!;
  if (rankMap.has(username)) {
    const rank = rankMap.get(username)!;
    if (isNaN(rank)) {
      console.log(`[${nodeId}] Warning: User ${username} has invalid rank ${rank}, defaulting to 0`);
      return 0;
    }
    return rank;
  }
  return 0;
}

async function startBot() {
  await db.initDatabase(config.database);

  api.startAPI(config.apiPort, config.apiSecret);

  const prefixSetting = await db.getSetting('prefix');
  if (prefixSetting) cachedPrefix = prefixSetting;
  
  const defaultBotNameSetting = await db.getSetting('default_bot_name');
  if (defaultBotNameSetting) cachedDefaultBotName = defaultBotNameSetting;

  await refreshEmojiCache();
  await refreshGIFCache();
  await loadExtensionCommands();

  setInterval(refreshEmojiCache, 10000);
  setInterval(refreshGIFCache, 10000);
  setInterval(async () => {
    const prefixSetting = await db.getSetting('prefix');
    if (prefixSetting) cachedPrefix = prefixSetting;
    const defaultBotNameSetting = await db.getSetting('default_bot_name');
    if (defaultBotNameSetting) cachedDefaultBotName = defaultBotNameSetting;
  }, 30000);

  (global as any).refreshEmojiCache = refreshEmojiCache;
  (global as any).refreshGIFCache = refreshGIFCache;
  (global as any).connectVM = connectVM;
  (global as any).reconnectAllVMs = reconnectAllVMs;

  const vmsList = await db.getAllVMs();
  vmsList.forEach((vm, index) => {
    setTimeout(() => {
      connectToVM(vm);
    }, index * 1000);
  });

  setTimeout(() => {
    api.setVMConnections(vmConnections);
  }, vmsList.length * 1000 + 2000);

  const extensions = await db.getAllExtensions();
  for (const ext of extensions) {
    if (ext.enabled) {
      setTimeout(() => {
        connectToExtension(ext);
      }, vmsList.length * 1000 + 3000);
    }
  }
}

async function loadExtensionCommands() {
  try {
    const extensions = await db.getAllExtensions();
    extensionCommands.clear();
    for (const ext of extensions) {
      if (ext.enabled) {
        const commands = await db.getExtensionCommands(ext.extension_id);
        extensionCommands.set(ext.extension_id, commands);
      }
    }
  } catch (e) {
    console.error('Failed to load extension commands:', e);
  }
}

function connectToExtension(extension: db.Extension) {
  const ws = new WebSocket(extension.websocket_uri);
  let authenticated = false;
  let extensionId: string = extension.extension_id;

  ws.on('open', () => {
    console.log(`[Extension] Connected to ${extension.display_name} (${extension.extension_id})`);
  });

  ws.on('message', async (data: WebSocket.RawData) => {
    try {
      const msg = JSON.parse(data.toString());
      
      if (msg.type === 'handshake') {
        extensionId = msg.extension_id || extension.extension_id;
        authenticated = true;
        
        const commands = msg.commands || [];
        const permissions = msg.permissions || [];
        
        try {
          const finalExtensionId: string = extensionId || extension.extension_id;
          
          await db.createExtension(
            finalExtensionId,
            msg.display_name || extension.display_name,
            msg.description || extension.description,
            msg.version || extension.version,
            extension.websocket_uri,
            permissions,
            commands.map((c: any) => ({
              extension_id: finalExtensionId,
              name: c.name,
              help_text: c.help_text || '',
              mod_only: c.mod_only || false
            }))
          );
          
          extensionId = finalExtensionId;
          await loadExtensionCommands();
          
          ws.send(JSON.stringify({
            type: 'handshake_response',
            status: 'accepted',
            extension_id: finalExtensionId
          }));
          
          console.log(`[Extension] ${finalExtensionId} authenticated successfully`);
        } catch (e: any) {
          console.error(`[Extension] Failed to register ${extensionId}:`, e);
          ws.send(JSON.stringify({
            type: 'handshake_response',
            status: 'rejected',
            message: e.message || 'Registration failed'
          }));
        }
      } else if (!authenticated) {
        ws.send(JSON.stringify({
          type: 'error',
          code: 'NOT_AUTHENTICATED',
          message: 'Extension must complete handshake first'
        }));
        return;
      }

      if (msg.type === 'command_response') {
        const wsConnection = vmConnections.get(msg.node_id);
        if (!wsConnection || wsConnection.readyState !== WebSocket.OPEN) {
          ws.send(JSON.stringify({
            type: 'error',
            code: 'VM_NOT_FOUND',
            message: 'VM not connected'
          }));
          return;
        }

        if (msg.response_type === 'chat') {
          sendChat(wsConnection, msg.message);
        } else if (msg.response_type === 'xss') {
          wsConnection.send(encodeGuacArray(['admin', '21', msg.message]));
        } else if (msg.response_type === 'qemu') {
          wsConnection.send(encodeGuacArray(['admin', '5', msg.node_id, msg.message]));
        }
      } else if (msg.type === 'send_chat') {
        const wsConnection = vmConnections.get(msg.node_id);
        if (wsConnection && wsConnection.readyState === WebSocket.OPEN) {
          sendChat(wsConnection, msg.message);
        }
      } else if (msg.type === 'execute_qemu') {
        const wsConnection = vmConnections.get(msg.node_id);
        if (wsConnection && wsConnection.readyState === WebSocket.OPEN) {
          wsConnection.send(encodeGuacArray(['admin', '5', msg.node_id, msg.command]));
        }
      } else if (msg.type === 'pong') {
        // Keep-alive response
      } else if (msg.type === 'config_response') {
        // Configuration response handled by API
      } else if (msg.type === 'config_update') {
        if (extensionId) {
          await db.updateExtension(extensionId, { config: JSON.stringify(msg.config) });
        }
      }
    } catch (e) {
      console.error(`[Extension] Error processing message:`, e);
      ws.send(JSON.stringify({
        type: 'error',
        code: 'INVALID_MESSAGE',
        message: 'Invalid message format'
      }));
    }
  });

  ws.on('close', () => {
    console.log(`[Extension] Disconnected from ${extension.display_name}`);
    if (extensionId) {
      extensionConnections.delete(extensionId);
    }
  });

  ws.on('error', (err) => {
    console.error(`[Extension] Error for ${extension.display_name}:`, err);
  });

  if (extension.extension_id) {
    extensionConnections.set(extension.extension_id, ws);
  }
}

export function sendToExtension(extensionId: string, message: any) {
  const ws = extensionConnections.get(extensionId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

export function broadcastToExtensions(message: any) {
  extensionConnections.forEach((ws, extId) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
    }
  });
}

function connectToVM(vm: db.VM) {
  const nodeId = vm.node_id;
  const retryDelay = 5000;

  if (vmConnections.has(nodeId)) {
    const existingWs = vmConnections.get(nodeId);
    if (existingWs && existingWs.readyState === WebSocket.OPEN) {
      console.log(`[${nodeId}] Already connected, skipping.`);
      return;
    }
  }

  const ws = new WebSocket(vm.websocket_uri, 'guacamole');
  let connected = false;
  let username = vm.bot_name || cachedDefaultBotName;
  let isAdmin = false;
  let myUser: string = username;
  const prefix = cachedPrefix;

  ws.on('open', () => {
    console.log(`[${nodeId}] WebSocket opened, requesting username: ${username}`);
    connected = true;
    vmConnections.set(nodeId, ws);
    api.setVMConnections(vmConnections);
    ws.send(encodeGuacArray(['rename', username]));
  });

  let awaitingAuth = false;
  let awaitingConnect = false;

  ws.on('message', async (data: WebSocket.RawData) => {
    const msg = data.toString();
    const arr = parseGuacArray(msg);
    if (!arr.length) return;
    const opcode = arr[0];

    if (opcode === 'nop') {
      ws.send(encodeGuacArray(['nop']));
    } else if (opcode === 'auth') {
      awaitingAuth = true;
    } else if (opcode === 'rename' && arr[1] === '0') {
      username = arr[3];
      myUser = arr[3];
      if (!awaitingAuth) {
        ws.send(encodeGuacArray(['connect', nodeId]));
      } else {
        awaitingConnect = true;
      }
    } else if (opcode === 'connect' && arr[1] === '1') {
      if (!awaitingAuth) {
        console.log(`[${nodeId}] Logging in as admin...`);
        ws.send(encodeGuacArray(['admin', '2', vm.admin_password]));
      } else if (awaitingConnect) {
        ws.send(encodeGuacArray(['connect', nodeId]));
        awaitingConnect = false;
        setTimeout(() => {
          ws.send(encodeGuacArray(['list']));
        }, 1000);
      }
    } else if (opcode === 'list') {
      ws.send(encodeGuacArray(['list']));
    } else if (opcode === 'login') {
      if (arr[1] === '1') {
        if (awaitingConnect) {
          ws.send(encodeGuacArray(['connect', nodeId]));
          awaitingConnect = false;
        }
        isAdmin = true;
        if (!userRanks.has(nodeId)) {
          userRanks.set(nodeId, new Map());
        }
        userRanks.get(nodeId)!.set(myUser, 2);
        console.log(`[${nodeId}] Logged in with bot token.`);
        ws.send(encodeGuacArray(['list']));
      } else {
        const errMsg = arr[2] || 'Unknown error';
        console.error(`[${nodeId}] Bot token login failed: ${errMsg}`);
        ws.close();
      }
    } else if (opcode === 'adduser') {
      console.log(`[${nodeId}] Received adduser:`, arr);
      const count = parseInt(arr[1] || '0', 10);
      for (let i = 2; i < arr.length; i += 2) {
        const userName = arr[i];
        const rank = parseInt(arr[i + 1] || '0', 10);
        if (!userRanks.has(nodeId)) {
          userRanks.set(nodeId, new Map());
        }
        if (userName && !isNaN(rank)) {
          userRanks.get(nodeId)!.set(userName, rank);
          console.log(`[${nodeId}] Tracked user ${userName} with rank ${rank}`);
          
          // Notify extensions
          broadcastToExtensions({
            type: 'user_join',
            username: userName,
            node_id: nodeId,
            user_rank: rank
          });
        } else {
          console.log(`[${nodeId}] Skipping invalid adduser entry: userName=${userName}, rank=${arr[i + 1]}`);
        }
      }
    } else if (opcode === 'remuser') {
      const count = parseInt(arr[1] || '0', 10);
      for (let i = 2; i < arr.length; i++) {
        const userName = arr[i];
        if (userRanks.has(nodeId)) {
          userRanks.get(nodeId)!.delete(userName);
          
          // Notify extensions
          broadcastToExtensions({
            type: 'user_leave',
            username: userName,
            node_id: nodeId
          });
        }
      }
    } else if (opcode === 'rename' && arr[1] === '1') {
      const oldName = arr[2];
      const newName = arr[3];
      if (userRanks.has(nodeId)) {
        const rankMap = userRanks.get(nodeId)!;
        if (rankMap.has(oldName)) {
          const rank = rankMap.get(oldName)!;
          rankMap.delete(oldName);
          rankMap.set(newName, rank);
        }
      }
    } else if (opcode === 'admin') {
      if (arr[1] === '0') {
        const status = arr[2];
        if (status === '1') {
          console.log(`[${nodeId}] Successfully logged in as Admin`);
          isAdmin = true;
          if (!userRanks.has(nodeId)) {
            userRanks.set(nodeId, new Map());
          }
          userRanks.get(nodeId)!.set(myUser, 2);
          ws.send(encodeGuacArray(['list']));
        } else if (status === '3') {
          console.log(`[${nodeId}] Successfully logged in as Moderator`);
          isAdmin = true;
          if (!userRanks.has(nodeId)) {
            userRanks.set(nodeId, new Map());
          }
          userRanks.get(nodeId)!.set(myUser, 3);
          ws.send(encodeGuacArray(['list']));
        } else {
          console.error(`[${nodeId}] Admin login failed: ${status}`);
        }
      } else if (arr[1] === '2') {
        const response = arr[2] || '';
        console.log(`[${nodeId}] QEMU monitor response: ${response}`);
      }
    } else if (opcode === 'chat') {
      const sender = arr[1];
      const message = arr[2];
      if (sender && message && sender !== myUser) {
        handleMessage(ws, sender, message, nodeId, prefix).catch(err => {
          console.error(`[${nodeId}] Error handling message:`, err);
        });
        
        // Broadcast chat to extensions
        const userRank = getUserRank(sender, nodeId);
        broadcastToExtensions({
          type: 'chat_message',
          sender: sender,
          message: message,
          node_id: nodeId,
          user_rank: userRank
        });
      }
    }
  });

  ws.on('close', (code, reason) => {
    console.log(`[${nodeId}] Disconnected (code: ${code}, reason: ${reason.toString()})`);
    connected = false;
    vmConnections.delete(nodeId);
    api.setVMConnections(vmConnections);
    if (userRanks.has(nodeId)) {
      userRanks.delete(nodeId);
    }

    if (code !== 1000) {
      console.log(`[${nodeId}] Attempting to reconnect in ${retryDelay / 1000} seconds...`);
      setTimeout(() => {
        connectToVM(vm);
      }, retryDelay);
    }
  });

  ws.on('error', (err: Error) => {
    console.error(`[${nodeId}] WebSocket error:`, err);
  });
}

async function handleMessage(ws: WebSocket, sender: string, message: string, nodeId: string, prefix: string) {
  const currentPrefix = cachedPrefix;
  let args: string[];
  let cmd: string;
  let dotMatch: RegExpMatchArray | null = null;
  let colonMatch: RegExpMatchArray | null = null;
  let isSpecialSyntax = false;

  if ((colonMatch = message.match(/^:([a-zA-Z0-9_]+):/))) {
    cmd = 'emoji';
    args = ['emoji', colonMatch[1]];
    isSpecialSyntax = true;
  } else if ((dotMatch = message.match(/^\.([a-zA-Z0-9_]+)\./))) {
    cmd = 'gif';
    args = ['gif', dotMatch[1]];
    isSpecialSyntax = true;
  } else if (message.startsWith(currentPrefix)) {
    args = message.slice(currentPrefix.length).trim().split(/\s+/);
    cmd = args[0].toLowerCase();
  } else {
    return;
  }

  let command = await db.getCommand(cmd);
  let isExtensionCommand = false;
  
  if (!command || !command.enabled) {
    // Check extension commands
    for (const [extId, extCommands] of extensionCommands.entries()) {
      const extCmd = extCommands.find(c => c.name === cmd);
      if (extCmd) {
        const extension = await db.getExtensionById(extId);
        if (extension && extension.enabled) {
          isExtensionCommand = true;
          const extWs = extensionConnections.get(extId);
          if (extWs && extWs.readyState === WebSocket.OPEN) {
            const userRank = getUserRank(sender, nodeId);
            extWs.send(JSON.stringify({
              type: 'command_request',
              command: cmd,
              sender: sender,
              args: args,
              node_id: nodeId,
              user_rank: userRank,
              request_id: `${Date.now()}-${Math.random()}`
            }));
            return;
          } else {
            sendChat(ws, `Extension command ${cmd} is not available (extension offline).`);
            return;
          }
        }
      }
    }
    
    if (!isExtensionCommand) {
      sendChat(ws, `Unknown command ${cmd}. See ${currentPrefix}help?`);
      return;
    }
  }

  if (!command) {
    sendChat(ws, `Unknown command ${cmd}. See ${currentPrefix}help?`);
    return;
  }

  const userRank = getUserRank(sender, nodeId);
  const isUserAdmin = userRank === 2;
  const isUserMod = userRank === 3;

  // TypeScript type guard: command is guaranteed to be non-null here
  const cmdObj: db.Command = command;

  console.log(`[${nodeId}] Command ${cmd} requested by ${sender} (rank: ${userRank}, admin: ${isUserAdmin}, mod: ${isUserMod}, mod_only: ${cmdObj.mod_only})`);
  console.log(`[${nodeId}] Current user ranks:`, Array.from(userRanks.get(nodeId)?.entries() || []));

  if (cmdObj.mod_only && !isUserAdmin && !isUserMod) {
    sendChat(ws, 'You do not have permission to run this command.');
    return;
  }

  await handleCommand(ws, sender, cmd, args, nodeId, currentPrefix, cmdObj);
}

async function handleCommand(ws: WebSocket, sender: string, cmd: string, args: string[], nodeId: string, currentPrefix: string, command: db.Command) {
  switch (cmd) {
    case 'help':
      const allCommands = await db.getAllCommands();
      const enabledCommands = allCommands.filter(c => c.enabled);
      let helpItems = enabledCommands.map(c => {
        if (c.type === 'builtin') {
          if (c.name === 'help') return `<li><b>${currentPrefix}help</b> - Show this help</li>`;
          if (c.name === 'emojilist') return `<li><b>${currentPrefix}emojilist</b> - List available emojis</li>`;
          if (c.name === 'emoji') return `<li><b>${currentPrefix}emoji &lt;name&gt;</b> or <b>:name:</b> - Send an emoji</li>`;
          if (c.name === 'giflist') return `<li><b>${currentPrefix}giflist</b> - List available GIFs</li>`;
          if (c.name === 'gif') return `<li><b>${currentPrefix}gif &lt;name&gt;</b> or <b>.name.</b> - Send a GIF</li>`;
          if (c.name === 'panel') return `<li><b>${currentPrefix}panel</b> - Show panel tutorial</li>`;
          if (c.name === 'reboot') return `<li><b>${currentPrefix}reboot</b> - Reboot the VM</li>`;
          if (c.name === 'nmi') return `<li><b>${currentPrefix}nmi</b> - Send NMI</li>`;
          if (c.name === 'lock') return `<li><b>${currentPrefix}lock</b> - Lock the VM</li>`;
          if (c.name === 'ban') return `<li><b>${currentPrefix}ban &lt;username&gt;</b> - Ban a user</li>`;
          if (c.name === 'report') return `<li><b>${currentPrefix}report @username reason</b> - Report a user</li>`;
        } else if (c.help_text) {
          return `<li><b>${currentPrefix}${c.name}</b> - ${c.help_text}</li>`;
        }
        return '';
      }).filter(item => item !== '');
      
      const html = `<div style='color:#fff;padding:8px 12px;font-family:sans-serif;'>
        <b>enixBot Commands:</b><ul style='margin:4px 0 0 16px;padding:0;'>
          ${helpItems.join('')}
        </ul>
      </div>`;
      ws.send(encodeGuacArray(['admin', '21', html]));
      break;

    case 'emojilist':
      const emojiList = emojiCache.get(nodeId) || [];
      if (!emojiList.length) {
        sendChat(ws, 'No emojis available for this VM.');
        return;
      }
      const emojiHtml = `<div style='color:#fff;padding:8px 12px;font-family:sans-serif;'>
        <b>Available Emojis:</b>
        <ul style='margin:4px 0 0 16px;padding:0;'>
          ${emojiList.map(e => `<li><b>${e.name}</b>: ${e.description} <img src='${e.web_address}' alt='${e.name}' style='height:20px;vertical-align:middle;'></li>`).join('')}
        </ul>
      </div>`;
      ws.send(encodeGuacArray(['admin', '21', emojiHtml]));
      break;

    case 'emoji':
      const emojiName = args[1];
      if (!emojiName) {
        sendChat(ws, `Usage: ${currentPrefix}emoji <name>`);
        return;
      }
      const emojiList2 = emojiCache.get(nodeId) || [];
      const emoji = emojiList2.find(e => e.name === emojiName);
      if (!emoji) {
        sendChat(ws, `Emoji not found. Use ${currentPrefix}emojilist to see available emojis.`);
        return;
      }
      const emojiHtml2 = `<img src='${emoji.web_address}' alt='${emoji.name}' style='height:32px;'>`;
      ws.send(encodeGuacArray(['admin', '21', emojiHtml2]));
      console.log(`[${nodeId}] Sent emoji '${emojiName}' for ${sender}`);

      try {
        const user = await db.getUserByUsername(sender);
        if (user) {
          await db.logEmojiRequest(user.id, emoji.id, nodeId);
        }
      } catch (e) {
        console.error('Failed to log emoji request:', e);
      }
      break;

    case 'giflist':
      const gifList = gifCache.get(nodeId) || [];
      if (!gifList.length) {
        sendChat(ws, 'No GIFs available for this VM.');
        return;
      }
      const gifHtml = `<div style='color:#fff;padding:8px 12px;font-family:sans-serif;'>
        <b>Available GIFs:</b>
        <ul style='margin:4px 0 0 16px;padding:0;'>
          ${gifList.map(g => `<li><b>${g.name}</b>: ${g.description}</li>`).join('')}
        </ul>
      </div>`;
      ws.send(encodeGuacArray(['admin', '21', gifHtml]));
      break;

    case 'gif':
      const gifName = args[1];
      if (!gifName) {
        sendChat(ws, `Usage: ${currentPrefix}gif <name> or .gifname.`);
        return;
      }
      const gifList2 = gifCache.get(nodeId) || [];
      const gif = gifList2.find(g => g.name === gifName);
      if (!gif) {
        sendChat(ws, `GIF not found. Use ${currentPrefix}giflist to see available GIFs.`);
        return;
      }
      const gifHtml2 = `<img src='${gif.web_address}' alt='${gif.name}'>`;
      ws.send(encodeGuacArray(['admin', '21', gifHtml2]));
      console.log(`[${nodeId}] Sent GIF '${gifName}' for ${sender}`);
      break;

    case 'reboot':
      ws.send(encodeGuacArray(['admin', '10']));
      sendChat(ws, 'Rebooting VM...');
      break;

    case 'nmi':
      ws.send(encodeGuacArray(['admin', '5', nodeId, 'nmi']));
      sendChat(ws, 'Sending NMI...');
      break;

    case 'lock':
      ws.send(encodeGuacArray(['admin', '5', nodeId, 'sendkey meta_l-l']));
      sendChat(ws, 'Locking VM...');
      break;

    case 'ban':
      const banTarget = args[1];
      if (!banTarget) {
        sendChat(ws, `Usage: ${currentPrefix}ban <username>`);
        return;
      }
      ws.send(encodeGuacArray(['admin', '12', banTarget]));
      sendChat(ws, `Banned ${banTarget}.`);
      break;

    case 'report':
      const reportTarget = args[1];
      if (!reportTarget) {
        sendChat(ws, `Usage: ${currentPrefix}report @username reason`);
        return;
      }
      if (!reportTarget.startsWith('@')) {
        sendChat(ws, `Usage: ${currentPrefix}report @username reason`);
        return;
      }
      const reportedUser = reportTarget.slice(1);
      const reportReason = args.slice(2).join(' ');
      if (!reportReason) {
        sendChat(ws, `Please provide a reason for the report. Usage: ${currentPrefix}report @username reason`);
        return;
      }
      
      const reportedIp = userIPs.get(nodeId)?.get(reportedUser) || null;
      try {
        await db.createReport(reportedUser, reportedIp, sender, reportReason);
        sendChat(ws, `Report submitted for ${reportedUser}. Thank you for your report.`);
      } catch (e) {
        console.error(`[${nodeId}] Failed to create report:`, e);
        sendChat(ws, 'Failed to submit report. Please try again later.');
      }
      break;

    case 'panel':
      const panelUrl = await db.getSetting('panel_url') || 'http://localhost:3001';
      const panelHtml = `<div style='color:#fff;padding:8px 12px;font-family:sans-serif;'>
        <b>enixBot Panel Tutorial:</b>
        <ul style='margin:4px 0 0 16px;padding:0;'>
          <li><b>Panel URL:</b> <a href='${panelUrl}' target='_blank' style='color:#4a9eff'>${panelUrl}</a></li>
          <li><b>Adding Emojis:</b> Go to the Emojis page, click "Create Emoji", fill in the name, URL, description, and select which VMs it should be available on.</li>
          <li><b>Adding GIFs:</b> Go to the GIFs page, click "Create GIF", fill in the name, URL, description, and select which VMs it should be available on.</li>
          <li><b>Using Emojis:</b> Use ${currentPrefix}emoji &lt;name&gt; or :name: in chat</li>
          <li><b>Using GIFs:</b> Use ${currentPrefix}gif &lt;name&gt; or .name. in chat</li>
        </ul>
      </div>`;
      ws.send(encodeGuacArray(['admin', '21', panelHtml]));
      break;

    default:
      if (command.type === 'text' && command.response_text) {
        const response = command.response_text.replace(/{user}/g, sender);
        sendChat(ws, response);
      } else if (command.type === 'xss' && command.response_text) {
        const response = command.response_text.replace(/{user}/g, sender);
        ws.send(encodeGuacArray(['admin', '21', response]));
      } else if (command.type === 'qemu' && command.response_text) {
        ws.send(encodeGuacArray(['admin', '5', nodeId, command.response_text]));
        if (command.help_text) {
          sendChat(ws, command.help_text.replace(/{user}/g, sender));
        }
      } else {
        sendChat(ws, `Unknown command ${cmd}. See ${currentPrefix}help?`);
      }
      break;
  }
}

function sendChat(ws: WebSocket, msg: string) {
  ws.send(encodeGuacArray(['chat', msg]));
}

startBot().catch((error) => {
  console.error('Failed to start bot:', error);
  process.exit(1);
});

process.on('SIGINT', async () => {
  console.log('Shutting down...');
  await db.closeDatabase();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Shutting down...');
  await db.closeDatabase();
  process.exit(0);
});

