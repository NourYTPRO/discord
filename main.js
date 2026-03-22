require('dotenv').config();
const fs = require('node:fs');
const path = require('node:path');
const { Client, Collection, GatewayIntentBits, MessageFlags } = require('discord.js');

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
    ],
});
client.commands = new Collection();
const PREFIX = '+';
const STATE_PATH = path.join(__dirname, 'data', 'ambrosia-state.json');
const INSTANCE_LOCK_PATH = path.join(__dirname, 'data', 'ambrosia-main.lock');
const VERIFY_EXPIRES_MS = null; // null = no verification expiry
const VERIFY_EXEMPT_COMMANDS = new Set(['verify', 'vote', 'verifylist', 'unverify', 'verifyuser', 'purge', 'channel']);
const SCAM_PATTERNS = [
    /security you are not human robot verify/i,
    /\+200\b.*security.*robot verify/i,
];
const DEFAULT_SECURITY_LOG_CHANNEL_ID = process.env.SECURITY_LOG_CHANNEL_ID || '1484410870758113451';

function isPidRunning(pid) {
    if (!Number.isInteger(pid) || pid <= 0) return false;
    try {
        process.kill(pid, 0);
        return true;
    } catch (error) {
        return false;
    }
}

function writeInstanceLock() {
    const fd = fs.openSync(INSTANCE_LOCK_PATH, 'wx');
    const content = {
        pid: process.pid,
        startedAt: new Date().toISOString(),
    };
    fs.writeFileSync(fd, JSON.stringify(content, null, 2));
    fs.closeSync(fd);
}

function acquireInstanceLock() {
    try {
        writeInstanceLock();
        return;
    } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
    }

    let existingPid = null;
    try {
        const raw = JSON.parse(fs.readFileSync(INSTANCE_LOCK_PATH, 'utf8'));
        existingPid = Number(raw?.pid);
    } catch (error) {
        existingPid = null;
    }

    if (existingPid && existingPid !== process.pid && isPidRunning(existingPid)) {
        console.error(`Another bot instance is already running (PID ${existingPid}). Exiting.`);
        process.exit(1);
    }

    try {
        fs.unlinkSync(INSTANCE_LOCK_PATH);
    } catch (error) {
        // ignore stale lock cleanup failures
    }

    writeInstanceLock();
}

function releaseInstanceLock() {
    try {
        if (!fs.existsSync(INSTANCE_LOCK_PATH)) return;
        const raw = JSON.parse(fs.readFileSync(INSTANCE_LOCK_PATH, 'utf8'));
        if (Number(raw?.pid) === process.pid) {
            fs.unlinkSync(INSTANCE_LOCK_PATH);
        }
    } catch (error) {
        // ignore cleanup errors on shutdown
    }
}

acquireInstanceLock();
process.on('exit', releaseInstanceLock);
process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));

function loadState() {
    if (!fs.existsSync(STATE_PATH)) {
        return { version: 1, parties: {}, players: {}, disabledUsers: {}, verifiedUsers: {}, pendingVerifications: {} };
    }
    return JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
}

function saveState(state) {
    fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
}

function ensureStateDefaults(state) {
    if (!state.disabledUsers) state.disabledUsers = {};
    if (!state.parties) state.parties = {};
    if (!state.players) state.players = {};
    if (!state.verifiedUsers) state.verifiedUsers = {};
    if (!state.pendingVerifications) state.pendingVerifications = {};
    if (!state.settings) state.settings = {};
    if (!state.guildSettings) state.guildSettings = {};
}

function isUserVerified(state, userId) {
    if (!state.verifiedUsers || !state.verifiedUsers[userId]) return false;
    const entry = state.verifiedUsers[userId];
    if (!VERIFY_EXPIRES_MS) return true;
    const expiresAt = entry.expiresAt || (entry.at ? (new Date(entry.at).getTime() + VERIFY_EXPIRES_MS) : null);
    if (expiresAt && Date.now() > expiresAt) {
        delete state.verifiedUsers[userId];
        saveState(state);
        return false;
    }
    return true;
}

function getSecurityLogChannelId(state, guildId) {
    if (guildId && state.guildSettings?.[guildId]?.securityLogChannelId) {
        return state.guildSettings[guildId].securityLogChannelId;
    }
    return state.settings?.securityLogChannelId || DEFAULT_SECURITY_LOG_CHANNEL_ID || null;
}

async function handleExpiredVerification(state, userId, client) {
    const pending = state.pendingVerifications?.[userId];
    if (!pending) return false;
    if (Date.now() <= pending.expiresAt) return false;
    if (state.verifiedUsers?.[userId]) {
        delete state.pendingVerifications[userId];
        saveState(state);
        return false;
    }
    delete state.pendingVerifications[userId];
    saveState(state);
    if (client) {
        try {
            const targetUser = await client.users.fetch(userId);
            await targetUser.send('Ambrosia Security: Verification expired. Please run /verify again to get a new code.');
        } catch (err) {
            // ignore DM failures
        }
        const logChannelId = getSecurityLogChannelId(state, pending.guildId);
        if (logChannelId) {
            try {
                const channel = await client.channels.fetch(logChannelId);
                if (channel && channel.isTextBased()) {
                    await channel.send(`Ambrosia Security: Verification expired for <@${userId}> (${userId}).`);
                }
            } catch (err) {
                // ignore log failures
            }
        }
    }
    return true;
}

async function checkAndBlockScam(message) {
    if (!message?.content) return false;
    const state = loadState();
    ensureStateDefaults(state);
    if (isUserVerified(state, message.author.id)) return false;
    const text = message.content.toLowerCase();
    if (!SCAM_PATTERNS.some((pattern) => pattern.test(text))) return false;
    try {
        await message.delete();
    } catch (err) {
        console.error('Security delete failed:', err);
    }
    try {
        await message.channel.send(`${message.author} message blocked by security.`);
    } catch (err) {
        console.error('Security alert failed:', err);
    }
    return true;
}

function tokenize(input) {
    const tokens = [];
    const regex = /"([^"]+)"|'([^']+)'|(\S+)/g;
    let match = null;
    while ((match = regex.exec(input)) !== null) {
        tokens.push(match[1] || match[2] || match[3]);
    }
    return tokens;
}

function parseNumber(value) {
    if (!value) return null;
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
}

function resolveUserFromHandle(tokens, message) {
    if (!message?.guild || !tokens?.length) return null;
    const handleToken = tokens.find((token) => token.startsWith('@'));
    if (!handleToken) return null;
    const handle = handleToken.slice(1).trim().toLowerCase();
    if (!handle) return null;
    const members = message.guild.members?.cache;
    if (!members || members.size === 0) return null;
    const match = members.find((member) => {
        const username = member.user?.username?.toLowerCase();
        const displayName = member.displayName?.toLowerCase();
        return username === handle || displayName === handle;
    });
    return match?.user ?? null;
}

function parseAmbrosia(tokens, message) {
    if (tokens.length === 0) {
        return { error: 'Usage: +ambrosia <story|levels|skills|bosses|waves|other|play>' };
    }
    const parsed = { name: 'ambrosia', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    const first = tokens.shift().toLowerCase();
    if (first === 'play') {
        parsed.subcommandGroup = 'play';
        const sub = tokens.shift();
        if (!sub) return { error: 'Usage: +ambrosia play <start|join|leave|party|status|act|skills|relics|equip|unequip|log>' };
        parsed.subcommand = sub.toLowerCase();
        if (parsed.subcommand === 'start') {
            for (const token of tokens) {
                const value = token.toLowerCase();
                if (['easy', 'story', 'normal', 'hard', 'nightmare'].includes(value)) {
                    parsed.stringOptions.difficulty = value;
                } else if (['campaign', 'endless'].includes(value)) {
                    parsed.stringOptions.mode = value;
                }
            }
        } else if (parsed.subcommand === 'join') {
            const leader = message.mentions.users.first();
            if (leader) parsed.userOptions.leader = leader;
        } else if (parsed.subcommand === 'equip' || parsed.subcommand === 'unequip') {
            if (tokens.length > 0) {
                parsed.stringOptions.relic = tokens.join(' ');
            }
        } else if (parsed.subcommand === 'log') {
            const page = parseNumber(tokens[0]);
            if (page) parsed.integerOptions.page = Math.floor(page);
        } else if (parsed.subcommand === 'act') {
            const action = tokens.shift();
            if (!action) return { error: 'Usage: +ambrosia play act <attack|defend|focus|pass|skill|item>' };
            parsed.stringOptions.action = action.toLowerCase();
            if (parsed.stringOptions.action === 'skill') {
                if (!tokens[0]) return { error: 'Usage: +ambrosia play act skill \"<skill name>\" [target] [@ally]' };
                const nameTokens = [];
                while (tokens.length > 0) {
                    const token = tokens[0];
                    if (token.startsWith('@')) break;
                    if (/^<@!?\\d+>$/.test(token)) break;
                    if (Number.isFinite(Number(token))) break;
                    nameTokens.push(tokens.shift());
                }
                if (nameTokens.length === 0) {
                    return { error: 'Usage: +ambrosia play act skill \"<skill name>\" [target] [@ally]' };
                }
                parsed.stringOptions.skill = nameTokens.join(' ');
            } else if (parsed.stringOptions.action === 'item') {
                if (!tokens[0]) return { error: 'Usage: +ambrosia play act item \"<item name>\" [@ally]' };
                const nameTokens = [];
                while (tokens.length > 0) {
                    const token = tokens[0];
                    if (token.startsWith('@')) break;
                    if (/^<@!?\\d+>$/.test(token)) break;
                    if (Number.isFinite(Number(token))) break;
                    nameTokens.push(tokens.shift());
                }
                if (nameTokens.length === 0) {
                    return { error: 'Usage: +ambrosia play act item \"<item name>\" [@ally]' };
                }
                parsed.stringOptions.item = nameTokens.join(' ');
            }
            const target = tokens.find((token) => Number.isFinite(Number(token)));
            if (target) parsed.integerOptions.target = Math.floor(Number(target));
            const ally = message.mentions.users.first();
            if (ally) {
                parsed.userOptions.ally = ally;
            } else {
                const fallback = resolveUserFromHandle(tokens, message);
                if (fallback) parsed.userOptions.ally = fallback;
                const handleToken = tokens.find((token) => token.startsWith('@'));
                if (handleToken && !parsed.userOptions.ally) {
                    parsed.stringOptions.ally = handleToken.slice(1);
                }
            }
        }
        return parsed;
    }

    parsed.subcommand = first;
    if (['story', 'levels', 'skills', 'bosses', 'waves', 'other'].includes(first)) {
        const page = parseNumber(tokens[0]);
        if (page) parsed.integerOptions.page = Math.floor(page);
        return parsed;
    }

    return { error: 'Unknown ambrosia subcommand.' };
}

function parseShop(tokens) {
    const parsed = { name: 'shop', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    if (tokens.length === 0) return parsed;
    const firstToken = tokens[0]?.toLowerCase();
    if (['item', 'weapon', 'skills'].includes(firstToken)) {
        parsed.stringOptions.menu = tokens.shift().toLowerCase();
        const page = parseNumber(tokens[0]);
        if (page) parsed.integerOptions.page = Math.floor(page);
        return parsed;
    }
    if (tokens[0].toLowerCase() === 'menu') {
        parsed.stringOptions.menu = tokens[1] ? tokens[1].toLowerCase() : null;
        const page = parseNumber(tokens[2]);
        if (page) parsed.integerOptions.page = Math.floor(page);
        return parsed;
    }
    parsed.stringOptions.item = tokens[0];
    const qty = parseNumber(tokens[1]);
    if (qty) parsed.integerOptions.quantity = Math.floor(qty);
    return parsed;
}

function parseMarket(tokens) {
    const parsed = { name: 'market', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    if (tokens.length === 0) return parsed;
    const first = tokens.shift().toLowerCase();
    if (first === 'refresh') {
        parsed.stringOptions.action = 'refresh';
        return parsed;
    }
    if (first === 'buy') {
        const id = parseNumber(tokens[0]);
        if (!id) return { error: 'Usage: +market buy <id>' };
        parsed.integerOptions.id = Math.floor(id);
        return parsed;
    }
    if (first === 'page') {
        const page = parseNumber(tokens[0]);
        if (!page) return { error: 'Usage: +market page <number>' };
        parsed.integerOptions.page = Math.floor(page);
        return parsed;
    }
    const page = parseNumber(first);
    if (page) {
        parsed.integerOptions.page = Math.floor(page);
        return parsed;
    }
    return { error: 'Usage: +market [page <number>|buy <id>]' };
}

function parseInventory(tokens, message) {
    const parsed = { name: 'inventory', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    if (tokens.length === 0) {
        parsed.subcommand = 'show';
        return parsed;
    }
    const sub = tokens.shift().toLowerCase();
    parsed.subcommand = sub;
    if (sub === 'use') {
        if (tokens[0]) parsed.stringOptions.item = tokens.shift();
        const target = message.mentions.users.first();
        if (target) parsed.userOptions.target = target;
    } else if (sub === 'equip') {
        if (tokens[0]) parsed.stringOptions.weapon = tokens.join(' ');
    }
    return parsed;
}

function parseTrade(tokens, message) {
    const parsed = { name: 'trade', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    if (tokens.length === 0) return { error: 'Usage: +trade <coin|item> @user <amount> [item]' };
    parsed.stringOptions.type = tokens.shift().toLowerCase();
    const user = message.mentions.users.first();
    if (user) parsed.userOptions.user = user;
    const amountToken = tokens.find((token) => Number.isFinite(Number(token)));
    const amount = parseNumber(amountToken);
    if (amount) parsed.integerOptions.amount = Math.floor(amount);
    if (parsed.stringOptions.type === 'item') {
        const itemToken = tokens.filter((token) => token !== amountToken).filter((token) => !/^<@!?(\d+)>$/.test(token));
        if (itemToken.length > 0) parsed.stringOptions.item = itemToken[itemToken.length - 1];
    }
    return parsed;
}

function parseLeaderboard(tokens) {
    const parsed = { name: 'leaderboard', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    for (const token of tokens) {
        const value = String(token || '').toLowerCase();
        if (!value) continue;
        if (['server', 'guild', 'global', 'all'].includes(value)) {
            parsed.stringOptions.scope = value === 'guild' ? 'server' : (value === 'all' ? 'global' : value);
            continue;
        }
        if (!parsed.stringOptions.type) parsed.stringOptions.type = value;
    }
    return parsed;
}

function parsePurge(tokens) {
    const parsed = { name: 'purge', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    const amount = parseNumber(tokens[0]);
    if (!amount || amount < 1) return { error: 'Usage: +purge <amount 1-100>' };
    parsed.integerOptions.amount = Math.min(100, Math.floor(amount));
    return parsed;
}

function parseChannel(tokens) {
    const parsed = { name: 'channel', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    const sub = (tokens.shift() || 'show').toLowerCase();
    if (sub === 'show') {
        parsed.subcommand = 'show';
        return parsed;
    }
    if (sub !== 'set') {
        return { error: 'Usage: +channel <set|show> [#channel|channel_id]' };
    }
    parsed.subcommand = 'set';
    let id = null;
    for (const token of tokens) {
        const mentionMatch = token.match(/^<#(\d+)>$/);
        if (mentionMatch) {
            id = mentionMatch[1];
            break;
        }
        if (/^\d{16,20}$/.test(token)) {
            id = token;
            break;
        }
    }
    if (!id) return { error: 'Usage: +channel set #channel or +channel set <channel_id>' };
    parsed.stringOptions.channel_id = id;
    return parsed;
}

function parseMod(tokens, message) {
    const parsed = { name: 'mod', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    if (tokens.length === 0) {
        return { error: 'Usage: +mod set @user <co-owner|admin|mod|staff|admin-support|mod-support|staff-support> | +mod remove @user' };
    }
    const roles = ['co-owner', 'admin', 'mod', 'staff', 'admin-support', 'mod-support', 'staff-support'];
    const first = tokens.shift().toLowerCase();
    if (first === 'remove' || first === 'delete' || first === 'clear') {
        parsed.subcommand = 'remove';
    } else if (first === 'set') {
        const roleTokens = tokens
            .filter((token) => !/^<@!?(\d+)>$/.test(token))
            .filter((token) => !token.startsWith('@'));
        let role = roleTokens.shift();
        if (!role) {
            return { error: 'Usage: +mod set @user <co-owner|admin|mod|staff|admin-support|mod-support|staff-support> | +mod remove @user' };
        }
        role = role.toLowerCase();
        const next = roleTokens[0]?.toLowerCase();
        if (next === 'support' && ['admin', 'mod', 'staff'].includes(role)) {
            role = `${role}-support`;
        }
        if (!roles.includes(role)) {
            return { error: 'Usage: +mod set @user <co-owner|admin|mod|staff|admin-support|mod-support|staff-support> | +mod remove @user' };
        }
        parsed.subcommand = 'set';
        parsed.stringOptions.role = role;
    } else {
        let role = first;
        const next = tokens[0]?.toLowerCase();
        if (next === 'support' && ['admin', 'mod', 'staff'].includes(role)) {
            tokens.shift();
            role = `${role}-support`;
        }
        if (roles.includes(role)) {
            parsed.subcommand = 'set';
            parsed.stringOptions.role = role;
        } else {
            return { error: 'Usage: +mod set @user <co-owner|admin|mod|staff|admin-support|mod-support|staff-support> | +mod remove @user' };
        }
    }

    const user = message.mentions.users.first();
    if (user) {
        parsed.userOptions.user = user;
        return parsed;
    }
    const fallback = resolveUserFromHandle(tokens, message);
    if (fallback) {
        parsed.userOptions.user = fallback;
        return parsed;
    }
    return { error: 'User is required.' };
}

function parseAdd(tokens, message) {
    const parsed = { name: 'add', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    if (tokens.length === 0) {
        return { error: 'Usage: +add <item|weapon|skill|stat|custom> @user ...' };
    }
    const sub = tokens.shift().toLowerCase();
    if (!['item', 'weapon', 'skill', 'stat', 'custom'].includes(sub)) {
        return { error: 'Usage: +add <item|weapon|skill|stat|custom> @user ...' };
    }
    parsed.subcommand = sub;

    const user = message.mentions.users.first() || resolveUserFromHandle(tokens, message);
    if (!user) {
        return { error: 'Usage: +add <item|weapon|skill|stat|custom> @user ...' };
    }
    parsed.userOptions.user = user;

    const cleanedTokens = tokens.filter((token) => !/^<@!?(\d+)>$/.test(token) && !token.startsWith('@'));

    if (sub === 'item') {
        if (cleanedTokens.length === 0) return { error: 'Usage: +add item @user <item name> [amount]' };
        const last = cleanedTokens[cleanedTokens.length - 1];
        const amount = parseNumber(last);
        if (amount && amount > 0) {
            parsed.integerOptions.amount = Math.floor(amount);
            cleanedTokens.pop();
        }
        if (cleanedTokens.length === 0) return { error: 'Usage: +add item @user <item name> [amount]' };
        parsed.stringOptions.item = cleanedTokens.join(' ');
        return parsed;
    }

    if (sub === 'weapon') {
        if (cleanedTokens.length === 0) return { error: 'Usage: +add weapon @user <weapon name> [amount]' };
        const last = cleanedTokens[cleanedTokens.length - 1];
        const amount = parseNumber(last);
        if (amount && amount > 0) {
            parsed.integerOptions.amount = Math.floor(amount);
            cleanedTokens.pop();
        }
        if (cleanedTokens.length === 0) return { error: 'Usage: +add weapon @user <weapon name> [amount]' };
        parsed.stringOptions.weapon = cleanedTokens.join(' ');
        return parsed;
    }

    if (sub === 'skill') {
        if (cleanedTokens.length === 0) return { error: 'Usage: +add skill @user <skill name>' };
        parsed.stringOptions.skill = cleanedTokens.join(' ');
        return parsed;
    }

    if (sub === 'stat') {
        if (cleanedTokens.length < 2) return { error: 'Usage: +add stat @user <gold|xp|level|hp|attack|armor|energy|focus|max_hp|max_energy|max_focus> <amount>' };
        const statRaw = String(cleanedTokens[0] || '').toLowerCase();
        const map = {
            maxhp: 'max_hp',
            maxenergy: 'max_energy',
            maxfocus: 'max_focus',
        };
        const stat = map[statRaw] || statRaw;
        const amount = parseNumber(cleanedTokens[1]);
        if (!amount || amount <= 0) {
            return { error: 'Usage: +add stat @user <gold|xp|level|hp|attack|armor|energy|focus|max_hp|max_energy|max_focus> <amount>' };
        }
        parsed.stringOptions.stat = stat;
        parsed.integerOptions.amount = Math.floor(amount);
        return parsed;
    }

    if (sub === 'custom') {
        if (cleanedTokens.length === 0) return { error: 'Usage: +add custom @user hp 500 maxhp 700 energy 6 maxenergy 12 focus 3 maxfocus 8' };
        parsed.stringOptions.values = cleanedTokens.join(' ');
        return parsed;
    }

    return parsed;
}

function parseUserCommand(tokens, message, name) {
    const parsed = { name, subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    const user = message.mentions.users.first();
    if (user) parsed.userOptions.user = user;
    if (!user && name === 'profile' && tokens.length > 0) {
        parsed.stringOptions.query = tokens.join(' ');
    }
    if (!user && name === 'unverify') {
        const idToken = tokens.find((token) => /^\d{16,20}$/.test(token));
        if (idToken) parsed.stringOptions.user_id = idToken;
    }
    if (!user && (name === 'verify' || name === 'verifyuser')) {
        const idToken = tokens.find((token) => /^\d{16,20}$/.test(token));
        if (idToken) parsed.stringOptions.user_id = idToken;
    }
    if (name === 'verify') {
        let codeToken = tokens.find((token) => /^\d{6}$/.test(token));
        const pairToken = tokens.find((token) => /^code[:=]\d{6}$/i.test(token));
        if (!codeToken && pairToken) {
            codeToken = pairToken.split(/[:=]/)[1];
        }
        if (!codeToken) {
            const codeIndex = tokens.findIndex((token) => /^code$/i.test(token));
            if (codeIndex !== -1 && /^\d{6}$/.test(tokens[codeIndex + 1] || '')) {
                codeToken = tokens[codeIndex + 1];
            }
        }
        if (codeToken && !parsed.userOptions.user) parsed.stringOptions.code = codeToken;
    }
    return parsed;
}

function normalizeReplyPayload(payload) {
    if (typeof payload === 'string') return { content: payload };
    if (!payload || typeof payload !== 'object') return {};
    const next = { ...payload };
    if (Object.prototype.hasOwnProperty.call(next, 'ephemeral')) {
        if (next.ephemeral && next.flags == null) {
            next.flags = MessageFlags.Ephemeral;
        }
        delete next.ephemeral;
    }
    return next;
}

async function safeInteractionReply(interaction, payload) {
    const data = normalizeReplyPayload(payload);
    try {
        if (interaction.replied || interaction.deferred) {
            return await interaction.followUp(data);
        }
        return await interaction.reply(data);
    } catch (error) {
        // Ignore expired/already-acked interaction replies.
        if (error?.code === 10062 || error?.code === 40060) {
            console.warn(`Interaction response skipped (${error.code}).`);
            return null;
        }
        throw error;
    }
}

function buildPrefixInteraction(message, parsed) {
    let replied = false;
    let deferred = false;
    const normalizePayload = (payload) => {
        if (!payload) return {};
        if (typeof payload === 'string') return { content: payload };
        return payload;
    };
    return {
        user: message.author,
        member: message.member,
        memberPermissions: message.member?.permissions || null,
        guild: message.guild || null,
        guildId: message.guildId || null,
        channel: message.channel,
        client: message.client,
        id: message.id,
        createdTimestamp: message.createdTimestamp,
        createdAt: message.createdAt,
        replied,
        deferred,
        inGuild: () => Boolean(message.guild),
        options: {
            getString: (name) => parsed.stringOptions[name] ?? null,
            getInteger: (name) => parsed.integerOptions[name] ?? null,
            getUser: (name) => parsed.userOptions[name] ?? null,
            getChannel: (name) => parsed.userOptions[name] ?? null,
            getSubcommandGroup: () => parsed.subcommandGroup ?? null,
            getSubcommand: () => parsed.subcommand ?? null,
        },
        reply: async (payload) => {
            replied = true;
            const content = normalizePayload(payload);
            return message.channel.send({
                content: content.content || null,
                embeds: content.embeds,
                files: content.files,
                components: content.components,
            });
        },
        followUp: async (payload) => {
            const content = normalizePayload(payload);
            return message.channel.send({
                content: content.content || null,
                embeds: content.embeds,
                files: content.files,
                components: content.components,
            });
        },
    };
}

// 1. Load Commands
const commandsPath = path.join(__dirname, 'commands');
const commandFiles = fs.readdirSync(commandsPath).filter(file => file.endsWith('.js'));

for (const file of commandFiles) {
    const filePath = path.join(commandsPath, file);
    const command = require(filePath);
    if ('data' in command && 'execute' in command) {
        client.commands.set(command.data.name, command);
    }
}

// 2. Interaction Handler
client.on('interactionCreate', async interaction => {
    if (interaction.isStringSelectMenu()) {
        const customId = String(interaction.customId || '');
        if (customId.startsWith('help_menu:')) {
            const command = client.commands.get('help');
            if (command && typeof command.handleSelect === 'function') {
                try {
                    await command.handleSelect(interaction);
                } catch (error) {
                    console.error('Select Menu Error:', error);
                    if (!interaction.replied && !interaction.deferred) {
                        await safeInteractionReply(interaction, { content: 'There was an error handling this menu.', flags: MessageFlags.Ephemeral });
                    }
                }
            }
            return;
        }
        if (customId.startsWith('support_menu:')) {
            const command = client.commands.get('support');
            if (command && typeof command.handleSelect === 'function') {
                try {
                    await command.handleSelect(interaction);
                } catch (error) {
                    console.error('Select Menu Error:', error);
                    if (!interaction.replied && !interaction.deferred) {
                        await safeInteractionReply(interaction, { content: 'There was an error handling this menu.', flags: MessageFlags.Ephemeral });
                    }
                }
            }
            return;
        }
        return;
    }
    if (interaction.isButton()) {
        const customId = String(interaction.customId || '');
        if (customId.startsWith('support_action:') || customId.startsWith('support_unban:') || customId.startsWith('support_ban:')) {
            const command = client.commands.get('support');
            if (command && typeof command.handleButton === 'function') {
                try {
                    await command.handleButton(interaction);
                } catch (error) {
                    console.error('Button Error:', error);
                    if (!interaction.replied && !interaction.deferred) {
                        await safeInteractionReply(interaction, { content: 'There was an error handling this button.', flags: MessageFlags.Ephemeral });
                    }
                }
            }
            return;
        }
    }
    if (interaction.isModalSubmit()) {
        const customId = String(interaction.customId || '');
        if (customId.startsWith('support_modal:')) {
            const command = client.commands.get('support');
            if (command && typeof command.handleModal === 'function') {
                try {
                    await command.handleModal(interaction);
                } catch (error) {
                    console.error('Modal Error:', error);
                    if (!interaction.replied && !interaction.deferred) {
                        await safeInteractionReply(interaction, { content: 'There was an error handling this form.', flags: MessageFlags.Ephemeral });
                    }
                }
            }
            return;
        }
        if (customId.startsWith('support_ban_modal:')) {
            const command = client.commands.get('support');
            if (command && typeof command.handleOwnerBanModal === 'function') {
                try {
                    await command.handleOwnerBanModal(interaction);
                } catch (error) {
                    console.error('Modal Error:', error);
                    if (!interaction.replied && !interaction.deferred) {
                        await safeInteractionReply(interaction, { content: 'There was an error handling this form.', flags: MessageFlags.Ephemeral });
                    }
                }
            }
            return;
        }
        if (customId.startsWith('support_reply:')) {
            const command = client.commands.get('support');
            if (command && typeof command.handleOwnerModal === 'function') {
                try {
                    await command.handleOwnerModal(interaction);
                } catch (error) {
                    console.error('Modal Error:', error);
                    if (!interaction.replied && !interaction.deferred) {
                        await safeInteractionReply(interaction, { content: 'There was an error handling this form.', flags: MessageFlags.Ephemeral });
                    }
                }
            }
            return;
        }
        return;
    }
    if (interaction.isButton()) {
        const customId = String(interaction.customId || '');
        if (customId.startsWith('skills_page:') || customId.startsWith('story_page:') || customId.startsWith('list_page:')) {
            const command = client.commands.get('ambrosia');
            if (command && typeof command.handleButton === 'function') {
                try {
                    await command.handleButton(interaction);
                } catch (error) {
                    console.error('Button Error:', error);
                    if (!interaction.replied && !interaction.deferred) {
                        await safeInteractionReply(interaction, { content: 'There was an error handling this button.', flags: MessageFlags.Ephemeral });
                    }
                }
            }
            return;
        }
        if (customId.startsWith('shop_page:')) {
            const command = client.commands.get('shop');
            if (command && typeof command.handleButton === 'function') {
                try {
                    await command.handleButton(interaction);
                } catch (error) {
                    console.error('Button Error:', error);
                    if (!interaction.replied && !interaction.deferred) {
                        await safeInteractionReply(interaction, { content: 'There was an error handling this button.', flags: MessageFlags.Ephemeral });
                    }
                }
            }
            return;
        }
        return;
    }
    if (!interaction.isChatInputCommand()) return;

    const command = client.commands.get(interaction.commandName);
    if (!command) return;

    const state = loadState();
    ensureStateDefaults(state);
    if (await handleExpiredVerification(state, interaction.user.id, interaction.client)) {
        return safeInteractionReply(interaction, { content: 'Ambrosia Security: Verification expired. Use /verify again for a new code.', flags: MessageFlags.Ephemeral });
    }
    if (!VERIFY_EXEMPT_COMMANDS.has(interaction.commandName) && !isUserVerified(state, interaction.user.id)) {
        return safeInteractionReply(interaction, { content: 'You must verify first. Use /verify to get a 6-digit code image.', flags: MessageFlags.Ephemeral });
    }

    try {
        // Just execute the command. 
        // We moved the player data loading inside the command file itself 
        // to avoid "Application did not respond" errors.
        await command.execute(interaction);
    } catch (error) {
        console.error("Command Error:", error);
        const errorMessage = { content: 'There was an error executing this command!', flags: MessageFlags.Ephemeral };
        await safeInteractionReply(interaction, errorMessage);
    }
});

client.on('messageCreate', async message => {
    if (!message.content || message.author.bot) return;
    let state = loadState();
    ensureStateDefaults(state);
    if (await handleExpiredVerification(state, message.author.id, message.client)) {
        try {
            await message.channel.send(`${message.author} verification expired. Use /verify again. (Ambrosia Security)`);
        } catch (err) {
            // ignore send failures
        }
        return;
    }
    if (await checkAndBlockScam(message)) return;
    if (!message.content.startsWith(PREFIX)) return;
    const input = message.content.slice(PREFIX.length).trim();
    if (!input) return;
    const tokens = tokenize(input);
    const name = tokens.shift()?.toLowerCase();
    if (!name) return;

    let parsed = null;
    if (name === 'ambrosia') parsed = parseAmbrosia(tokens, message);
    else if (name === 'start') parsed = parseAmbrosia(['play', 'start', ...tokens], message);
    else if (name === 'act') parsed = parseAmbrosia(['play', 'act', ...tokens], message);
    else if (name === 'join') parsed = parseAmbrosia(['play', 'join', ...tokens], message);
    else if (name === 'skills') parsed = parseAmbrosia(['play', 'skills', ...tokens], message);
    else if (name === 'status') parsed = parseAmbrosia(['play', 'status', ...tokens], message);
    else if (name === 'party') parsed = parseAmbrosia(['play', 'party', ...tokens], message);
    else if (name === 'leave') parsed = parseAmbrosia(['play', 'leave', ...tokens], message);
    else if (name === 'story') parsed = parseAmbrosia(['story', ...tokens], message);
    else if (name === 'levels') parsed = parseAmbrosia(['levels', ...tokens], message);
    else if (name === 'bosses') parsed = parseAmbrosia(['bosses', ...tokens], message);
    else if (name === 'waves') parsed = parseAmbrosia(['waves', ...tokens], message);
    else if (name === 'other') parsed = parseAmbrosia(['other', ...tokens], message);
    else if (name === 'shop') parsed = parseShop(tokens);
    else if (name === 'market') parsed = parseMarket(tokens);
    else if (name === 'inventory') parsed = parseInventory(tokens, message);
    else if (name === 'trade') parsed = parseTrade(tokens, message);
    else if (name === 'ban') parsed = parseUserCommand(tokens, message, 'ban');
    else if (name === 'unban') parsed = parseUserCommand(tokens, message, 'unban');
    else if (name === 'add') parsed = parseAdd(tokens, message);
    else if (name === 'help') parsed = { name: 'help', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    else if (name === 'rules') parsed = { name: 'rules', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    else if (name === 'profile') parsed = parseUserCommand(tokens, message, 'profile');
    else if (name === 'leaderboard') parsed = parseLeaderboard(tokens);
    else if (name === 'balance') parsed = parseUserCommand(tokens, message, 'balance');
    else if (name === 'mod') parsed = parseMod(tokens, message);
    else if (name === 'modlist') parsed = { name: 'modlist', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    else if (name === 'verify') parsed = parseUserCommand(tokens, message, 'verify');
    else if (name === 'verifyuser') parsed = parseUserCommand(tokens, message, 'verifyuser');
    else if (name === 'unverify') parsed = parseUserCommand(tokens, message, 'unverify');
    else if (name === 'verifylist') parsed = { name: 'verifylist', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    else if (name === 'rank') parsed = { name: 'rank', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    else if (name === 'ping') parsed = { name: 'ping', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    else if (name === 'vote') parsed = { name: 'vote', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    else if (name === 'support') parsed = { name: 'support', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    else if (name === 'banlist') parsed = { name: 'banlist', subcommandGroup: null, subcommand: null, stringOptions: {}, integerOptions: {}, userOptions: {} };
    else if (name === 'afk') parsed = parseUserCommand(tokens, message, 'afk');
    else if (name === 'purge') parsed = parsePurge(tokens);
    else if (name === 'channel') parsed = parseChannel(tokens);
    else return message.channel.send('Unknown prefix command.');

    if (parsed?.error) return message.channel.send(parsed.error);

    const command = client.commands.get(parsed.name);
    if (!command) return message.channel.send('Command not found.');

    state = loadState();
    ensureStateDefaults(state);
    if (!VERIFY_EXEMPT_COMMANDS.has(parsed.name) && !isUserVerified(state, message.author.id)) {
        return message.channel.send('You must verify first. Use /verify to get a 6-digit code image.');
    }

    try {
        const interaction = buildPrefixInteraction(message, parsed);
        await command.execute(interaction);
    } catch (error) {
        console.error('Prefix Command Error:', error);
        await message.channel.send('There was an error executing this command!');
    }
});

client.on('error', (error) => {
    console.error('Client Error:', error);
});

client.once('clientReady', (c) => {
    console.log(`✅ ${c.user.tag} is online and ready for adventure!`);
});

client.login(process.env.DISCORD_TOKEN);


