import express from "express";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
import { WebSocketServer } from "ws";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 5177;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// ---------- DB ----------
const db = new Database(path.join(__dirname, "pangolia.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS characters (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  faction TEXT NOT NULL,
  level INTEGER NOT NULL,
  xp INTEGER NOT NULL,
  skill_points INTEGER NOT NULL,
  micro_tokens INTEGER NOT NULL,
  macro_tokens INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS action_log (
  id TEXT PRIMARY KEY,
  char_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  scope TEXT NOT NULL,        -- micro|macro
  action_key TEXT NOT NULL,
  district_id TEXT NOT NULL,
  delta_influence INTEGER NOT NULL,
  meta TEXT NOT NULL
);
`);

// ---------- WORLD MODEL (server authoritative, persisted minimal) ----------
/**
 * MMORPG Stack minimal :
 * - World graph (districts + influence per faction)
 * - Micro actions (street-level)
 * - Macro actions (institutional / policy)
 * - Progression (XP, levels, skills)
 * - Live sync (WS broadcast)
 *
 * Conquête: Bruxelles -> Wallonie -> Francophonie (zones lock/unlock)
 */

const FACTIONS = [
  { key: "pangoliens", name: "Collectif Pangolien", color: "#8ef" },
  { key: "grille", name: "La Grille (Architecte/Wintermute)", color: "#9f8" },
  { key: "ombre", name: "L’Ombre (Sauron numérique)", color: "#f88" },
  { key: "resistance", name: "Résistance Fragmentée", color: "#ff8" }
];

const ZONES = [
  { key: "bruxelles", name: "Bruxelles", unlockLevel: 1 },
  { key: "wallonie", name: "Wallonie", unlockLevel: 8 },
  { key: "francophonie", name: "Francophonie", unlockLevel: 15 }
];

// 12 districts (fiction + réel stylisé)
const DISTRICTS = [
  { id: "bxl-ixelles", zone: "bruxelles", name: "Ixelles / Matonge", tags: ["culture", "réseaux", "campus"] },
  { id: "bxl-eu", zone: "bruxelles", name: "Quartier Européen", tags: ["institutions", "lobby", "procédure"] },
  { id: "bxl-molenbeek", zone: "bruxelles", name: "Molenbeek", tags: ["tension", "récits", "réputation"] },
  { id: "bxl-centre", zone: "bruxelles", name: "Centre / Bourse", tags: ["médias", "flux", "tourisme"] },
  { id: "bxl-schaerbeek", zone: "bruxelles", name: "Schaerbeek", tags: ["densité", "signal", "terrain"] },
  { id: "bxl-anderlecht", zone: "bruxelles", name: "Anderlecht", tags: ["infrastructure", "sport", "filières"] },
  { id: "wal-namur", zone: "wallonie", name: "Namur", tags: ["capitale", "administration"] },
  { id: "wal-liege", zone: "wallonie", name: "Liège", tags: ["industrie", "syndicats", "ports"] },
  { id: "wal-charleroi", zone: "wallonie", name: "Charleroi", tags: ["transition", "fractures", "mémoires"] },
  { id: "wal-mons", zone: "wallonie", name: "Mons", tags: ["tech", "clusters", "stratégie"] },
  { id: "fr-paris", zone: "francophonie", name: "Paris (Hub)", tags: ["centralité", "narratif", "prestige"] },
  { id: "fr-geneve", zone: "francophonie", name: "Genève (Hub)", tags: ["normes", "ONG", "diplomatie"] }
];

// influence[factionKey] = 0..100, total is not fixed (tension matters)
const world = {
  version: 1,
  tick: 0,
  startedAt: new Date().toISOString(),
  districts: Object.fromEntries(
    DISTRICTS.map(d => [
      d.id,
      {
        ...d,
        influence: Object.fromEntries(FACTIONS.map(f => [f.key, 25])),
        heat: 10, // 0..100 (répression / instabilité)
        narrative: []
      }
    ])
  ),
  global: {
    // “retourner le système contre lui-même” => la légitimité devient ressource
    legitimacy: {
      pangoliens: 50,
      grille: 50,
      ombre: 50,
      resistance: 50
    },
    // Indique si le système se “mange” lui-même
    selfInversionIndex: 12 // 0..100
  }
};

// ---------- ACTIONS ----------
const ACTIONS = {
  // MICRO: terrain, proximité, réseaux faibles, perception
  micro: [
    {
      key: "meme_infiltration",
      name: "Infiltration memétique",
      desc: "Retourne les slogans du système pour pousser une doctrine sous couverture.",
      baseInfluence: 3,
      heat: +2,
      requires: { zone: "bruxelles" }
    },
    {
      key: "assembly",
      name: "Assemblée de voisinage",
      desc: "Crée une légitimité locale; peut se faire récupérer par la procédure.",
      baseInfluence: 2,
      heat: +1
    },
    {
      key: "paperwork_poison",
      name: "Poison procédural",
      desc: "Surcharge les processus jusqu’à rendre la décision automatique.",
      baseInfluence: 4,
      heat: +3
    },
    {
      key: "mutual_aid",
      name: "Entraide (anti-stack)",
      desc: "Renforce les liens réels. Baisse le Self-Inversion Index si bien joué.",
      baseInfluence: 2,
      heat: -1,
      sideEffect: { selfInversionDelta: -1 }
    }
  ],

  // MACRO: institutions, indicateurs, plateformes, normes
  macro: [
    {
      key: "kpi_capture",
      name: "Capture des indicateurs (KPI)",
      desc: "Change les métriques pour que la réalité doive s’aligner sur elles.",
      baseInfluence: 6,
      heat: +4,
      requires: { minLevel: 5 }
    },
    {
      key: "platform_unification",
      name: "Plateforme unique",
      desc: "Une seule interface = une seule vision du monde.",
      baseInfluence: 8,
      heat: +6,
      requires: { minLevel: 8, zone: "wallonie" }
    },
    {
      key: "norm_export",
      name: "Export de norme",
      desc: "Rend ta manière de faire obligatoire au-delà du territoire.",
      baseInfluence: 10,
      heat: +8,
      requires: { minLevel: 15, zone: "francophonie" }
    }
  ]
};

function clamp(n, a, b) {
  return Math.max(a, Math.min(b, n));
}

function nowISO() {
  return new Date().toISOString();
}

function districtUnlockedForChar(char, district) {
  const zone = ZONES.find(z => z.key === district.zone);
  return char.level >= zone.unlockLevel;
}

function getAction(scope, key) {
  const list = ACTIONS[scope] || [];
  return list.find(a => a.key === key);
}

// “retourner le système contre lui-même” : plus la légitimité est haute,
// plus on peut faire du contrôle “soft” sans se faire punir.
function computeLegitimacyBuff(factionKey) {
  const L = world.global.legitimacy[factionKey] ?? 50;
  // 0.8 .. 1.25
  return 0.8 + (L / 100) * 0.45;
}

function computeHeatPenalty(district) {
  // 1.0 .. 0.6
  return 1.0 - (district.heat / 100) * 0.4;
}

function xpForDelta(deltaInfluence) {
  // petite progression stable
  return Math.max(1, deltaInfluence);
}

function levelFromXp(xp) {
  // simple curve
  // lvl 1: 0-19, lvl 2: 20-49, lvl 3: 50-89 ...
  let lvl = 1;
  let need = 20;
  let remain = xp;
  while (remain >= need) {
    remain -= need;
    lvl++;
    need = Math.floor(need * 1.35);
    if (lvl > 60) break;
  }
  return lvl;
}

// ---------- AUTH ----------
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return res.status(401).json({ error: "missing_token" });
  try {
    req.auth = verifyToken(token);
    return next();
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
}

function getCharByUser(userId) {
  return db
    .prepare("SELECT * FROM characters WHERE user_id=? LIMIT 1")
    .get(userId);
}

function saveChar(char) {
  db.prepare(`
    UPDATE characters
    SET level=?, xp=?, skill_points=?, micro_tokens=?, macro_tokens=?
    WHERE id=?
  `).run(char.level, char.xp, char.skill_points, char.micro_tokens, char.macro_tokens, char.id);
}

// ---------- EXPRESS ----------
const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/meta", (_req, res) => {
  res.json({ factions: FACTIONS, zones: ZONES, actions: ACTIONS });
});

app.post("/api/register", (req, res) => {
  const { username, password, characterName, faction } = req.body || {};
  const cleanUser = String(username || "").trim().toLowerCase();
  const cleanName = String(characterName || "").trim();
  const cleanFaction = String(faction || "").trim();

  if (!cleanUser || cleanUser.length < 3) return res.status(400).json({ error: "bad_username" });
  if (!password || String(password).length < 6) return res.status(400).json({ error: "bad_password" });
  if (!cleanName || cleanName.length < 3) return res.status(400).json({ error: "bad_characterName" });
  if (!FACTIONS.some(f => f.key === cleanFaction)) return res.status(400).json({ error: "bad_faction" });

  const exists = db.prepare("SELECT id FROM users WHERE username=?").get(cleanUser);
  if (exists) return res.status(409).json({ error: "username_taken" });

  const userId = nanoid();
  const charId = nanoid();
  const pass_hash = bcrypt.hashSync(String(password), 10);

  db.prepare("INSERT INTO users(id, username, pass_hash, created_at) VALUES(?,?,?,?)")
    .run(userId, cleanUser, pass_hash, nowISO());

  db.prepare(`
    INSERT INTO characters(id, user_id, name, faction, level, xp, skill_points, micro_tokens, macro_tokens, created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?)
  `).run(charId, userId, cleanName, cleanFaction, 1, 0, 0, 12, 4, nowISO());

  const token = signToken({ userId });
  res.json({ token });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const cleanUser = String(username || "").trim().toLowerCase();
  const row = db.prepare("SELECT * FROM users WHERE username=?").get(cleanUser);
  if (!row) return res.status(401).json({ error: "bad_credentials" });
  const ok = bcrypt.compareSync(String(password || ""), row.pass_hash);
  if (!ok) return res.status(401).json({ error: "bad_credentials" });
  const token = signToken({ userId: row.id });
  res.json({ token });
});

app.get("/api/me", authMiddleware, (req, res) => {
  const char = getCharByUser(req.auth.userId);
  if (!char) return res.status(404).json({ error: "no_character" });
  res.json({ character: char });
});

app.get("/api/world", authMiddleware, (req, res) => {
  const char = getCharByUser(req.auth.userId);
  if (!char) return res.status(404).json({ error: "no_character" });

  // send only what player can see (unlocked districts)
  const visible = {};
  for (const [id, d] of Object.entries(world.districts)) {
    if (districtUnlockedForChar(char, d)) visible[id] = d;
  }

  res.json({
    world: {
      version: world.version,
      tick: world.tick,
      global: world.global,
      districts: visible
    }
  });
});

// Action endpoint: micro/macro
app.post("/api/action", authMiddleware, (req, res) => {
  const { scope, actionKey, districtId } = req.body || {};
  const sc = String(scope || "").trim();
  const aKey = String(actionKey || "").trim();
  const dId = String(districtId || "").trim();

  const char = getCharByUser(req.auth.userId);
  if (!char) return res.status(404).json({ error: "no_character" });

  const district = world.districts[dId];
  if (!district) return res.status(404).json({ error: "bad_district" });

  if (!districtUnlockedForChar(char, district)) {
    return res.status(403).json({ error: "district_locked" });
  }

  const action = getAction(sc, aKey);
  if (!action) return res.status(400).json({ error: "bad_action" });

  if (action.requires?.minLevel && char.level < action.requires.minLevel) {
    return res.status(403).json({ error: "level_required" });
  }
  if (action.requires?.zone && action.requires.zone !== district.zone) {
    return res.status(403).json({ error: "wrong_zone" });
  }

  // token check
  if (sc === "micro") {
    if (char.micro_tokens <= 0) return res.status(429).json({ error: "no_micro_tokens" });
  } else if (sc === "macro") {
    if (char.macro_tokens <= 0) return res.status(429).json({ error: "no_macro_tokens" });
  } else {
    return res.status(400).json({ error: "bad_scope" });
  }

  // compute influence change
  const factionKey = char.faction;
  const legBuff = computeLegitimacyBuff(factionKey);
  const heatPen = computeHeatPenalty(district);

  // system inversion: plus c’est haut, plus "paperwork" et "kpi" sont puissants
  const inversion = world.global.selfInversionIndex;
  const inversionBuff =
    action.key.includes("paperwork") || action.key.includes("kpi") || action.key.includes("platform")
      ? (1.0 + inversion / 200) // 1.0..1.5
      : 1.0;

  let delta = Math.round(action.baseInfluence * legBuff * heatPen * inversionBuff);

  // Small randomness to avoid deterministic farming (but stable-ish)
  delta += Math.floor((Math.random() * 3) - 1); // -1..+1
  delta = clamp(delta, 1, 15);

  // Apply influence
  district.influence[factionKey] = clamp((district.influence[factionKey] || 0) + delta, 0, 100);

  // Side effects
  district.heat = clamp(district.heat + (action.heat ?? 0), 0, 100);

  if (action.sideEffect?.selfInversionDelta) {
    world.global.selfInversionIndex = clamp(
      world.global.selfInversionIndex + action.sideEffect.selfInversionDelta,
      0,
      100
    );
  }

  // legitimacy shifts: soft control rises with “assembly/mutual aid”, hard rises with "paperwork/kpi"
  const legitDelta =
    action.key.includes("mutual") || action.key.includes("assembly")
      ? +1
      : action.key.includes("paperwork") || action.key.includes("kpi") || action.key.includes("platform")
        ? +2
        : +0;

  world.global.legitimacy[factionKey] = clamp(world.global.legitimacy[factionKey] + legitDelta, 0, 100);

  // Character progression
  const gainedXp = xpForDelta(delta);
  char.xp += gainedXp;

  const newLevel = levelFromXp(char.xp);
  if (newLevel > char.level) {
    const diff = newLevel - char.level;
    char.level = newLevel;
    char.skill_points += diff;
    // on level up: refresh some tokens
    char.micro_tokens += 6;
    char.macro_tokens += 2;
  }

  // consume token
  if (sc === "micro") char.micro_tokens -= 1;
  else char.macro_tokens -= 1;

  saveChar(char);

  // Log
  db.prepare(`
    INSERT INTO action_log(id, char_id, ts, scope, action_key, district_id, delta_influence, meta)
    VALUES(?,?,?,?,?,?,?,?)
  `).run(
    nanoid(),
    char.id,
    nowISO(),
    sc,
    aKey,
    dId,
    delta,
    JSON.stringify({
      legBuff,
      heatPen,
      inversionBuff,
      inversion: world.global.selfInversionIndex
    })
  );

  // narrative line
  district.narrative.unshift({
    ts: nowISO(),
    faction: factionKey,
    action: aKey,
    delta,
    heat: district.heat,
    line: `${char.name} (${factionKey}) exécute ${aKey} → +${delta} influence`
  });
  district.narrative = district.narrative.slice(0, 30);

  world.tick++;
  world.version++;

  broadcastWorldPatch({
    type: "WORLD_PATCH",
    tick: world.tick,
    version: world.version,
    district: district.id,
    payload: {
      influence: district.influence,
      heat: district.heat,
      narrative: district.narrative.slice(0, 10)
    },
    global: world.global
  });

  res.json({
    ok: true,
    delta,
    gainedXp,
    character: {
      level: char.level,
      xp: char.xp,
      skill_points: char.skill_points,
      micro_tokens: char.micro_tokens,
      macro_tokens: char.macro_tokens
    },
    district: {
      id: district.id,
      influence: district.influence,
      heat: district.heat
    },
    global: world.global
  });
});

// Token regen + macro cycle (every 60s = “minute in game”)
setInterval(() => {
  // regen tokens for everyone (light)
  const rows = db.prepare("SELECT * FROM characters").all();
  const upd = db.prepare(`
    UPDATE characters
    SET micro_tokens=?, macro_tokens=?
    WHERE id=?
  `);
  for (const c of rows) {
    const micro = clamp(c.micro_tokens + 1, 0, 18);
    const macro = clamp(c.macro_tokens + 0, 0, 6);
    upd.run(micro, macro, c.id);
  }

  // global drift: heat decays slowly, influences decay slightly toward 25 to avoid permanent lock
  for (const d of Object.values(world.districts)) {
    d.heat = clamp(d.heat - 1, 0, 100);
    for (const f of FACTIONS) {
      const cur = d.influence[f.key] ?? 25;
      const toward = 25;
      const drift = cur > toward ? -1 : cur < toward ? +1 : 0;
      d.influence[f.key] = clamp(cur + drift, 0, 100);
    }
  }

  world.tick++;
  world.version++;
  broadcastWorldPatch({ type: "WORLD_TICK", tick: world.tick, version: world.version, global: world.global });
}, 60000);

// ---------- WEBSOCKET ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

function broadcastWorldPatch(msg) {
  const data = JSON.stringify(msg);
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(data);
  }
}

wss.on("connection", ws => {
  ws.send(JSON.stringify({ type: "HELLO", serverTime: nowISO(), factions: FACTIONS, zones: ZONES }));
});

server.listen(PORT, () => {
  console.log(`Pangolia MMORPG running on http://localhost:${PORT}`);
});
