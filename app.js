/* VoiceInbox — 画面のロジック
 *
 * 設計メモ
 *  - トークンはこのブラウザの中にしか置かない。ページ側（GitHub Pages）には何も保存しない。
 *  - 接続先（オーナー名 / リポジトリ名）はコードに書かず、利用者が設定画面で入力する。
 *  - 「外部の人かどうか」をこの JS で判定しない。判定は GitHub 側の 401 / 404 が行う。
 */
'use strict';

/* ============================== 定数 ============================== */

const API = 'https://api.github.com';
const API_VERSION = '2022-11-28';

const LS_CFG = 'vi.cfg';   // {owner, repo, protect, expiry}
const LS_TOK = 'vi.tok';   // 平文トークン（保護オフのとき）
const LS_ENC = 'vi.enc';   // {v, salt, iv, ct, iter} 暗号化トークン（保護オンのとき）

const PBKDF2_ITER = 310000;
const IDLE_LOCK_MS = 10 * 60 * 1000;   // 10 分操作が無ければ自動ロック
const REFRESH_MS = 30 * 1000;          // 自動更新
const EXPIRY_WARN_DAYS = 14;
const PAGE_SIZE = 100;
const MAX_PAGES = 5;

/* Phase 3 で整形状態を表すために使う予約語。送信先ピッカーには出さない。 */
const RESERVED_LABELS = new Set(['raw', 'tidy']);

/* ============================== 状態 ============================== */

const state = {
  owner: '',
  repo: '',
  protect: false,
  expiry: null,          // 手入力の有効期限 'YYYY-MM-DD'
  expiryFromHeader: null,// レスポンスヘッダから取れた期限（Date）
  token: null,           // メモリ上だけ

  view: 'inbox',         // 'inbox' | 'trash'
  issues: [],
  labels: [],
  query: '',
  labelFilter: '',
  cursor: -1,

  listState: 'idle',     // 'idle' | 'loading' | 'ok' | 'error'
  error: null,
  busy: false,
  lastActivity: Date.now(),
};

/* ============================== 小道具 ============================== */

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const RTF = new Intl.RelativeTimeFormat('ja', { numeric: 'auto' });
const UNITS = [
  ['year',   1000 * 60 * 60 * 24 * 365],
  ['month',  1000 * 60 * 60 * 24 * 30],
  ['day',    1000 * 60 * 60 * 24],
  ['hour',   1000 * 60 * 60],
  ['minute', 1000 * 60],
];
function relTime(iso) {
  const t = new Date(iso).getTime();
  if (!isFinite(t)) return '';
  const diff = t - Date.now();
  const abs = Math.abs(diff);
  for (const [unit, ms] of UNITS) {
    if (abs >= ms) return RTF.format(Math.round(diff / ms), unit);
  }
  return 'たった今';
}

function absTime(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return '';
  return new Intl.DateTimeFormat('ja-JP', {
    year: 'numeric', month: 'numeric', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  }).format(d);
}

function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('is-on');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('is-on'), 1800);
}

const b64 = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

function daysUntil(date) {
  if (!date) return null;
  const ms = date.getTime() - Date.now();
  return Math.floor(ms / (1000 * 60 * 60 * 24));
}

/** 有効期限は (1) レスポンスヘッダ (2) 設定画面の手入力 の順で見る。 */
function effectiveExpiry() {
  if (state.expiryFromHeader) return { date: state.expiryFromHeader, source: 'header' };
  if (state.expiry) {
    const d = new Date(state.expiry + 'T23:59:59');
    if (!isNaN(d)) return { date: d, source: 'manual' };
  }
  return null;
}

/* ============================== 保存領域 ============================== */

function loadCfg() {
  try {
    const raw = localStorage.getItem(LS_CFG);
    if (!raw) return null;
    const c = JSON.parse(raw);
    if (!c || typeof c !== 'object') return null;
    return c;
  } catch (_) { return null; }
}

function saveCfg() {
  localStorage.setItem(LS_CFG, JSON.stringify({
    owner: state.owner,
    repo: state.repo,
    protect: state.protect,
    expiry: state.expiry || null,
  }));
}

function forgetEverything() {
  localStorage.removeItem(LS_CFG);
  localStorage.removeItem(LS_TOK);
  localStorage.removeItem(LS_ENC);
  state.token = null;
  state.issues = [];
}

/* ============================== 暗号 ============================== */

async function deriveKey(passphrase, salt, iter) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptToken(token, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, PBKDF2_ITER);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(token)
  );
  return { v: 1, iter: PBKDF2_ITER, salt: b64.enc(salt), iv: b64.enc(iv), ct: b64.enc(ct) };
}

async function decryptToken(box, passphrase) {
  const key = await deriveKey(passphrase, b64.dec(box.salt), box.iter || PBKDF2_ITER);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64.dec(box.iv) }, key, b64.dec(box.ct)
  );
  return new TextDecoder().decode(pt);
}

/* ============================== GitHub API ============================== */

class ApiError extends Error {
  constructor(kind, title, detail, opts) {
    super(title);
    this.kind = kind;                       // 'auth'|'notfound'|'perm'|'ratelimit'|'network'|'http'|'locked'
    this.title = title;
    this.detail = detail || '';
    this.setupLink = !!(opts && opts.setupLink);
    this.retryAfter = (opts && opts.retryAfter) || null;
  }
}

/** レスポンスから有効期限ヘッダを拾う。CORS で読めない環境では単に null のまま。 */
function captureExpiryHeader(res) {
  let raw = null;
  try {
    raw = res.headers.get('GitHub-Authentication-Token-Expiration');
  } catch (_) { /* 読めない環境がある */ }
  if (!raw) return;
  let d = new Date(raw);
  if (isNaN(d)) d = new Date(raw.replace(' ', 'T').replace(' ', ''));
  if (!isNaN(d)) state.expiryFromHeader = d;
}

async function gh(path, opts) {
  opts = opts || {};
  if (!state.token) {
    throw new ApiError('locked', '鍵がありません', 'この端末に鍵を登録してください。');
  }

  const headers = {
    'Authorization': 'Bearer ' + state.token,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': API_VERSION,
  };
  if (opts.body) headers['Content-Type'] = 'application/json';

  let res;
  try {
    res = await fetch(API + path, {
      method: opts.method || 'GET',
      headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      cache: 'no-store',
      redirect: 'follow',
    });
  } catch (_) {
    throw new ApiError(
      'network',
      '接続できません。オフラインの可能性があります',
      'ネットワークにつながっているか確認して、もう一度更新してください。'
    );
  }

  captureExpiryHeader(res);

  if (res.status === 401) {
    throw new ApiError(
      'auth',
      '鍵の期限が切れているか、無効になっています',
      '新しい fine-grained token を作り直して、設定画面に貼り直してください。メモは消えていません。',
      { setupLink: true }
    );
  }

  if (res.status === 404) {
    throw new ApiError(
      'notfound',
      'リポジトリが見つからないか、鍵の権限が足りていません',
      'オーナー名とリポジトリ名の綴り、トークンの Only select repositories の指定、Issues の権限（Read and write）を確認してください。',
      { setupLink: true }
    );
  }

  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get('x-ratelimit-remaining');
    const retryAfter = res.headers.get('retry-after');
    let msg = '';
    try { msg = (await res.clone().json()).message || ''; } catch (_) { /* noop */ }

    if (res.status === 429 || remaining === '0' || /rate limit|abuse|secondary/i.test(msg)) {
      const reset = res.headers.get('x-ratelimit-reset');
      let when = '';
      if (reset) {
        const d = new Date(Number(reset) * 1000);
        if (!isNaN(d)) when = `（${absTime(d.toISOString())}ごろに解除されます）`;
      } else if (retryAfter) {
        when = `（約 ${retryAfter} 秒後に解除されます）`;
      }
      throw new ApiError(
        'ratelimit',
        'アクセス制限中です。しばらく待ってから更新してください',
        'GitHub 側の呼び出し回数の上限に達しました。' + when,
        { retryAfter }
      );
    }

    throw new ApiError(
      'perm',
      '鍵の権限が足りていません',
      'トークンの Repository permissions で Issues が Read and write になっているか確認してください。' +
      (msg ? `（GitHub の応答: ${msg}）` : ''),
      { setupLink: true }
    );
  }

  if (!res.ok) {
    let msg = '';
    try { msg = (await res.clone().json()).message || ''; } catch (_) { /* noop */ }
    throw new ApiError(
      'http',
      `GitHub からエラーが返りました（${res.status}）`,
      msg || 'しばらく待ってからもう一度お試しください。'
    );
  }

  if (res.status === 204) return null;
  return res.json();
}

/** Issues API は Pull Request も返す。pull_request を持つものは必ず除外する。 */
function stripPulls(list) {
  return list.filter((it) => it && !it.pull_request);
}

async function fetchIssues(stateName) {
  const out = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const q = new URLSearchParams({
      state: stateName,
      sort: 'created',
      direction: 'desc',
      per_page: String(PAGE_SIZE),
      page: String(page),
    });
    const batch = await gh(`/repos/${encodeURIComponent(state.owner)}/${encodeURIComponent(state.repo)}/issues?${q}`);
    if (!Array.isArray(batch)) break;
    out.push(...stripPulls(batch));
    if (batch.length < PAGE_SIZE) break;
  }
  return out;
}

async function fetchLabels() {
  const q = new URLSearchParams({ per_page: String(PAGE_SIZE) });
  const list = await gh(`/repos/${encodeURIComponent(state.owner)}/${encodeURIComponent(state.repo)}/labels?${q}`);
  return Array.isArray(list) ? list : [];
}

function setIssueState(num, next, reason) {
  return gh(`/repos/${encodeURIComponent(state.owner)}/${encodeURIComponent(state.repo)}/issues/${num}`, {
    method: 'PATCH',
    body: { state: next, state_reason: reason },
  });
}

/* ============================== 表示 ============================== */

const SETUP_LINK = '<a href="./setup.html">はじめかた（鍵の作り方）</a>';

function bannerHtml(cls, title, detail, extra) {
  return `<div class="notice ${cls}" role="${cls === 'notice-error' ? 'alert' : 'status'}">
    <strong>${esc(title)}</strong>
    ${detail ? `<span>${esc(detail)}</span> ` : ''}${extra || ''}
  </div>`;
}

function renderBanners() {
  const out = [];

  const exp = effectiveExpiry();
  if (exp) {
    const left = daysUntil(exp.date);
    if (left !== null && left < 0) {
      out.push(bannerHtml('notice-error', '鍵の有効期限が過ぎています',
        '新しい鍵を作って、設定画面から貼り直してください。', SETUP_LINK));
    } else if (left !== null && left <= EXPIRY_WARN_DAYS) {
      out.push(bannerHtml('notice-warn', `鍵の期限が近づいています（残り ${left} 日）`,
        '期限が切れる前に新しい鍵を作っておくと、画面が止まりません。', SETUP_LINK));
    }
  }

  if (state.error) {
    const e = state.error;
    out.push(bannerHtml('notice-error', e.title, e.detail, e.setupLink ? SETUP_LINK : ''));
  }

  $('#banners').innerHTML = out.join('');
}

function visibleIssues() {
  const q = state.query.trim().toLowerCase();
  const lf = state.labelFilter;
  return state.issues.filter((it) => {
    const names = (it.labels || []).map((l) => (typeof l === 'string' ? l : l.name));
    if (lf && !names.includes(lf)) return false;
    if (q) {
      const hay = ((it.body || '') + ' ' + names.join(' ')).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function cardHtml(it, idx) {
  const names = (it.labels || []).map((l) => (typeof l === 'string' ? l : l.name));
  const chips = names.map((n) => `<span class="chip">${esc(n)}</span>`).join('');
  const isTrash = state.view === 'trash';
  const body = it.body && it.body.trim() ? it.body : '（本文が空のメモ）';

  return `<li class="card${idx === state.cursor ? ' is-cursor' : ''}" data-num="${it.number}" data-idx="${idx}">
    <p class="card-body clamped" id="body-${it.number}">${esc(body)}</p>
    <button type="button" class="card-more" data-act="expand" hidden>全文を表示</button>
    <div class="card-foot">
      <div class="chips">${chips}</div>
      <span class="card-time" title="${esc(absTime(it.created_at))}">${esc(relTime(it.created_at))}</span>
      <div class="card-actions">
        <button type="button" class="btn btn-sm" data-act="copy">コピー</button>
        ${isTrash
          ? '<button type="button" class="btn btn-sm btn-primary" data-act="restore">戻す</button>'
          : '<button type="button" class="btn btn-sm btn-primary" data-act="done">完了</button>'}
      </div>
    </div>
  </li>`;
}

function renderList() {
  const list = $('#list');

  if (state.listState === 'loading' && state.issues.length === 0) {
    list.innerHTML = '<li class="skeleton"></li><li class="skeleton"></li><li class="skeleton"></li>';
    list.setAttribute('aria-busy', 'true');
    return;
  }
  list.removeAttribute('aria-busy');

  if (state.listState === 'error') {
    // 空のリストを黙って出さない。理由と次の一手を必ず出す。
    const e = state.error || {};
    list.innerHTML = `<li class="empty">
      <div class="big">⚠️</div>
      <p><b>${esc(e.title || '読み込めませんでした')}</b></p>
      <p>${esc(e.detail || '')}</p>
      <p><button type="button" class="btn" id="btn-retry">もう一度読み込む</button>
      ${e.setupLink ? ' ' + SETUP_LINK : ''}</p>
    </li>`;
    return;
  }

  const items = visibleIssues();

  if (items.length === 0) {
    const filtered = state.query.trim() || state.labelFilter;
    if (filtered) {
      list.innerHTML = `<li class="empty">
        <div class="big">🔍</div>
        <p>条件に合うメモはありません。</p>
        <p><button type="button" class="btn btn-sm" id="btn-clear-filter">絞り込みを解除</button></p>
      </li>`;
    } else if (state.view === 'trash') {
      list.innerHTML = '<li class="empty"><div class="big">🗑️</div><p>ゴミ箱は空です。</p></li>';
    } else {
      list.innerHTML = `<li class="empty">
        <div class="big">📥</div>
        <p>未処理のメモはありません。</p>
        <p>iPhone から話しかけると、ここにカードが並びます。</p>
      </li>`;
    }
    return;
  }

  list.innerHTML = items.map(cardHtml).join('');

  // 4 行を超えるものだけ「全文を表示」を出す。
  $$('.card', list).forEach((card) => {
    const body = $('.card-body', card);
    const more = $('.card-more', card);
    if (body.scrollHeight - body.clientHeight > 2) more.hidden = false;
  });
}

function renderCount() {
  const total = state.issues.length;
  const shown = visibleIssues().length;
  const noun = state.view === 'trash' ? 'ゴミ箱' : '未処理';
  $('#count').textContent = (shown === total)
    ? `${noun} ${total} 件`
    : `${noun} ${total} 件中 ${shown} 件`;
}

function renderLabelFilter() {
  const sel = $('#label-filter');
  const cur = state.labelFilter;
  const names = state.labels
    .map((l) => l.name)
    .filter((n) => !RESERVED_LABELS.has(n))
    .sort((a, b) => a.localeCompare(b, 'ja'));
  sel.innerHTML = '<option value="">すべてのラベル</option>' +
    names.map((n) => `<option value="${esc(n)}"${n === cur ? ' selected' : ''}>${esc(n)}</option>`).join('');
  sel.value = names.includes(cur) ? cur : '';
  if (sel.value !== cur) state.labelFilter = sel.value;
}

function render() {
  renderBanners();
  renderList();
  renderCount();
}

/* ============================== テーマ ============================== */

const THEMES = ['auto', 'light', 'dark'];
const THEME_LABEL = { auto: '🌗 自動', light: '☀️ ライト', dark: '🌙 ダーク' };

function applyTheme(t) {
  if (t === 'auto') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
  localStorage.setItem('vi.theme', t);
  const btn = $('#btn-theme');
  if (btn) {
    btn.textContent = THEME_LABEL[t];
    btn.title = `配色: ${THEME_LABEL[t]}（クリックで切り替え）`;
  }
}

/* ============================== 動作 ============================== */

async function loadAll() {
  if (!state.token || state.busy) return;
  state.busy = true;
  if (state.issues.length === 0) state.listState = 'loading';
  render();

  try {
    const [issues, labels] = await Promise.all([
      fetchIssues(state.view === 'trash' ? 'closed' : 'open'),
      fetchLabels().catch(() => state.labels),
    ]);
    state.issues = issues;
    state.labels = labels;
    state.error = null;
    state.listState = 'ok';
    if (state.cursor >= issues.length) state.cursor = issues.length - 1;
    renderLabelFilter();
  } catch (e) {
    state.error = (e instanceof ApiError) ? e
      : new ApiError('http', '読み込めませんでした', String((e && e.message) || e));
    state.listState = 'error';
  } finally {
    state.busy = false;
    render();
  }
}

function legacyCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.cssText = 'position:fixed;left:-9999px;top:0;';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } finally { ta.remove(); }
}

/** コピーするのは本文だけ。タイトル・ラベル・日時・元の文字起こしは含めない。 */
async function copyIssue(num, btn) {
  const it = state.issues.find((i) => i.number === num);
  if (!it) return;
  const text = it.body || '';
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    try { legacyCopy(text); } catch (_e) { toast('コピーできませんでした'); return; }
  }
  if (btn) {
    const old = btn.dataset.orig || btn.textContent;
    btn.dataset.orig = old;
    btn.textContent = 'コピーしました';
    btn.classList.add('is-done');
    clearTimeout(btn._t);
    btn._t = setTimeout(() => {
      btn.textContent = btn.dataset.orig || 'コピー';
      btn.classList.remove('is-done');
    }, 1500);
  } else {
    toast('本文をコピーしました');
  }
}

async function changeIssueState(num, next) {
  const card = $(`.card[data-num="${num}"]`);
  if (card) card.classList.add('is-leaving');
  try {
    await setIssueState(num, next, next === 'closed' ? 'completed' : 'reopened');
    state.issues = state.issues.filter((i) => i.number !== num);
    state.error = null;
    const vis = visibleIssues().length;
    if (state.cursor >= vis) state.cursor = vis - 1;
    render();
    toast(next === 'closed' ? 'ゴミ箱に移しました' : '未処理に戻しました');
  } catch (e) {
    if (card) card.classList.remove('is-leaving');
    state.error = (e instanceof ApiError) ? e
      : new ApiError('http', '操作できませんでした', String((e && e.message) || e));
    renderBanners();
  }
}

function moveCursor(delta) {
  const items = visibleIssues();
  if (items.length === 0) return;
  let next = state.cursor + delta;
  if (next < 0) next = 0;
  if (next > items.length - 1) next = items.length - 1;
  state.cursor = next;
  $$('.card').forEach((c) => c.classList.toggle('is-cursor', Number(c.dataset.idx) === next));
  const el = $(`.card[data-idx="${next}"]`);
  if (el) el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function currentIssueNumber() {
  const items = visibleIssues();
  const it = items[state.cursor];
  return it ? it.number : null;
}

function switchView(v) {
  if (state.view === v) return;
  state.view = v;
  state.issues = [];
  state.cursor = -1;
  state.error = null;
  state.listState = 'loading';
  $('#tab-inbox').setAttribute('aria-selected', String(v === 'inbox'));
  $('#tab-trash').setAttribute('aria-selected', String(v === 'trash'));
  render();
  loadAll();
}

/* ============================== 画面の出し分け ============================== */

let refreshTimer = null;
let idleTimer = null;

function showGate(mode) {
  $('#app').classList.remove('is-on');
  $('#gate').hidden = false;
  $('#form-setup').hidden = (mode !== 'setup');
  $('#form-unlock').hidden = (mode !== 'unlock');
  $('#gate-title').textContent = (mode === 'unlock') ? 'ロックを解除' : 'この端末に鍵を登録';
  $('#gate-lead').textContent = (mode === 'unlock')
    ? 'このパソコンは保護されています。パスフレーズを入力してください。'
    : 'GitHub の fine-grained token を貼ると、メモが読み込まれます。';
  stopTimers();
  setTimeout(() => {
    const f = (mode === 'unlock') ? $('#u-pass') : $('#g-owner');
    if (f) f.focus();
  }, 30);
}

function enterApp() {
  $('#gate').hidden = true;
  $('#app').classList.add('is-on');
  $('#lock-now').hidden = !state.protect;
  startTimers();
  loadAll();
}

function lockNow() {
  state.token = null;
  state.issues = [];
  state.cursor = -1;
  state.error = null;
  $('#list').innerHTML = '';
  $('#banners').innerHTML = '';
  $('#u-pass').value = '';
  $('#unlock-err').innerHTML = '';
  showGate('unlock');
}

function startTimers() {
  stopTimers();
  refreshTimer = setInterval(() => {
    if (!document.hidden && state.token && !state.busy) loadAll();
  }, REFRESH_MS);
  if (state.protect) {
    state.lastActivity = Date.now();
    idleTimer = setInterval(() => {
      if (Date.now() - state.lastActivity > IDLE_LOCK_MS) {
        lockNow();
        toast('10 分操作がなかったのでロックしました');
      }
    }, 15000);
  }
}

function stopTimers() {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
  if (idleTimer) { clearInterval(idleTimer); idleTimer = null; }
}

/* ============================== 鍵の登録 ============================== */

function splitOwnerRepo(ownerRaw, repoRaw) {
  let owner = (ownerRaw || '').trim();
  let repo = (repoRaw || '').trim();
  const m = owner.match(/github\.com\/([^/\s]+)\/([^/\s?#]+)/i);
  if (m) {
    owner = m[1];
    if (!repo) repo = m[2];
  } else if (owner.includes('/')) {
    const parts = owner.split('/').filter(Boolean);
    if (parts.length >= 2) { owner = parts[0]; if (!repo) repo = parts[1]; }
  }
  repo = repo.replace(/\.git$/i, '');
  return { owner, repo };
}

function showFormError(elId, err) {
  const box = $(elId);
  if (!err) { box.innerHTML = ''; return; }
  const e = (err instanceof ApiError) ? err
    : new ApiError('http', '保存できませんでした', String((err && err.message) || err));
  box.innerHTML = bannerHtml('notice-error', e.title, e.detail, e.setupLink ? SETUP_LINK : '');
}

/** 保存する前に一度だけ GitHub に問い合わせて、鍵と権限が本当に通るか確かめる。 */
async function verifyConnection(owner, repo, token) {
  const keep = { owner: state.owner, repo: state.repo, token: state.token };
  state.owner = owner; state.repo = repo; state.token = token;
  try {
    await fetchLabels();
  } catch (e) {
    state.owner = keep.owner; state.repo = keep.repo; state.token = keep.token;
    throw e;
  }
}

async function persistCredentials(token, passphrase) {
  if (state.protect) {
    const box = await encryptToken(token, passphrase);
    localStorage.setItem(LS_ENC, JSON.stringify(box));
    localStorage.removeItem(LS_TOK);
  } else {
    localStorage.setItem(LS_TOK, token);
    localStorage.removeItem(LS_ENC);
  }
  saveCfg();
}

function tokenShapeHint(token) {
  if (token.startsWith('github_pat_')) return null;
  if (token.startsWith('ghp_')) {
    return 'Tokens (classic) の鍵のようです。このアプリは fine-grained token（github_pat_ で始まる鍵）を前提にしています。';
  }
  return 'fine-grained token は github_pat_ で始まります。貼り付けた内容を確認してください。';
}

async function submitSetup(ev) {
  ev.preventDefault();
  const btn = $('#btn-connect');
  const { owner, repo } = splitOwnerRepo($('#g-owner').value, $('#g-repo').value);
  const token = $('#g-token').value.trim();
  const protect = $('#g-protect').checked;
  const pass = $('#g-pass').value;
  const pass2 = $('#g-pass2').value;
  const expiry = $('#g-expiry').value || null;

  showFormError('#setup-err', null);

  if (!owner || !repo) {
    return showFormError('#setup-err', new ApiError('input', 'オーナー名とリポジトリ名を入力してください', ''));
  }
  if (!token) {
    return showFormError('#setup-err', new ApiError('input', '鍵（トークン）を貼り付けてください',
      '作り方が分からないときは、下の「はじめかた」を開いてください。', { setupLink: true }));
  }
  if (protect) {
    if (pass.length < 8) {
      return showFormError('#setup-err', new ApiError('input', 'パスフレーズは 8 文字以上にしてください', ''));
    }
    if (pass !== pass2) {
      return showFormError('#setup-err', new ApiError('input', 'パスフレーズが一致しません', ''));
    }
  }

  const hint = tokenShapeHint(token);
  btn.disabled = true;
  btn.textContent = '確認中…';
  try {
    await verifyConnection(owner, repo, token);
    state.owner = owner; state.repo = repo; state.protect = protect; state.expiry = expiry;
    await persistCredentials(token, pass);
    $('#g-token').value = ''; $('#g-pass').value = ''; $('#g-pass2').value = '';
    enterApp();
    if (hint) toast('接続しました（' + hint + '）');
  } catch (e) {
    showFormError('#setup-err', e);
    if (hint && e instanceof ApiError && e.kind === 'auth') {
      $('#setup-err').insertAdjacentHTML('beforeend',
        bannerHtml('notice-warn', '鍵の形が想定と違います', hint, SETUP_LINK));
    }
  } finally {
    btn.disabled = false;
    btn.textContent = '接続する';
  }
}

async function submitUnlock(ev) {
  ev.preventDefault();
  const btn = $('#btn-unlock');
  const pass = $('#u-pass').value;
  showFormError('#unlock-err', null);
  const raw = localStorage.getItem(LS_ENC);
  if (!raw) {
    state.protect = false;
    return showGate('setup');
  }
  btn.disabled = true;
  try {
    const token = await decryptToken(JSON.parse(raw), pass);
    state.token = token;
    $('#u-pass').value = '';
    enterApp();
  } catch (_) {
    showFormError('#unlock-err', new ApiError('input', 'パスフレーズが違います',
      '思い出せない場合は「このパソコンから削除」で登録をやり直してください。メモは消えません。'));
  } finally {
    btn.disabled = false;
  }
}

/* ============================== 設定画面 ============================== */

function openSettings() {
  $('#s-owner').value = state.owner;
  $('#s-repo').value = state.repo;
  $('#s-expiry').value = state.expiry || '';
  $('#s-token').value = '';
  $('#s-protect').checked = state.protect;
  $('#s-pass').value = '';
  $('#s-pass2').value = '';
  togglePassFields('#s-protect', '#s-pass-wrap');
  showFormError('#settings-err', null);

  const exp = effectiveExpiry();
  const lines = [];
  lines.push(`接続先: <b>${esc(state.owner)}/${esc(state.repo)}</b>`);
  lines.push(`保護: <b>${state.protect ? 'オン（パスフレーズ）' : 'オフ'}</b>`);
  if (exp) {
    const left = daysUntil(exp.date);
    const src = exp.source === 'header' ? 'GitHub の応答から取得' : '手入力';
    lines.push(`鍵の期限: <b>残り ${left} 日</b>（${src}）`);
  } else {
    lines.push('鍵の期限: <b>不明</b>（下の欄に入力すると残り日数を表示します）');
  }
  $('#s-status').innerHTML = lines.map((l) => `<p class="status-line">${l}</p>`).join('');
  $('#dlg-settings').showModal();
}

async function saveSettings(ev) {
  ev.preventDefault();
  const { owner, repo } = splitOwnerRepo($('#s-owner').value, $('#s-repo').value);
  const newToken = $('#s-token').value.trim();
  const protect = $('#s-protect').checked;
  const pass = $('#s-pass').value;
  const pass2 = $('#s-pass2').value;
  const expiry = $('#s-expiry').value || null;

  showFormError('#settings-err', null);
  if (!owner || !repo) {
    return showFormError('#settings-err', new ApiError('input', 'オーナー名とリポジトリ名を入力してください', ''));
  }

  const token = newToken || state.token;
  if (!token) {
    return showFormError('#settings-err', new ApiError('input', '鍵（トークン）を貼り付けてください', ''));
  }

  const needsPass = protect && (!state.protect || newToken || pass);
  if (protect && needsPass) {
    if (pass.length < 8) {
      return showFormError('#settings-err', new ApiError('input', 'パスフレーズは 8 文字以上にしてください', ''));
    }
    if (pass !== pass2) {
      return showFormError('#settings-err', new ApiError('input', 'パスフレーズが一致しません', ''));
    }
  }

  const btn = $('#btn-save-settings');
  btn.disabled = true;
  btn.textContent = '確認中…';
  try {
    await verifyConnection(owner, repo, token);
    const wasProtected = state.protect;
    state.owner = owner; state.repo = repo; state.expiry = expiry; state.protect = protect;
    state.token = token;

    if (protect && !needsPass && wasProtected) {
      // 既存の暗号化トークンをそのまま使う（パスフレーズ変更なし・鍵変更なし）
      localStorage.removeItem(LS_TOK);
      saveCfg();
    } else {
      await persistCredentials(token, pass);
    }

    $('#lock-now').hidden = !state.protect;
    startTimers();
    $('#dlg-settings').close();
    toast('設定を保存しました');
    state.issues = [];
    loadAll();
  } catch (e) {
    showFormError('#settings-err', e);
  } finally {
    btn.disabled = false;
    btn.textContent = '保存';
  }
}

function togglePassFields(cbSel, wrapSel) {
  $(wrapSel).hidden = !$(cbSel).checked;
}

/* ============================== 配線 ============================== */

function isTyping(e) {
  const t = e.target;
  if (!t || !t.tagName) return false;
  return t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName);
}

function clearFilters() {
  state.query = '';
  state.labelFilter = '';
  state.cursor = -1;
  $('#q').value = '';
  $('#label-filter').value = '';
  render();
}

function wire() {
  $('#form-setup').addEventListener('submit', submitSetup);
  $('#form-unlock').addEventListener('submit', submitUnlock);
  $('#form-settings').addEventListener('submit', saveSettings);

  $('#g-protect').addEventListener('change', () => togglePassFields('#g-protect', '#g-pass-wrap'));
  $('#s-protect').addEventListener('change', () => togglePassFields('#s-protect', '#s-pass-wrap'));

  $('#tab-inbox').addEventListener('click', () => switchView('inbox'));
  $('#tab-trash').addEventListener('click', () => switchView('trash'));

  $('#btn-refresh').addEventListener('click', () => { state.error = null; loadAll(); });
  $('#btn-settings').addEventListener('click', openSettings);
  $('#btn-close-settings').addEventListener('click', () => $('#dlg-settings').close());
  $('#lock-now').addEventListener('click', () => { $('#dlg-settings').close(); lockNow(); });

  $('#btn-theme').addEventListener('click', () => {
    const cur = localStorage.getItem('vi.theme') || 'auto';
    applyTheme(THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length]);
  });

  const forget = () => {
    if (!confirm('この端末から鍵と接続先を削除します。GitHub 上のメモは消えません。よろしいですか？')) return;
    forgetEverything();
    stopTimers();
    state.owner = ''; state.repo = ''; state.protect = false; state.expiry = null;
    state.expiryFromHeader = null;
    $('#app').classList.remove('is-on');
    $('#list').innerHTML = '';
    $('#banners').innerHTML = '';
    $$('#form-setup input').forEach((i) => { if (i.type === 'checkbox') i.checked = false; else i.value = ''; });
    togglePassFields('#g-protect', '#g-pass-wrap');
    showFormError('#setup-err', null);
    if ($('#dlg-settings').open) $('#dlg-settings').close();
    showGate('setup');
    toast('この端末から削除しました');
  };
  $('#btn-forget').addEventListener('click', forget);
  $('#btn-forget-gate').addEventListener('click', forget);

  $('#q').addEventListener('input', (e) => {
    state.query = e.target.value;
    state.cursor = -1;
    renderList();
    renderCount();
  });
  $('#label-filter').addEventListener('change', (e) => {
    state.labelFilter = e.target.value;
    state.cursor = -1;
    renderList();
    renderCount();
  });

  $('#list').addEventListener('click', (e) => {
    if (e.target.id === 'btn-retry') { state.error = null; state.listState = 'loading'; render(); loadAll(); return; }
    if (e.target.id === 'btn-clear-filter') { clearFilters(); return; }

    const card = e.target.closest('.card');
    if (!card) return;
    const num = Number(card.dataset.num);

    const actBtn = e.target.closest('[data-act]');
    const act = actBtn && actBtn.dataset.act;

    if (act === 'copy') { copyIssue(num, actBtn); return; }
    if (act === 'done') { changeIssueState(num, 'closed'); return; }
    if (act === 'restore') { changeIssueState(num, 'open'); return; }

    if (act === 'expand' || e.target.closest('.card-body')) {
      const body = $('.card-body', card);
      const more = $('.card-more', card);
      const nowClamped = body.classList.toggle('clamped');
      if (more) more.textContent = nowClamped ? '全文を表示' : '折りたたむ';
      return;
    }

    state.cursor = Number(card.dataset.idx);
    $$('.card').forEach((c) => c.classList.toggle('is-cursor', c === card));
  });

  document.addEventListener('keydown', (e) => {
    if (!state.token) return;
    const dlgOpen = !!$('dialog[open]');

    if (e.key === 'Escape') {
      if (document.activeElement === $('#q')) {
        $('#q').value = ''; state.query = ''; state.cursor = -1; render(); $('#q').blur();
        e.preventDefault(); return;
      }
      if (dlgOpen) return;                       // dialog は自分で閉じる
      if (state.query || state.labelFilter) { clearFilters(); e.preventDefault(); }
      return;
    }

    if (dlgOpen || isTyping(e) || e.metaKey || e.ctrlKey || e.altKey) return;

    if (e.key === '/') { const q = $('#q'); q.focus(); q.select(); e.preventDefault(); return; }
    if (e.key === 'j') { moveCursor(1); e.preventDefault(); return; }
    if (e.key === 'k') { moveCursor(-1); e.preventDefault(); return; }
    if (e.key === 'r') { state.error = null; loadAll(); e.preventDefault(); return; }

    if (e.key === 'c') {
      const n = currentIssueNumber();
      if (n != null) copyIssue(n, $(`.card[data-num="${n}"] [data-act="copy"]`));
      e.preventDefault(); return;
    }
    if (e.key === 'x') {
      const n = currentIssueNumber();
      if (n != null) changeIssueState(n, state.view === 'trash' ? 'open' : 'closed');
      e.preventDefault(); return;
    }
  });

  ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach((ev) => {
    document.addEventListener(ev, () => { state.lastActivity = Date.now(); }, { passive: true });
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && state.token && !state.busy) loadAll();
  });
  window.addEventListener('online', () => {
    if (state.token) { state.error = null; loadAll(); }
  });
}

/* ============================== 起動 ============================== */

function boot() {
  applyTheme(localStorage.getItem('vi.theme') || 'auto');
  wire();

  const cfg = loadCfg();
  if (!cfg || !cfg.owner || !cfg.repo) return showGate('setup');

  state.owner = cfg.owner;
  state.repo = cfg.repo;
  state.protect = !!cfg.protect;
  state.expiry = cfg.expiry || null;

  if (state.protect) {
    if (!localStorage.getItem(LS_ENC)) return showGate('setup');
    return showGate('unlock');
  }

  const tok = localStorage.getItem(LS_TOK);
  if (!tok) return showGate('setup');
  state.token = tok;
  enterApp();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
