/* ============================================================
   会食セレクト — script.js  v2.0
   ローディング固着バグ修正版
   ============================================================ */
'use strict';

/* ─────────────────────────────────────────
   ① ローディング画面：最大1.5秒で必ず消す
   IIFE で即時実行 → どんなエラーが後で起きても
   ローディング画面が固まらない安全網
───────────────────────────────────────── */
(function forceHideLoading() {
  function hide() {
    const ls = document.getElementById('loading-screen');
    if (!ls || ls.dataset.hidden) return;
    ls.dataset.hidden = '1';
    ls.style.transition    = 'opacity 0.4s ease';
    ls.style.opacity       = '0';
    ls.style.pointerEvents = 'none';
    setTimeout(() => { ls.style.display = 'none'; }, 450);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(hide, 700));
  } else {
    setTimeout(hide, 700);
  }
  // 絶対安全網 — 1.5秒後に強制非表示
  setTimeout(hide, 1500);
})();

/* ─────────────────────────────────────────
   AUTH MODULE
   Web Crypto API / SHA-256 / localStorage
   外部サーバー送信なし・完全ローカル認証
───────────────────────────────────────── */
const AUTH = {
  KEY_CRED:     'kaishoku_credentials',
  KEY_SESSION:  'kaishoku_session',
  KEY_REMEMBER: 'kaishoku_remember',
  KEY_ATTEMPTS: 'kaishoku_attempts',
  MAX_TRIES: 5,
  LOCK_MS:   5 * 60 * 1000,

  async sha256(text) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
  },

  genSalt() {
    const a = new Uint8Array(16);
    crypto.getRandomValues(a);
    return [...a].map(b => b.toString(16).padStart(2,'0')).join('');
  },

  async saveCredentials(email, password) {
    const salt = this.genSalt();
    const eH   = await this.sha256(email.toLowerCase().trim());
    const pH   = await this.sha256(password + salt);
    localStorage.setItem(this.KEY_CRED, JSON.stringify({ eH, pH, salt }));
  },

  hasCredentials() {
    try { return !!JSON.parse(localStorage.getItem(this.KEY_CRED)); }
    catch { return false; }
  },

  async verify(email, password) {
    try {
      const c = JSON.parse(localStorage.getItem(this.KEY_CRED));
      if (!c) return false;
      const eH = await this.sha256(email.toLowerCase().trim());
      const pH = await this.sha256(password + c.salt);
      return eH === c.eH && pH === c.pH;
    } catch { return false; }
  },

  isLockedOut() {
    try {
      const d = JSON.parse(localStorage.getItem(this.KEY_ATTEMPTS) || '{}');
      if (d.until && Date.now() < d.until) return true;
      if (d.until) localStorage.removeItem(this.KEY_ATTEMPTS);
    } catch {}
    return false;
  },

  lockSecs() {
    try {
      const d = JSON.parse(localStorage.getItem(this.KEY_ATTEMPTS) || '{}');
      return d.until ? Math.ceil((d.until - Date.now()) / 1000) : 0;
    } catch { return 0; }
  },

  recordFail() {
    try {
      const d = JSON.parse(localStorage.getItem(this.KEY_ATTEMPTS) || '{"n":0}');
      d.n = (d.n || 0) + 1;
      if (d.n >= this.MAX_TRIES) { d.until = Date.now() + this.LOCK_MS; d.n = 0; }
      localStorage.setItem(this.KEY_ATTEMPTS, JSON.stringify(d));
      return Math.max(0, this.MAX_TRIES - d.n);
    } catch { return 0; }
  },

  clearFails() { localStorage.removeItem(this.KEY_ATTEMPTS); },

  createSession(email, remember) {
    const sid = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : Math.random().toString(36).slice(2);
    const payload = JSON.stringify({ sid, email, ts: Date.now() });
    sessionStorage.setItem(this.KEY_SESSION, payload);
    if (remember) localStorage.setItem(this.KEY_REMEMBER, payload);
    this.clearFails();
  },

  isAuthenticated() {
    try {
      const raw = sessionStorage.getItem(this.KEY_SESSION) || localStorage.getItem(this.KEY_REMEMBER);
      if (!raw) return false;
      const d = JSON.parse(raw);
      if (!d.sid) return false;
      if (localStorage.getItem(this.KEY_REMEMBER)) {
        return (Date.now() - d.ts) < 30 * 24 * 60 * 60 * 1000;
      }
      return true;
    } catch { return false; }
  },

  getEmail() {
    try {
      const raw = sessionStorage.getItem(this.KEY_SESSION) || localStorage.getItem(this.KEY_REMEMBER);
      return raw ? (JSON.parse(raw).email || '') : '';
    } catch { return ''; }
  },

  logout() {
    sessionStorage.removeItem(this.KEY_SESSION);
    localStorage.removeItem(this.KEY_REMEMBER);
  },
};

/* ─────────────────────────────────────────
   AUTH UI
───────────────────────────────────────── */
const AuthUI = {

  show(cardId) {
    document.getElementById('login-screen').classList.remove('hidden');
    ['login-card','setup-card'].forEach(id =>
      document.getElementById(id).classList.toggle('hidden', id !== cardId)
    );
    const focus = { 'login-card':'login-email', 'setup-card':'setup-email' };
    if (focus[cardId]) setTimeout(() => document.getElementById(focus[cardId]).focus(), 250);
  },

  hide() {
    document.getElementById('login-screen').classList.add('hidden');
  },

  err(id, msg) {
    const el = document.getElementById(id);
    el.textContent = msg;
    el.classList.remove('hidden');
  },

  noErr(id) { document.getElementById(id).classList.add('hidden'); },

  setBusy(on) {
    document.getElementById('btn-login').disabled = on;
    document.getElementById('login-btn-text').style.display = on ? 'none' : '';
    document.getElementById('login-spinner').classList.toggle('hidden', !on);
  },

  async handleLogin() {
    this.noErr('login-error');
    ['login-email','login-password'].forEach(id => document.getElementById(id).classList.remove('error'));
    const email    = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const remember = document.getElementById('remember-me').checked;

    if (!email || !password) {
      return this.err('login-error', 'メールアドレスとパスワードを入力してください');
    }
    if (AUTH.isLockedOut()) {
      return this.err('login-error', `試行回数超過。あと ${AUTH.lockSecs()} 秒お待ちください`);
    }

    // HTTPS以外では crypto.subtle が使えない
    if (!window.isSecureContext) {
      // 非セキュア環境向けフォールバック（ローカル開発用）
      return this.err('login-error', 'HTTPS環境（GitHub Pages）でご利用ください。http://では動作しません。');
    }

    this.setBusy(true);
    try {
      const ok = await AUTH.verify(email, password);
      this.setBusy(false);
      if (ok) {
        AUTH.createSession(email, remember);
        this.hide();
        AppMain.start();
      } else {
        const left = AUTH.recordFail();
        const msg = left > 0
          ? `認証情報が正しくありません（残り${left}回）`
          : '試行回数が上限に達しました。5分後に再試行してください';
        this.err('login-error', msg);
        ['login-email','login-password'].forEach(id => document.getElementById(id).classList.add('error'));
        document.getElementById('login-password').value = '';
      }
    } catch (e) {
      this.setBusy(false);
      this.err('login-error', '認証処理でエラーが発生しました: ' + e.message);
    }
  },

  async handleSetup() {
    this.noErr('setup-error');
    const email   = document.getElementById('setup-email').value.trim();
    const pw      = document.getElementById('setup-password').value;
    const confirm = document.getElementById('setup-confirm').value;

    if (!email || !pw || !confirm) return this.err('setup-error','すべての項目を入力してください');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return this.err('setup-error','正しいメールアドレス形式で入力してください');
    if (pw.length < 8)   return this.err('setup-error','パスワードは8文字以上にしてください');
    if (pw !== confirm)  return this.err('setup-error','パスワードが一致しません');
    if (!window.isSecureContext) return this.err('setup-error','HTTPS環境（GitHub Pages）でご利用ください');

    const btn = document.getElementById('btn-setup-save');
    btn.disabled = true;
    try {
      await AUTH.saveCredentials(email, pw);
      AUTH.createSession(email, false);
      this.hide();
      AppMain.start();
    } catch (e) {
      this.err('setup-error', 'エラー: ' + e.message);
      btn.disabled = false;
    }
  },

  handleLogout() {
    if (!confirm('ログアウトしますか？')) return;
    AUTH.logout();
    document.getElementById('login-email').value    = '';
    document.getElementById('login-password').value = '';
    this.noErr('login-error');
    this.show('login-card');
  },

  bindEvents() {
    document.getElementById('btn-login').addEventListener('click', () => this.handleLogin());
    document.getElementById('login-password').addEventListener('keydown', e => { if (e.key==='Enter') this.handleLogin(); });
    document.getElementById('login-email').addEventListener('keydown',    e => { if (e.key==='Enter') document.getElementById('login-password').focus(); });
    document.getElementById('btn-setup-save').addEventListener('click', () => this.handleSetup());
    document.getElementById('btn-to-setup').addEventListener('click', () => this.show('setup-card'));
    document.getElementById('btn-to-login').addEventListener('click',  () => this.show('login-card'));
    document.getElementById('btn-logout').addEventListener('click', () => this.handleLogout());
    document.getElementById('toggle-login-pw').addEventListener('click', () => {
      const inp = document.getElementById('login-password');
      const vis = inp.type === 'password';
      inp.type = vis ? 'text' : 'password';
      document.getElementById('pw-eye-on').style.display  = vis ? 'none' : '';
      document.getElementById('pw-eye-off').style.display = vis ? '' : 'none';
    });
  },

  init() {
    this.bindEvents();
    if (AUTH.isAuthenticated()) {
      this.hide();
      AppMain.start();
    } else if (!AUTH.hasCredentials()) {
      this.show('setup-card');
    } else {
      this.show('login-card');
    }
  },
};

/* ─────────────────────────────────────────
   DEMO DATA
───────────────────────────────────────── */
const DEMO_STORES = [
  { id:'d01', name:'銀座 鮨 真田', area:'銀座', genre:'寿司・鮨', budget:'¥30,000〜', atmosphere:'高級・接待向き',
    photo_url:'https://images.unsplash.com/photo-1579871494447-9811cf80d66c?w=600&q=80',
    map_url:'https://maps.google.com/?q=銀座+寿司', instagram_url:'https://instagram.com', tiktok_url:'',
    address:'東京都中央区銀座5-5-1', lat:35.6718, lng:139.7650,
    description:'江戸前の伝統を守りながら現代の感性で昇華させた鮨の名店。厳選された旬の食材と職人の技が光る。接待・会食に最適な個室完備。' },
  { id:'d02', name:'恵比寿 Bistro 葉月', area:'恵比寿', genre:'フレンチ・イタリアン', budget:'¥15,000〜', atmosphere:'大人カジュアル',
    photo_url:'https://images.unsplash.com/photo-1414235077428-338989a2e8c0?w=600&q=80',
    map_url:'https://maps.google.com/?q=恵比寿+フレンチ', instagram_url:'https://instagram.com', tiktok_url:'',
    address:'東京都渋谷区恵比寿3-8-14', lat:35.6465, lng:139.7139,
    description:'地中海の風を感じるカジュアルフレンチ。ソムリエ厳選のワインと、旬の食材を使ったコースが大人気。' },
  { id:'d03', name:'新宿 割烹 月夜', area:'新宿', genre:'和食・割烹', budget:'¥20,000〜', atmosphere:'和モダン・落ち着き',
    photo_url:'https://images.unsplash.com/photo-1504674900247-0877df9cc836?w=600&q=80',
    map_url:'https://maps.google.com/?q=新宿+割烹', instagram_url:'https://instagram.com', tiktok_url:'',
    address:'東京都新宿区新宿3-1-26', lat:35.6896, lng:139.7006,
    description:'隠れ家的な一軒家割烹。旬の食材にこだわった本格会席料理。完全個室対応可能。' },
  { id:'d04', name:'六本木 The Rooftop', area:'六本木', genre:'フュージョン・モダン', budget:'¥20,000〜', atmosphere:'スタイリッシュ・景色◎',
    photo_url:'https://images.unsplash.com/photo-1552566626-52f8b828add9?w=600&q=80',
    map_url:'https://maps.google.com/?q=六本木+ルーフトップ', instagram_url:'https://instagram.com', tiktok_url:'https://tiktok.com',
    address:'東京都港区六本木6-10-1', lat:35.6628, lng:139.7316,
    description:'東京タワーを望む最高のロケーション。特別な夜に彩りを添える一軒。' },
  { id:'d05', name:'渋谷 焼肉 黒毛座', area:'渋谷', genre:'焼肉・肉料理', budget:'¥10,000〜', atmosphere:'活気・賑やか',
    photo_url:'https://images.unsplash.com/photo-1558030006-450675393462?w=600&q=80',
    map_url:'https://maps.google.com/?q=渋谷+焼肉', instagram_url:'https://instagram.com', tiktok_url:'https://tiktok.com',
    address:'東京都渋谷区道玄坂1-8-3', lat:35.6595, lng:139.6979,
    description:'最高級A5黒毛和牛を堪能できる焼肉の名店。希少部位から定番まで。' },
  { id:'d06', name:'丸の内 個室和牛 一頭', area:'丸の内', genre:'焼肉・肉料理', budget:'¥25,000〜', atmosphere:'高級・接待向き',
    photo_url:'https://images.unsplash.com/photo-1546069901-ba9599a7e63c?w=600&q=80',
    map_url:'https://maps.google.com/?q=丸の内+和牛', instagram_url:'https://instagram.com', tiktok_url:'',
    address:'東京都千代田区丸の内2-4-1', lat:35.6796, lng:139.7644,
    description:'完全個室で楽しむ最高峰の和牛料理。ビジネスの大切な接待にも最適。' },
  { id:'d07', name:'品川 シーフード テラス', area:'品川', genre:'シーフード・魚介', budget:'¥15,000〜', atmosphere:'開放的・テラス席',
    photo_url:'https://images.unsplash.com/photo-1559339352-11d035aa65de?w=600&q=80',
    map_url:'https://maps.google.com/?q=品川+シーフード', instagram_url:'https://instagram.com', tiktok_url:'',
    address:'東京都港区高輪4-10-30', lat:35.6285, lng:139.7365,
    description:'東京湾を一望するテラスで楽しむシーフードの祭典。大人数での会食にも対応。' },
  { id:'d08', name:'上野 中華料理 龍苑', area:'上野', genre:'中華・点心', budget:'¥8,000〜', atmosphere:'賑やか・ファミリー向き',
    photo_url:'https://images.unsplash.com/photo-1563245372-f21724e3856d?w=600&q=80',
    map_url:'https://maps.google.com/?q=上野+中華料理', instagram_url:'', tiktok_url:'',
    address:'東京都台東区上野4-1-3', lat:35.7089, lng:139.7745,
    description:'本格広東料理と飲茶の名店。手作り点心が絶品。宴会にも対応。' },
];

/* ─────────────────────────────────────────
   STATE
───────────────────────────────────────── */
const STATE = {
  stores:[], filteredStores:[], favorites:[], history:[],
  searchLat:null, searchLng:null, searchLabel:'',
  mapInstance:null, activePanel:'search', filterOpen:false,
  sheetId:'', usingDemo:false,
};

const LS = {
  KEY_FAV:'kaishoku_fav', KEY_HIST:'kaishoku_hist',
  KEY_SHEET:'kaishoku_sheet', KEY_DEMO:'kaishoku_demo',
  load(k, def=[]) { try { return JSON.parse(localStorage.getItem(k) || JSON.stringify(def)); } catch { return def; } },
  save(k, v) { localStorage.setItem(k, JSON.stringify(v)); },
};

/* ─────────────────────────────────────────
   APP MAIN — 認証後に一度だけ起動
───────────────────────────────────────── */
const AppMain = {
  started: false,
  async start() {
    if (this.started) return;
    this.started = true;

    STATE.favorites = LS.load(LS.KEY_FAV, []);
    STATE.history   = LS.load(LS.KEY_HIST, []);
    STATE.sheetId   = localStorage.getItem(LS.KEY_SHEET) || '';
    STATE.usingDemo = localStorage.getItem(LS.KEY_DEMO) === 'true';

    updateFavBadge();
    attachEvents();

    if (STATE.usingDemo) {
      STATE.stores = [...DEMO_STORES];
      buildFilterOptions(STATE.stores);
    } else if (STATE.sheetId) {
      try {
        STATE.stores = await loadStoresFromSheet(STATE.sheetId);
        buildFilterOptions(STATE.stores);
        showToast(`${STATE.stores.length}件の店舗データを読み込みました`);
      } catch {
        setTimeout(openConfigModal, 300);
      }
    } else {
      setTimeout(openConfigModal, 300);
    }
  },
};

/* ─────────────────────────────────────────
   GOOGLE SHEETS
───────────────────────────────────────── */
async function loadStoresFromSheet(sheetId) {
  const res  = await fetch(`https://docs.google.com/spreadsheets/d/${sheetId}/gviz/tq?tqx=out:json`);
  const text = await res.text();
  const m    = text.match(/google\.visualization\.Query\.setResponse\(([\s\S]*)\)/);
  if (!m) throw new Error('parse error');
  const data = JSON.parse(m[1]);
  const cols = data.table.cols.map(c => c.label.trim().toLowerCase().replace(/\s+/g,'_'));
  return data.table.rows.map((row, i) => {
    const o = { id:`s${i}` };
    row.c.forEach((cell, j) => { o[cols[j]] = cell ? (cell.v !== null ? String(cell.v) : '') : ''; });
    o.lat = parseFloat(o.lat) || 0;
    o.lng = parseFloat(o.lng) || 0;
    return o;
  }).filter(s => s.name);
}

/* ─────────────────────────────────────────
   FILTER
───────────────────────────────────────── */
function buildFilterOptions(stores) {
  ['area','genre','budget','atmosphere'].forEach(key => {
    const sel = document.getElementById(`f-${key}`);
    if (!sel) return;
    const vals = [...new Set(stores.map(s => s[key]).filter(Boolean))].sort();
    while (sel.options.length > 1) sel.remove(1);
    vals.forEach(v => { const o = document.createElement('option'); o.value = o.textContent = v; sel.appendChild(o); });
  });
}

function haversine(a, b, c, d) {
  const R=6371, dLat=(c-a)*Math.PI/180, dLng=(d-b)*Math.PI/180;
  const x=Math.sin(dLat/2)**2 + Math.cos(a*Math.PI/180)*Math.cos(c*Math.PI/180)*Math.sin(dLng/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(x), Math.sqrt(1-x));
}
function fmt(km) { return km < 1 ? `${Math.round(km*1000)}m` : `${km.toFixed(1)}km`; }

function applyFilters() {
  const area  = document.getElementById('f-area').value;
  const genre = document.getElementById('f-genre').value;
  const budgt = document.getElementById('f-budget').value;
  const atmos = document.getElementById('f-atmosphere').value;
  const kw    = document.getElementById('f-keyword').value.trim().toLowerCase();
  let cnt = 0;
  STATE.filteredStores = STATE.stores.filter(s => {
    if (area  && s.area      !== area)  return false;
    if (genre && s.genre     !== genre) return false;
    if (budgt && s.budget    !== budgt) return false;
    if (atmos && s.atmosphere!== atmos) return false;
    if (kw && ![s.name,s.description,s.area,s.genre,s.atmosphere].some(v=>(v||'').toLowerCase().includes(kw))) return false;
    return true;
  });
  if (area)  cnt++; if (genre) cnt++; if (budgt) cnt++; if (atmos) cnt++; if (kw) cnt++;
  const b = document.getElementById('filter-badge');
  b.textContent = cnt;
  b.classList.toggle('hidden', cnt === 0);
  if (STATE.searchLat && STATE.searchLng) {
    STATE.filteredStores.forEach(s => { s._dist = (s.lat&&s.lng) ? haversine(STATE.searchLat,STATE.searchLng,s.lat,s.lng) : Infinity; });
    STATE.filteredStores.sort((a,b) => a._dist - b._dist);
  }
}

/* ─────────────────────────────────────────
   CARDS
───────────────────────────────────────── */
function isFav(id) { return STATE.favorites.some(f => f.id === id); }

function buildCard(store) {
  const fav  = isFav(store.id);
  const dist = (STATE.searchLat && STATE.searchLng && store.lat && store.lng)
    ? `<div class="card-distance">${fmt(store._dist)}</div>` : '';
  const photo = store.photo_url
    ? `<img class="card-photo" src="${store.photo_url}" alt="${store.name}" loading="lazy"
         onerror="this.parentElement.innerHTML='<div class=\\'card-photo-placeholder\\'><span>🍽</span><span>${store.genre||''}</span></div>'">`
    : `<div class="card-photo-placeholder"><span>🍽</span><span>${store.genre||'レストラン'}</span></div>`;
  const tags = [
    store.area       ? `<span class="card-tag tag-area">${store.area}</span>` : '',
    store.genre      ? `<span class="card-tag tag-genre">${store.genre}</span>` : '',
    store.budget     ? `<span class="card-tag tag-budget">${store.budget}</span>` : '',
    store.atmosphere ? `<span class="card-tag tag-atmos">${store.atmosphere}</span>` : '',
  ].join('');
  const el = document.createElement('div');
  el.className = 'store-card'; el.dataset.id = store.id;
  el.innerHTML = `
    <div class="card-photo-wrap">
      ${photo}
      <button class="card-fav-btn${fav?' active':''}" data-id="${store.id}">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="${fav?'#e53e3e':'none'}" stroke="${fav?'#e53e3e':'#555'}" stroke-width="2" stroke-linecap="round">
          <path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>
        </svg>
      </button>${dist}
    </div>
    <div class="card-body">
      <div class="card-tags">${tags}</div>
      <h3 class="card-name">${store.name}</h3>
      ${store.description ? `<p class="card-desc">${store.description}</p>` : ''}
      <div class="card-actions">
        ${store.map_url ? `<button class="card-action-btn btn-card-map" data-map="${store.map_url}">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/></svg>
          マップ</button>` : ''}
        <button class="card-action-btn btn-card-detail" data-id="${store.id}">詳細
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
        </button>
      </div>
    </div>`;
  return el;
}

function renderResults() {
  const grid    = document.getElementById('store-grid');
  const section = document.getElementById('results-section');
  const noRes   = document.getElementById('no-results');
  const count   = document.getElementById('results-count');
  section.classList.remove('hidden');
  grid.innerHTML = '';
  if (!STATE.filteredStores.length) {
    noRes.classList.remove('hidden');
    count.innerHTML = '0件のお店';
    return;
  }
  noRes.classList.add('hidden');
  count.innerHTML = `<strong>${STATE.filteredStores.length}</strong>件のお店が見つかりました`;
  const frag = document.createDocumentFragment();
  STATE.filteredStores.forEach(s => frag.appendChild(buildCard(s)));
  grid.appendChild(frag);
}

/* ─────────────────────────────────────────
   STORE DETAIL MODAL
───────────────────────────────────────── */
function openStoreModal(id) {
  const store = STATE.stores.find(s => s.id === id);
  if (!store) return;
  addHistory(store);
  const fav  = isFav(id);
  const tags = [
    store.area       ? `<span class="card-tag tag-area">${store.area}</span>` : '',
    store.genre      ? `<span class="card-tag tag-genre">${store.genre}</span>` : '',
    store.budget     ? `<span class="card-tag tag-budget">${store.budget}</span>` : '',
    store.atmosphere ? `<span class="card-tag tag-atmos">${store.atmosphere}</span>` : '',
  ].join('');
  const sns = [
    store.instagram_url ? `<a href="${store.instagram_url}" target="_blank" rel="noopener" class="modal-sns-btn btn-instagram">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="5"/><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/></svg>
      Instagramを見る</a>` : '',
    store.tiktok_url ? `<a href="${store.tiktok_url}" target="_blank" rel="noopener" class="modal-sns-btn btn-tiktok">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 01-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 01-2.88 2.5 2.89 2.89 0 01-2.89-2.89 2.89 2.89 0 012.89-2.89c.28 0 .54.04.79.1V9.01a6.3 6.3 0 00-.79-.05 6.34 6.34 0 00-6.34 6.34 6.34 6.34 0 006.34 6.34 6.34 6.34 0 006.33-6.34V9.37a8.16 8.16 0 004.77 1.52v-3.4a4.85 4.85 0 01-1-.8z"/></svg>
      TikTokを見る</a>` : '',
  ].filter(Boolean).join('');

  document.getElementById('store-modal-body').innerHTML = `
    ${store.photo_url
      ? `<img class="modal-hero-photo" src="${store.photo_url}" alt="${store.name}" loading="lazy">`
      : `<div class="modal-hero-placeholder">🍽</div>`}
    <div class="modal-content-pad">
      <div class="modal-tags">${tags}</div>
      <h2 class="modal-store-name">${store.name}</h2>
      ${store.address ? `<p style="font-size:.8rem;color:var(--text-soft);margin-bottom:8px">📍 ${store.address}</p>` : ''}
      ${store.description ? `<p class="modal-store-desc">${store.description}</p>` : ''}
      <div class="modal-actions">
        ${store.map_url ? `<a href="${store.map_url}" target="_blank" rel="noopener" class="modal-action-btn btn-modal-map">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/></svg>
          Googleマップで開く</a>` : ''}
        <button class="modal-action-btn btn-modal-fav${fav?' active':''}" id="modal-fav-btn" data-id="${id}">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="${fav?'#DC2626':'none'}" stroke="${fav?'#DC2626':'currentColor'}" stroke-width="2">
            <path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>
          </svg>
          ${fav ? 'お気に入り済み' : 'お気に入り'}
        </button>
      </div>
    </div>
    ${sns ? `<div class="modal-divider"></div><p class="modal-section-title">SNS・最新情報</p><div class="modal-sns-wrap">${sns}</div>` : ''}`;

  document.getElementById('modal-fav-btn').addEventListener('click', e => {
    const sid = e.currentTarget.dataset.id;
    toggleFavorite(sid);
    const f = isFav(sid);
    const btn = document.getElementById('modal-fav-btn');
    btn.classList.toggle('active', f);
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="${f?'#DC2626':'none'}" stroke="${f?'#DC2626':'currentColor'}" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>${f?'お気に入り済み':'お気に入り'}`;
    syncFavBtn(sid, f);
  });
  openModal('store-modal');
}

function syncFavBtn(id, faved) {
  const btn = document.querySelector(`.card-fav-btn[data-id="${id}"]`);
  if (!btn) return;
  btn.classList.toggle('active', faved);
  btn.innerHTML = `<svg width="17" height="17" viewBox="0 0 24 24" fill="${faved?'#e53e3e':'none'}" stroke="${faved?'#e53e3e':'#555'}" stroke-width="2" stroke-linecap="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`;
}

/* ─────────────────────────────────────────
   MAP
───────────────────────────────────────── */
function openMapModal() {
  openModal('map-modal');
  setTimeout(initMap, 120);
}

function initMap() {
  const container = document.getElementById('map-container');
  if (!container) return;
  if (STATE.mapInstance) { STATE.mapInstance.remove(); STATE.mapInstance = null; }
  container.style.height = '100%';
  const lat = STATE.searchLat || 35.6812;
  const lng = STATE.searchLng || 139.7671;
  const map = L.map('map-container').setView([lat, lng], 14);
  STATE.mapInstance = map;
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap', maxZoom: 19 }).addTo(map);
  if (STATE.searchLat) {
    L.marker([STATE.searchLat, STATE.searchLng], { icon: L.divIcon({
      html: '<div style="width:14px;height:14px;border-radius:50%;background:#00704A;border:3px solid white;box-shadow:0 2px 8px rgba(0,0,0,.4)"></div>',
      className:'', iconSize:[14,14], iconAnchor:[7,7] })
    }).addTo(map).bindPopup(`<strong>${STATE.searchLabel}</strong>`);
  }
  STATE.filteredStores.forEach(s => {
    if (!s.lat || !s.lng) return;
    L.marker([s.lat, s.lng], { icon: L.divIcon({
      html: `<div style="width:30px;height:30px;border-radius:50% 50% 50% 0;transform:rotate(-45deg);background:#CBA258;border:3px solid white;box-shadow:0 2px 8px rgba(0,0,0,.3)"></div>`,
      className:'', iconSize:[30,30], iconAnchor:[15,30] })
    }).addTo(map).bindPopup(`<div style="min-width:140px;font-family:sans-serif">
      ${s.photo_url?`<img src="${s.photo_url}" style="width:100%;height:70px;object-fit:cover;border-radius:6px;margin-bottom:6px">`:''}
      <strong style="font-size:13px">${s.name}</strong><br>
      <span style="font-size:11px;color:#666">${s.genre||''}</span>
      ${s.map_url?`<br><a href="${s.map_url}" target="_blank" style="font-size:11px;color:#00704A">マップで開く →</a>`:''}</div>`);
  });
  const pts = STATE.filteredStores.filter(s=>s.lat&&s.lng).map(s=>[s.lat,s.lng]);
  if (STATE.searchLat) pts.push([STATE.searchLat, STATE.searchLng]);
  if (pts.length > 1) map.fitBounds(L.latLngBounds(pts), {padding:[40,40]});
}

/* ─────────────────────────────────────────
   MODAL HELPERS
───────────────────────────────────────── */
function openModal(id) { document.getElementById(id).classList.add('open'); document.body.style.overflow='hidden'; }
function closeModal(id) { document.getElementById(id).classList.remove('open'); document.body.style.overflow=''; }
function closeAllModals() { document.querySelectorAll('.modal.open').forEach(m=>m.classList.remove('open')); document.body.style.overflow=''; }

/* ─────────────────────────────────────────
   FAVORITES
───────────────────────────────────────── */
function toggleFavorite(id) {
  const store = STATE.stores.find(s => s.id === id);
  if (!store) return;
  const idx = STATE.favorites.findIndex(f => f.id === id);
  if (idx >= 0) STATE.favorites.splice(idx, 1);
  else STATE.favorites.unshift({ id:store.id, name:store.name, photo_url:store.photo_url||'', map_url:store.map_url||'', area:store.area||'', genre:store.genre||'', budget:store.budget||'' });
  LS.save(LS.KEY_FAV, STATE.favorites);
  updateFavBadge();
  if (STATE.activePanel === 'favorites') renderFavorites();
}

function updateFavBadge() {
  const n = STATE.favorites.length;
  const b = document.getElementById('fav-nav-badge');
  b.textContent = n; b.classList.toggle('hidden', n === 0);
}

function renderFavorites() {
  const list=document.getElementById('favorites-list'), empty=document.getElementById('fav-empty');
  document.getElementById('fav-total').textContent = `${STATE.favorites.length}件`;
  if (!STATE.favorites.length) { list.innerHTML=''; empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden'); list.innerHTML='';
  const frag = document.createDocumentFragment();
  STATE.favorites.forEach(fav => {
    const el = document.createElement('div'); el.className='list-card';
    el.innerHTML=`<img class="list-card-photo" src="${fav.photo_url}" alt="${fav.name}" onerror="this.style.background='var(--g-pale)'">
      <div class="list-card-info"><div class="list-card-name">${fav.name}</div>
      <div class="list-card-meta">${[fav.area,fav.genre,fav.budget].filter(Boolean).join(' · ')}</div></div>
      <button class="list-card-remove" data-id="${fav.id}">✕</button>`;
    el.querySelector('.list-card-info').addEventListener('click', ()=>openStoreModal(fav.id));
    el.querySelector('.list-card-remove').addEventListener('click', e=>{e.stopPropagation();toggleFavorite(fav.id);syncFavBtn(fav.id,false);});
    frag.appendChild(el);
  });
  list.appendChild(frag);
}

function addHistory(store) {
  STATE.history = STATE.history.filter(h => h.id !== store.id);
  STATE.history.unshift({ id:store.id, name:store.name, photo_url:store.photo_url||'', area:store.area||'', genre:store.genre||'',
    date: new Date().toLocaleDateString('ja-JP',{month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit'}) });
  if (STATE.history.length > 30) STATE.history = STATE.history.slice(0, 30);
  LS.save(LS.KEY_HIST, STATE.history);
}

function renderHistory() {
  const list=document.getElementById('history-list'), empty=document.getElementById('history-empty');
  if (!STATE.history.length) { list.innerHTML=''; empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden'); list.innerHTML='';
  const frag = document.createDocumentFragment();
  STATE.history.forEach(h => {
    const el=document.createElement('div'); el.className='list-card';
    el.innerHTML=`<img class="list-card-photo" src="${h.photo_url}" alt="${h.name}" onerror="this.style.background='var(--g-pale)'">
      <div class="list-card-info"><div class="list-card-name">${h.name}</div>
      <div class="list-card-meta">${[h.area,h.genre].filter(Boolean).join(' · ')}</div>
      <div class="list-card-date">🕐 ${h.date}</div></div>`;
    el.addEventListener('click', ()=>openStoreModal(h.id));
    frag.appendChild(el);
  });
  list.appendChild(frag);
}

/* ─────────────────────────────────────────
   GEOLOCATION & NOMINATIM
───────────────────────────────────────── */
function getCurrentLocation() {
  if (!navigator.geolocation) { alert('このブラウザはGPSに対応していません'); return; }
  const btn=document.getElementById('btn-current'), save=btn.innerHTML;
  btn.innerHTML=`<div class="loc-icon-wrap"><div style="width:24px;height:24px;border:3px solid rgba(255,255,255,.3);border-top-color:white;border-radius:50%;animation:spin 0.8s linear infinite"></div></div><div class="loc-text"><strong>取得中...</strong></div>`;
  btn.disabled=true;
  navigator.geolocation.getCurrentPosition(
    pos => {
      STATE.searchLat=pos.coords.latitude; STATE.searchLng=pos.coords.longitude; STATE.searchLabel='現在地';
      showLocStatus('📍 現在地を取得しました');
      btn.innerHTML=save; btn.disabled=false;
      document.getElementById('dest-input-area').classList.add('hidden');
    },
    err => {
      btn.innerHTML=save; btn.disabled=false;
      alert(['','GPS利用が許可されていません','タイムアウト','取得できませんでした'][err.code]||'位置情報の取得に失敗しました');
    },
    {enableHighAccuracy:true, timeout:10000, maximumAge:60000}
  );
}

async function geocodeDestination() {
  const q=document.getElementById('dest-text').value.trim();
  if (!q) { alert('場所名を入力してください'); return; }
  const btn=document.getElementById('btn-geocode'), save=btn.innerHTML;
  btn.innerHTML='<div style="width:18px;height:18px;border:2px solid rgba(30,57,50,.3);border-top-color:#1E3932;border-radius:50%;animation:spin 0.8s linear infinite"></div>';
  btn.disabled=true;
  try {
    const res=await fetch(`https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q+' 日本')}&format=json&limit=1`,
      {headers:{'Accept-Language':'ja','User-Agent':'KaishokuSelect/1.0'}});
    const data=await res.json();
    if (!data.length) { alert(`「${q}」が見つかりませんでした`); return; }
    STATE.searchLat=parseFloat(data[0].lat); STATE.searchLng=parseFloat(data[0].lon);
    STATE.searchLabel=data[0].display_name.split(',')[0];
    showLocStatus(`📍 ${STATE.searchLabel}`);
  } catch { alert('検索中にエラーが発生しました'); }
  finally { btn.innerHTML=save; btn.disabled=false; }
}

function showLocStatus(label) {
  document.getElementById('loc-label').textContent = label;
  document.getElementById('loc-status').classList.remove('hidden');
}

/* ─────────────────────────────────────────
   PANEL NAVIGATION
───────────────────────────────────────── */
function switchPanel(id) {
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById(`panel-${id}`).classList.add('active');
  document.querySelector(`.nav-item[data-panel="${id}"]`).classList.add('active');
  STATE.activePanel=id;
  if (id==='favorites') renderFavorites();
  if (id==='history')   renderHistory();
  window.scrollTo({top:0,behavior:'smooth'});
}

/* ─────────────────────────────────────────
   CONFIG
───────────────────────────────────────── */
function openConfigModal() {
  document.getElementById('sheet-id-input').value = STATE.sheetId;
  openModal('config-modal');
}
async function saveConfig() {
  const id=document.getElementById('sheet-id-input').value.trim();
  if (!id) { alert('スプレッドシートIDを入力してください'); return; }
  localStorage.setItem(LS.KEY_SHEET,id); localStorage.removeItem(LS.KEY_DEMO);
  STATE.sheetId=id; STATE.usingDemo=false;
  closeModal('config-modal');
  try { STATE.stores=await loadStoresFromSheet(id); buildFilterOptions(STATE.stores); showToast(`${STATE.stores.length}件読み込みました`); }
  catch { alert('読み込みに失敗しました。IDとシートの公開設定を確認してください'); }
}
function loadDemoData() {
  localStorage.setItem(LS.KEY_DEMO,'true'); localStorage.removeItem(LS.KEY_SHEET);
  STATE.usingDemo=true; STATE.stores=[...DEMO_STORES]; buildFilterOptions(STATE.stores);
  closeModal('config-modal'); showToast('デモデータを読み込みました！「お店を探す」を押してください');
}

/* ─────────────────────────────────────────
   TOAST
───────────────────────────────────────── */
function showToast(msg, ms=3000) {
  let t=document.getElementById('app-toast');
  if (!t) {
    t=document.createElement('div'); t.id='app-toast';
    t.style.cssText='position:fixed;bottom:calc(var(--nav-h)+16px);left:50%;transform:translateX(-50%);background:var(--g-dark);color:var(--g-light);padding:12px 20px;border-radius:var(--r-full);font-size:.85rem;font-weight:500;box-shadow:0 4px 20px rgba(0,0,0,.3);z-index:500;max-width:90vw;text-align:center;transition:opacity .3s ease;white-space:nowrap';
    document.body.appendChild(t);
  }
  t.textContent=msg; t.style.opacity='1';
  clearTimeout(t._t); t._t=setTimeout(()=>{t.style.opacity='0';},ms);
}

/* ─────────────────────────────────────────
   SEARCH
───────────────────────────────────────── */
function doSearch() {
  if (!STATE.stores.length) { openConfigModal(); return; }
  applyFilters(); renderResults();
  setTimeout(()=>document.getElementById('results-section').scrollIntoView({behavior:'smooth',block:'start'}),100);
}

/* ─────────────────────────────────────────
   EVENT LISTENERS
───────────────────────────────────────── */
function attachEvents() {
  document.getElementById('btn-current').addEventListener('click', getCurrentLocation);
  document.getElementById('btn-destination').addEventListener('click', ()=>{
    document.getElementById('dest-input-area').classList.toggle('hidden');
    document.getElementById('dest-text').focus();
  });
  document.getElementById('btn-geocode').addEventListener('click', geocodeDestination);
  document.getElementById('dest-text').addEventListener('keydown', e=>{if(e.key==='Enter')geocodeDestination();});
  document.getElementById('btn-clear-loc').addEventListener('click', ()=>{
    STATE.searchLat=STATE.searchLng=null; STATE.searchLabel='';
    document.getElementById('loc-status').classList.add('hidden');
    document.getElementById('dest-input-area').classList.add('hidden');
    document.getElementById('dest-text').value='';
  });
  document.getElementById('filter-toggle').addEventListener('click', ()=>{
    STATE.filterOpen=!STATE.filterOpen;
    document.getElementById('filter-body').classList.toggle('hidden',!STATE.filterOpen);
    document.getElementById('filter-chevron').classList.toggle('open',STATE.filterOpen);
  });
  document.getElementById('btn-clear-filter').addEventListener('click', ()=>{
    ['f-area','f-genre','f-budget','f-atmosphere'].forEach(id=>document.getElementById(id).value='');
    document.getElementById('f-keyword').value='';
    document.getElementById('filter-badge').classList.add('hidden');
  });
  document.getElementById('btn-search').addEventListener('click', doSearch);
  document.getElementById('btn-show-map').addEventListener('click', openMapModal);
  document.querySelectorAll('.nav-item').forEach(b=>b.addEventListener('click',()=>switchPanel(b.dataset.panel)));
  document.getElementById('btn-clear-history').addEventListener('click',()=>{
    if (!STATE.history.length) return;
    if (confirm('閲覧履歴をすべて削除しますか？')) { STATE.history=[]; LS.save(LS.KEY_HIST,[]); renderHistory(); }
  });
  document.getElementById('config-btn').addEventListener('click', openConfigModal);
  document.getElementById('btn-save-config').addEventListener('click', saveConfig);
  document.getElementById('btn-demo').addEventListener('click', loadDemoData);

  document.getElementById('store-grid').addEventListener('click', e=>{
    const fab=e.target.closest('.card-fav-btn'), det=e.target.closest('.btn-card-detail'),
          map=e.target.closest('.btn-card-map'), card=e.target.closest('.store-card');
    if (fab) {
      e.stopPropagation(); toggleFavorite(fab.dataset.id); const f=isFav(fab.dataset.id);
      fab.classList.toggle('active',f);
      fab.innerHTML=`<svg width="17" height="17" viewBox="0 0 24 24" fill="${f?'#e53e3e':'none'}" stroke="${f?'#e53e3e':'#555'}" stroke-width="2" stroke-linecap="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`;
      showToast(f?'♡ お気に入りに追加':'お気に入りから削除');
    } else if (det) { openStoreModal(det.dataset.id); }
    else if (map)   { window.open(map.dataset.map,'_blank','noopener'); }
    else if (card)  { openStoreModal(card.dataset.id); }
  });

  document.getElementById('store-close').addEventListener('click', ()=>closeModal('store-modal'));
  document.getElementById('store-backdrop').addEventListener('click', ()=>closeModal('store-modal'));
  document.getElementById('map-close').addEventListener('click', ()=>closeModal('map-modal'));
  document.getElementById('map-backdrop').addEventListener('click', ()=>closeModal('map-modal'));
  document.getElementById('config-backdrop').addEventListener('click', ()=>closeModal('config-modal'));
  document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeAllModals(); });
}

/* ─────────────────────────────────────────
   ENTRY POINT — 単一の DOMContentLoaded
───────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  AuthUI.init();
});
