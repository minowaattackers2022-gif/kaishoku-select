/* ============================================================
   会食セレクト — script.js
   会食店舗検索アプリ完全ロジック
   ============================================================ */

'use strict';

/* ============================================================
   AUTH MODULE — メール＋パスワード認証
   Web Crypto API (SHA-256) を使用。外部サーバー送信なし。
   認証情報はlocalStorage、セッションはsessionStorage/localStorage管理。
   ============================================================ */

const AUTH = {
  KEY_CRED:    'kaishoku_credentials', // {emailHash, passwordHash, salt}
  KEY_SESSION: 'kaishoku_session',     // sessionStorage
  KEY_REMEMBER:'kaishoku_remember',    // localStorage (remember me)
  MAX_ATTEMPTS: 5,
  LOCKOUT_MS:  5 * 60 * 1000, // 5分間ロック
  KEY_ATTEMPTS:'kaishoku_auth_attempts',

  /* ── SHA-256 ハッシュ ── */
  async sha256(text) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  },

  /* ── Salt生成 ── */
  generateSalt() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
  },

  /* ── 認証情報の保存（初回設定） ── */
  async saveCredentials(email, password) {
    const salt          = this.generateSalt();
    const emailHash     = await this.sha256(email.toLowerCase().trim());
    const passwordHash  = await this.sha256(password + salt);
    localStorage.setItem(this.KEY_CRED, JSON.stringify({ emailHash, passwordHash, salt }));
  },

  /* ── 認証情報の存在確認 ── */
  hasCredentials() {
    return !!localStorage.getItem(this.KEY_CRED);
  },

  /* ── ログイン試行ロック確認 ── */
  isLockedOut() {
    try {
      const data = JSON.parse(localStorage.getItem(this.KEY_ATTEMPTS) || '{}');
      if (data.lockUntil && Date.now() < data.lockUntil) return true;
      if (data.lockUntil && Date.now() >= data.lockUntil) {
        localStorage.removeItem(this.KEY_ATTEMPTS);
      }
    } catch {}
    return false;
  },

  remainingLockSeconds() {
    try {
      const data = JSON.parse(localStorage.getItem(this.KEY_ATTEMPTS) || '{}');
      if (data.lockUntil) return Math.ceil((data.lockUntil - Date.now()) / 1000);
    } catch {}
    return 0;
  },

  recordFailedAttempt() {
    try {
      const data  = JSON.parse(localStorage.getItem(this.KEY_ATTEMPTS) || '{"count":0}');
      data.count  = (data.count || 0) + 1;
      if (data.count >= this.MAX_ATTEMPTS) {
        data.lockUntil = Date.now() + this.LOCKOUT_MS;
        data.count = 0;
      }
      localStorage.setItem(this.KEY_ATTEMPTS, JSON.stringify(data));
      return this.MAX_ATTEMPTS - (data.count || 0);
    } catch { return 0; }
  },

  clearAttempts() {
    localStorage.removeItem(this.KEY_ATTEMPTS);
  },

  /* ── 認証検証 ── */
  async verify(email, password) {
    try {
      const cred         = JSON.parse(localStorage.getItem(this.KEY_CRED));
      if (!cred)         return false;
      const emailHash    = await this.sha256(email.toLowerCase().trim());
      const passwordHash = await this.sha256(password + cred.salt);
      return emailHash === cred.emailHash && passwordHash === cred.passwordHash;
    } catch { return false; }
  },

  /* ── セッション管理 ── */
  createSession(email, remember) {
    const token = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
    const data  = JSON.stringify({ token, email, ts: Date.now() });
    sessionStorage.setItem(this.KEY_SESSION, data);
    if (remember) localStorage.setItem(this.KEY_REMEMBER, data);
    this.clearAttempts();
  },

  isAuthenticated() {
    try {
      const session = sessionStorage.getItem(this.KEY_SESSION)
                   || localStorage.getItem(this.KEY_REMEMBER);
      if (!session) return false;
      const data = JSON.parse(session);
      // remember me: 30日有効
      if (localStorage.getItem(this.KEY_REMEMBER)) {
        return (Date.now() - data.ts) < 30 * 24 * 60 * 60 * 1000;
      }
      return !!data.token;
    } catch { return false; }
  },

  getSessionEmail() {
    try {
      const session = sessionStorage.getItem(this.KEY_SESSION)
                   || localStorage.getItem(this.KEY_REMEMBER);
      if (!session) return '';
      return JSON.parse(session).email || '';
    } catch { return ''; }
  },

  logout() {
    sessionStorage.removeItem(this.KEY_SESSION);
    localStorage.removeItem(this.KEY_REMEMBER);
  },
};

/* ── Auth UI Controller ── */
const AuthUI = {
  init() {
    this.bindEvents();
    if (AUTH.isAuthenticated()) {
      this.showApp();
    } else if (!AUTH.hasCredentials()) {
      this.showSetup();
    } else {
      this.showLogin();
    }
  },

  showLogin() {
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('login-card').classList.remove('hidden');
    document.getElementById('setup-card').classList.add('hidden');
    setTimeout(() => document.getElementById('login-email').focus(), 300);
  },

  showSetup() {
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('login-card').classList.add('hidden');
    document.getElementById('setup-card').classList.remove('hidden');
    setTimeout(() => document.getElementById('setup-email').focus(), 300);
  },

  showApp() {
    document.getElementById('login-screen').classList.add('hidden');
    const email = AUTH.getSessionEmail();
    // show email in header (truncated)
    const hdr = document.getElementById('app-header');
    if (hdr && email) {
      let indicator = document.getElementById('header-user-email');
      if (!indicator) {
        indicator = document.createElement('span');
        indicator.id = 'header-user-email';
        indicator.className = 'header-user';
        document.querySelector('.brand').appendChild(indicator);
      }
      indicator.textContent = email;
    }
  },

  setLoginError(msg) {
    const el = document.getElementById('login-error');
    el.textContent = msg;
    el.classList.remove('hidden');
    document.getElementById('login-email').classList.add('error');
    document.getElementById('login-password').classList.add('error');
  },

  clearLoginError() {
    document.getElementById('login-error').classList.add('hidden');
    document.getElementById('login-email').classList.remove('error');
    document.getElementById('login-password').classList.remove('error');
  },

  setSetupError(msg) {
    const el = document.getElementById('setup-error');
    el.textContent = msg;
    el.classList.remove('hidden');
  },

  async handleLogin() {
    this.clearLoginError();
    const email    = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const remember = document.getElementById('remember-me').checked;

    if (!email || !password) {
      this.setLoginError('メールアドレスとパスワードを入力してください');
      return;
    }

    // Lockout check
    if (AUTH.isLockedOut()) {
      const sec = AUTH.remainingLockSeconds();
      this.setLoginError(`試行回数が多すぎます。あと ${sec} 秒お待ちください`);
      return;
    }

    // Spinner
    document.getElementById('login-btn-text').style.display = 'none';
    document.getElementById('login-spinner').classList.remove('hidden');
    document.getElementById('btn-login').disabled = true;

    const ok = await AUTH.verify(email, password);

    document.getElementById('login-btn-text').style.display = '';
    document.getElementById('login-spinner').classList.add('hidden');
    document.getElementById('btn-login').disabled = false;

    if (ok) {
      AUTH.createSession(email, remember);
      // Brief success animation
      document.getElementById('login-card').style.transform = 'scale(0.98)';
      setTimeout(() => { this.showApp(); init(); }, 250);
    } else {
      const remaining = AUTH.recordFailedAttempt();
      if (remaining > 0) {
        this.setLoginError(`認証情報が正しくありません（残り ${remaining} 回）`);
      } else {
        this.setLoginError(`試行回数が上限に達しました。5分後に再試行してください`);
      }
      document.getElementById('login-password').value = '';
      document.getElementById('login-password').focus();
    }
  },

  async handleSetup() {
    const email    = document.getElementById('setup-email').value.trim();
    const password = document.getElementById('setup-password').value;
    const confirm  = document.getElementById('setup-confirm').value;

    if (!email || !password || !confirm) {
      this.setSetupError('すべての項目を入力してください');
      return;
    }
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) {
      this.setSetupError('正しいメールアドレスの形式で入力してください');
      return;
    }
    if (password.length < 8) {
      this.setSetupError('パスワードは8文字以上にしてください');
      return;
    }
    if (password !== confirm) {
      this.setSetupError('パスワードが一致しません');
      return;
    }

    document.getElementById('btn-setup-save').disabled = true;
    await AUTH.saveCredentials(email, password);
    AUTH.createSession(email, false);
    this.showApp();
    init();
  },

  handleLogout() {
    if (!confirm('ログアウトしますか？')) return;
    AUTH.logout();
    document.getElementById('login-email').value = '';
    document.getElementById('login-password').value = '';
    this.clearLoginError();
    this.showLogin();
    // Hide app content
    document.getElementById('login-screen').classList.remove('hidden');
  },

  bindEvents() {
    document.getElementById('btn-login').addEventListener('click', () => this.handleLogin());
    document.getElementById('login-password').addEventListener('keydown', e => {
      if (e.key === 'Enter') this.handleLogin();
    });
    document.getElementById('login-email').addEventListener('keydown', e => {
      if (e.key === 'Enter') document.getElementById('login-password').focus();
    });
    document.getElementById('btn-to-setup').addEventListener('click', () => this.showSetup());
    document.getElementById('btn-to-login').addEventListener('click',  () => this.showLogin());
    document.getElementById('btn-setup-save').addEventListener('click',() => this.handleSetup());

    // Password visibility toggle
    document.getElementById('toggle-login-pw').addEventListener('click', () => {
      const input  = document.getElementById('login-password');
      const eyeOn  = document.getElementById('pw-eye-on');
      const eyeOff = document.getElementById('pw-eye-off');
      const show   = input.type === 'password';
      input.type   = show ? 'text' : 'password';
      eyeOn.style.display  = show ? 'none' : '';
      eyeOff.style.display = show ? '' : 'none';
    });

    // Logout
    document.getElementById('btn-logout').addEventListener('click', () => this.handleLogout());

    // Backdrop click closes nothing (security: must click buttons)
  },
};

/* ── Auth Entry Point (runs before main init) ── */
document.addEventListener('DOMContentLoaded', () => {
  AuthUI.init();
});

/* ─────────────────────────────────────────
   DEMO DATA (スプレッドシート未設定時の代替)
───────────────────────────────────────── */
const DEMO_STORES = [
  { id:'d01', name:'銀座 鮨 真田', area:'銀座', genre:'寿司・鮨', budget:'¥30,000〜', atmosphere:'高級・接待向き',
    photo_url:'https://images.unsplash.com/photo-1579871494447-9811cf80d66c?w=600&q=80',
    map_url:'https://maps.google.com/?q=銀座+寿司', instagram_url:'https://instagram.com', tiktok_url:'',
    address:'東京都中央区銀座5-5-1', lat:35.6718, lng:139.7650,
    description:'江戸前の伝統を守りながら現代の感性で昇華させた鮨の名店。厳選された旬の食材と職人の技が光る。接待・会食に最適な個室完備。' },
  { id:'d02', name:'恵比寿 Bistro 葉月', area:'恵比寿', genre:'フレンチ・イタリアン', budget:'¥15,000〜',atmosphere:'大人カジュアル',
    photo_url:'https://images.unsplash.com/photo-1414235077428-338989a2e8c0?w=600&q=80',
    map_url:'https://maps.google.com/?q=恵比寿+フレンチ', instagram_url:'https://instagram.com', tiktok_url:'',
    address:'東京都渋谷区恵比寿3-8-14', lat:35.6465, lng:139.7139,
    description:'地中海の風を感じるカジュアルフレンチ。ソムリエ厳選のワインと、旬の食材を使ったコースが大人気。ガラス張りの開放的な空間。' },
  { id:'d03', name:'新宿 割烹 月夜', area:'新宿', genre:'和食・割烹', budget:'¥20,000〜', atmosphere:'和モダン・落ち着き',
    photo_url:'https://images.unsplash.com/photo-1504674900247-0877df9cc836?w=600&q=80',
    map_url:'https://maps.google.com/?q=新宿+割烹', instagram_url:'https://instagram.com', tiktok_url:'',
    address:'東京都新宿区新宿3-1-26', lat:35.6896, lng:139.7006,
    description:'隠れ家的な一軒家割烹。旬の食材にこだわった本格会席料理。静寂と品格が漂う空間で、大切な会食に相応しい。完全個室対応可能。' },
  { id:'d04', name:'六本木 The Rooftop', area:'六本木', genre:'フュージョン・モダン', budget:'¥20,000〜', atmosphere:'スタイリッシュ・景色◎',
    photo_url:'https://images.unsplash.com/photo-1552566626-52f8b828add9?w=600&q=80',
    map_url:'https://maps.google.com/?q=六本木+ルーフトップ+レストラン', instagram_url:'https://instagram.com', tiktok_url:'https://tiktok.com',
    address:'東京都港区六本木6-10-1', lat:35.6628, lng:139.7316,
    description:'東京タワーを望む最高のロケーション。モダンジャパニーズとフレンチのフュージョン料理。特別な夜に彩りを添える一軒。スタイリッシュな空間が話題を呼んでいる。' },
  { id:'d05', name:'渋谷 焼肉 黒毛座', area:'渋谷', genre:'焼肉・肉料理', budget:'¥10,000〜', atmosphere:'活気・賑やか',
    photo_url:'https://images.unsplash.com/photo-1558030006-450675393462?w=600&q=80',
    map_url:'https://maps.google.com/?q=渋谷+焼肉', instagram_url:'https://instagram.com', tiktok_url:'https://tiktok.com',
    address:'東京都渋谷区道玄坂1-8-3', lat:35.6595, lng:139.6979,
    description:'最高級A5黒毛和牛を堪能できる焼肉の名店。希少部位から定番まで、肉の芸術を味わえる。活気ある雰囲気でビジネスを超えた会食に。' },
  { id:'d06', name:'丸の内 個室和牛 一頭', area:'丸の内', genre:'焼肉・肉料理', budget:'¥25,000〜', atmosphere:'高級・接待向き',
    photo_url:'https://images.unsplash.com/photo-1546069901-ba9599a7e63c?w=600&q=80',
    map_url:'https://maps.google.com/?q=丸の内+和牛', instagram_url:'https://instagram.com', tiktok_url:'',
    address:'東京都千代田区丸の内2-4-1', lat:35.6796, lng:139.7644,
    description:'一棟貸切りの完全個室で楽しむ最高峰の和牛料理。全席個室でプライベート感抜群。ビジネスの大切な接待にも最適。ソムリエが厳選した日本酒・ワインも充実。' },
  { id:'d07', name:'品川 シーフード テラス', area:'品川', genre:'シーフード・魚介', budget:'¥15,000〜', atmosphere:'開放的・テラス席',
    photo_url:'https://images.unsplash.com/photo-1559339352-11d035aa65de?w=600&q=80',
    map_url:'https://maps.google.com/?q=品川+シーフード', instagram_url:'https://instagram.com', tiktok_url:'',
    address:'東京都港区高輪4-10-30', lat:35.6285, lng:139.7365,
    description:'東京湾を一望するテラスで楽しむシーフードの祭典。産直の新鮮魚介をダイナミックに調理。夕暮れ時のテラス席は絶景。大人数での会食にも対応。' },
  { id:'d08', name:'上野 中華料理 龍苑', area:'上野', genre:'中華・点心', budget:'¥8,000〜', atmosphere:'賑やか・ファミリー向き',
    photo_url:'https://images.unsplash.com/photo-1563245372-f21724e3856d?w=600&q=80',
    map_url:'https://maps.google.com/?q=上野+中華料理', instagram_url:'', tiktok_url:'',
    address:'東京都台東区上野4-1-3', lat:35.7089, lng:139.7745,
    description:'本格広東料理と飲茶の名店。点心師が丁寧に作る手作り点心が絶品。大きな円卓を囲む宴会にも対応。老若男女に愛される活気ある空間。' },
];

/* ─────────────────────────────────────────
   STATE
───────────────────────────────────────── */
const STATE = {
  stores:        [],
  filteredStores:[],
  favorites:     [],    // [{id,name,photo_url,map_url,area,genre,budget}]
  history:       [],    // [{id,name,photo_url,area,date}]
  searchLat:     null,
  searchLng:     null,
  searchLabel:   '',
  mapInstance:   null,
  mapMarkers:    [],
  activePanel:   'search',
  filterOpen:    false,
  sheetId:       '',
  usingDemo:     false,
};

/* ─────────────────────────────────────────
   LOCAL STORAGE
───────────────────────────────────────── */
const LS = {
  KEY_FAV:     'kaishoku_favorites',
  KEY_HIST:    'kaishoku_history',
  KEY_SHEET:   'kaishoku_sheet_id',
  KEY_DEMO:    'kaishoku_use_demo',
  KEY_STORES:  'kaishoku_stores_cache',

  loadFavorites()  { try { return JSON.parse(localStorage.getItem(this.KEY_FAV) || '[]'); } catch { return []; } },
  saveFavorites(d) { localStorage.setItem(this.KEY_FAV,  JSON.stringify(d)); },
  loadHistory()    { try { return JSON.parse(localStorage.getItem(this.KEY_HIST) || '[]'); } catch { return []; } },
  saveHistory(d)   { localStorage.setItem(this.KEY_HIST, JSON.stringify(d)); },
  loadSheetId()    { return localStorage.getItem(this.KEY_SHEET) || ''; },
  saveSheetId(id)  { localStorage.setItem(this.KEY_SHEET, id); },
  loadUseDemo()    { return localStorage.getItem(this.KEY_DEMO) === 'true'; },
  saveUseDemo(v)   { localStorage.setItem(this.KEY_DEMO, String(v)); },
};

/* ─────────────────────────────────────────
   GOOGLE SHEETS DATA LOADER
───────────────────────────────────────── */
async function loadStoresFromSheet(sheetId) {
  const url = `https://docs.google.com/spreadsheets/d/${sheetId}/gviz/tq?tqx=out:json`;
  const res = await fetch(url);
  const text = await res.text();
  const match = text.match(/google\.visualization\.Query\.setResponse\(([\s\S]*)\)/);
  if (!match) throw new Error('Invalid sheet response');
  const data = JSON.parse(match[1]);
  const cols = data.table.cols.map(c => c.label.trim().toLowerCase().replace(/\s+/g,'_'));
  return data.table.rows.map((row, i) => {
    const obj = { id: `s${i}` };
    row.c.forEach((cell, j) => {
      obj[cols[j]] = cell ? (cell.v !== null ? String(cell.v) : '') : '';
    });
    obj.lat = parseFloat(obj.lat) || 0;
    obj.lng = parseFloat(obj.lng) || 0;
    return obj;
  }).filter(s => s.name);
}

/* ─────────────────────────────────────────
   FILTER DROPDOWNS BUILDER
───────────────────────────────────────── */
function buildFilterOptions(stores) {
  const unique = (key) => [...new Set(stores.map(s => s[key]).filter(Boolean))].sort();
  ['area','genre','budget','atmosphere'].forEach(key => {
    const sel = document.getElementById(`f-${key === 'atmosphere' ? 'atmosphere' : key}`);
    if (!sel) return;
    const current = sel.value;
    while (sel.options.length > 1) sel.remove(1);
    unique(key).forEach(val => {
      const opt = document.createElement('option');
      opt.value = val; opt.textContent = val;
      sel.appendChild(opt);
    });
    if (current) sel.value = current;
  });
}

/* ─────────────────────────────────────────
   DISTANCE CALCULATION (Haversine)
───────────────────────────────────────── */
function haversine(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat/2)**2 +
            Math.cos(lat1*Math.PI/180) * Math.cos(lat2*Math.PI/180) * Math.sin(dLng/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

function formatDist(km) {
  return km < 1 ? `${Math.round(km*1000)}m` : `${km.toFixed(1)}km`;
}

/* ─────────────────────────────────────────
   FILTER ENGINE
───────────────────────────────────────── */
function applyFilters() {
  const area  = document.getElementById('f-area').value;
  const genre = document.getElementById('f-genre').value;
  const budgt = document.getElementById('f-budget').value;
  const atmos = document.getElementById('f-atmosphere').value;
  const kw    = document.getElementById('f-keyword').value.trim().toLowerCase();

  let count = 0;
  STATE.filteredStores = STATE.stores.filter(s => {
    if (area  && s.area       !== area)  return false;
    if (genre && s.genre      !== genre) return false;
    if (budgt && s.budget     !== budgt) return false;
    if (atmos && s.atmosphere !== atmos) return false;
    if (kw && ![s.name, s.description, s.area, s.genre, s.atmosphere]
              .some(v => (v||'').toLowerCase().includes(kw))) return false;
    return true;
  });

  if (area)  count++;
  if (genre) count++;
  if (budgt) count++;
  if (atmos) count++;
  if (kw)    count++;

  const badge = document.getElementById('filter-badge');
  if (count > 0) { badge.textContent = count; badge.classList.remove('hidden'); }
  else           { badge.classList.add('hidden'); }

  // Sort by distance if location available
  if (STATE.searchLat && STATE.searchLng) {
    STATE.filteredStores.forEach(s => {
      s._dist = (s.lat && s.lng) ? haversine(STATE.searchLat, STATE.searchLng, s.lat, s.lng) : Infinity;
    });
    STATE.filteredStores.sort((a,b) => a._dist - b._dist);
  }
}

/* ─────────────────────────────────────────
   RENDER STORE CARD
───────────────────────────────────────── */
function isFav(id) { return STATE.favorites.some(f => f.id === id); }

function renderStoreCard(store) {
  const favored = isFav(store.id);
  const distHtml = (STATE.searchLat && STATE.searchLng && store.lat && store.lng)
    ? `<div class="card-distance">${formatDist(store._dist)}</div>` : '';

  const photoHtml = store.photo_url
    ? `<img class="card-photo" src="${store.photo_url}" alt="${store.name}" loading="lazy" onerror="this.parentElement.innerHTML='<div class=\\'card-photo-placeholder\\'><span>🍽</span><span>${store.genre||'レストラン'}</span></div>'">`
    : `<div class="card-photo-placeholder"><span>🍽</span><span>${store.genre||'レストラン'}</span></div>`;

  const tagsHtml = [
    store.area       ? `<span class="card-tag tag-area">${store.area}</span>` : '',
    store.genre      ? `<span class="card-tag tag-genre">${store.genre}</span>` : '',
    store.budget     ? `<span class="card-tag tag-budget">${store.budget}</span>` : '',
    store.atmosphere ? `<span class="card-tag tag-atmos">${store.atmosphere}</span>` : '',
  ].join('');

  const card = document.createElement('div');
  card.className = 'store-card';
  card.dataset.id = store.id;
  card.innerHTML = `
    <div class="card-photo-wrap">
      ${photoHtml}
      <button class="card-fav-btn ${favored ? 'active' : ''}" data-id="${store.id}" aria-label="${favored ? 'お気に入り解除' : 'お気に入りに追加'}">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="${favored ? '#e53e3e' : 'none'}" stroke="${favored ? '#e53e3e' : '#555'}" stroke-width="2" stroke-linecap="round">
          <path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>
        </svg>
      </button>
      ${distHtml}
    </div>
    <div class="card-body">
      <div class="card-tags">${tagsHtml}</div>
      <h3 class="card-name">${store.name}</h3>
      ${store.description ? `<p class="card-desc">${store.description}</p>` : ''}
      <div class="card-actions">
        ${store.map_url ? `
        <button class="card-action-btn btn-card-map" data-map="${store.map_url}">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/></svg>
          Googleマップ
        </button>` : ''}
        <button class="card-action-btn btn-card-detail" data-id="${store.id}">
          詳細を見る
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
        </button>
      </div>
    </div>`;
  return card;
}

/* ─────────────────────────────────────────
   RENDER RESULTS
───────────────────────────────────────── */
function renderResults() {
  const grid    = document.getElementById('store-grid');
  const section = document.getElementById('results-section');
  const noRes   = document.getElementById('no-results');
  const count   = document.getElementById('results-count');

  section.classList.remove('hidden');
  grid.innerHTML = '';

  if (STATE.filteredStores.length === 0) {
    noRes.classList.remove('hidden');
    count.innerHTML = '0件のお店';
    return;
  }
  noRes.classList.add('hidden');
  count.innerHTML = `<strong>${STATE.filteredStores.length}</strong>件のお店が見つかりました`;

  const frag = document.createDocumentFragment();
  STATE.filteredStores.forEach(s => frag.appendChild(renderStoreCard(s)));
  grid.appendChild(frag);
}

/* ─────────────────────────────────────────
   STORE DETAIL MODAL
───────────────────────────────────────── */
function openStoreModal(storeId) {
  const store = STATE.stores.find(s => s.id === storeId);
  if (!store) return;

  addHistory(store);

  const favored = isFav(store.id);
  const tagsHtml = [
    store.area       ? `<span class="card-tag tag-area">${store.area}</span>` : '',
    store.genre      ? `<span class="card-tag tag-genre">${store.genre}</span>` : '',
    store.budget     ? `<span class="card-tag tag-budget">${store.budget}</span>` : '',
    store.atmosphere ? `<span class="card-tag tag-atmos">${store.atmosphere}</span>` : '',
  ].join('');

  const photoHtml = store.photo_url
    ? `<img class="modal-hero-photo" src="${store.photo_url}" alt="${store.name}" loading="lazy">`
    : `<div class="modal-hero-placeholder">🍽</div>`;

  const snsHtml = [
    store.instagram_url ? `
    <a href="${store.instagram_url}" target="_blank" rel="noopener" class="modal-sns-btn btn-instagram">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="5"/><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/></svg>
      Instagramを見る
    </a>` : '',
    store.tiktok_url ? `
    <a href="${store.tiktok_url}" target="_blank" rel="noopener" class="modal-sns-btn btn-tiktok">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 01-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 01-2.88 2.5 2.89 2.89 0 01-2.89-2.89 2.89 2.89 0 012.89-2.89c.28 0 .54.04.79.1V9.01a6.3 6.3 0 00-.79-.05 6.34 6.34 0 00-6.34 6.34 6.34 6.34 0 006.34 6.34 6.34 6.34 0 006.33-6.34V9.37a8.16 8.16 0 004.77 1.52v-3.4a4.85 4.85 0 01-1-.8z"/></svg>
      TikTokを見る
    </a>` : '',
  ].join('');

  const body = document.getElementById('store-modal-body');
  body.innerHTML = `
    ${photoHtml}
    <div class="modal-content-pad">
      <div class="modal-tags">${tagsHtml}</div>
      <h2 class="modal-store-name">${store.name}</h2>
      ${store.address ? `<p style="font-size:0.8rem;color:var(--text-soft);margin-bottom:8px;">📍 ${store.address}</p>` : ''}
      ${store.description ? `<p class="modal-store-desc">${store.description}</p>` : ''}
      <div class="modal-actions">
        ${store.map_url ? `
        <a href="${store.map_url}" target="_blank" rel="noopener" class="modal-action-btn btn-modal-map">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/></svg>
          Googleマップで開く
        </a>` : ''}
        <button class="modal-action-btn btn-modal-fav ${favored ? 'active' : ''}" id="modal-fav-btn" data-id="${store.id}">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="${favored ? '#DC2626' : 'none'}" stroke="${favored ? '#DC2626' : 'currentColor'}" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
          ${favored ? 'お気に入り済み' : 'お気に入り'}
        </button>
      </div>
    </div>
    ${snsHtml ? `
    <div class="modal-divider"></div>
    <p class="modal-section-title">SNS・最新情報</p>
    <div class="modal-sns-wrap">${snsHtml}</div>` : ''}
  `;

  // Favorite button in modal
  document.getElementById('modal-fav-btn').addEventListener('click', (e) => {
    const id = e.currentTarget.dataset.id;
    toggleFavorite(id);
    const faved = isFav(id);
    const btn = document.getElementById('modal-fav-btn');
    btn.classList.toggle('active', faved);
    btn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="${faved ? '#DC2626' : 'none'}" stroke="${faved ? '#DC2626' : 'currentColor'}" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
      ${faved ? 'お気に入り済み' : 'お気に入り'}`;
    // Sync card if visible
    syncCardFavBtn(id, faved);
  });

  openModal('store-modal');
}

function syncCardFavBtn(id, faved) {
  const btn = document.querySelector(`.card-fav-btn[data-id="${id}"]`);
  if (!btn) return;
  btn.classList.toggle('active', faved);
  btn.innerHTML = `<svg width="17" height="17" viewBox="0 0 24 24" fill="${faved ? '#e53e3e' : 'none'}" stroke="${faved ? '#e53e3e' : '#555'}" stroke-width="2" stroke-linecap="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`;
}

/* ─────────────────────────────────────────
   MAP MODAL
───────────────────────────────────────── */
function openMapModal() {
  openModal('map-modal');
  setTimeout(() => initMap(), 100);
}

function initMap() {
  const container = document.getElementById('map-container');
  if (!container) return;

  const centerLat = STATE.searchLat || 35.6812;
  const centerLng = STATE.searchLng || 139.7671;

  if (STATE.mapInstance) {
    STATE.mapInstance.remove();
    STATE.mapInstance = null;
  }

  container.style.height = '100%';
  const map = L.map('map-container').setView([centerLat, centerLng], 14);
  STATE.mapInstance = map;

  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap contributors',
    maxZoom: 19,
  }).addTo(map);

  // Search location marker
  if (STATE.searchLat) {
    const myIcon = L.divIcon({
      html: '<div style="width:16px;height:16px;border-radius:50%;background:#00704A;border:3px solid white;box-shadow:0 2px 8px rgba(0,0,0,0.4)"></div>',
      className: '',
      iconSize: [16, 16],
      iconAnchor: [8, 8],
    });
    L.marker([STATE.searchLat, STATE.searchLng], { icon: myIcon })
      .addTo(map)
      .bindPopup(`<strong>${STATE.searchLabel}</strong>`);
  }

  // Store markers
  STATE.filteredStores.forEach(store => {
    if (!store.lat || !store.lng) return;
    const pinIcon = L.divIcon({
      html: `<div style="width:32px;height:32px;border-radius:50% 50% 50% 0;transform:rotate(-45deg);background:#CBA258;border:3px solid white;box-shadow:0 2px 8px rgba(0,0,0,0.35);cursor:pointer;"></div>`,
      className: '',
      iconSize: [32, 32],
      iconAnchor: [16, 32],
    });
    L.marker([store.lat, store.lng], { icon: pinIcon })
      .addTo(map)
      .bindPopup(`
        <div style="min-width:160px;font-family:sans-serif;">
          ${store.photo_url ? `<img src="${store.photo_url}" style="width:100%;height:80px;object-fit:cover;border-radius:6px;margin-bottom:8px;">` : ''}
          <strong style="font-size:13px;">${store.name}</strong><br>
          <span style="font-size:11px;color:#666;">${store.genre||''} ${store.budget ? '| '+store.budget : ''}</span><br>
          ${store.map_url ? `<a href="${store.map_url}" target="_blank" style="font-size:11px;color:#00704A;display:block;margin-top:6px;">Googleマップで開く →</a>` : ''}
        </div>
      `);
  });

  // Fit bounds if multiple markers
  const stores = STATE.filteredStores.filter(s => s.lat && s.lng);
  if (stores.length > 1) {
    const bounds = L.latLngBounds(stores.map(s => [s.lat, s.lng]));
    if (STATE.searchLat) bounds.extend([STATE.searchLat, STATE.searchLng]);
    map.fitBounds(bounds, { padding: [40, 40] });
  }
}

/* ─────────────────────────────────────────
   MODAL HELPERS
───────────────────────────────────────── */
function openModal(id) {
  const modal = document.getElementById(id);
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
}
function closeModal(id) {
  const modal = document.getElementById(id);
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
}
function closeAllModals() {
  document.querySelectorAll('.modal.open').forEach(m => {
    m.classList.remove('open');
    m.setAttribute('aria-hidden', 'true');
  });
  document.body.style.overflow = '';
}

/* ─────────────────────────────────────────
   FAVORITES
───────────────────────────────────────── */
function toggleFavorite(storeId) {
  const store = STATE.stores.find(s => s.id === storeId);
  if (!store) return;
  const idx = STATE.favorites.findIndex(f => f.id === storeId);
  if (idx >= 0) {
    STATE.favorites.splice(idx, 1);
  } else {
    STATE.favorites.unshift({ id: store.id, name: store.name, photo_url: store.photo_url||'',
      map_url: store.map_url||'', area: store.area||'', genre: store.genre||'', budget: store.budget||'' });
  }
  LS.saveFavorites(STATE.favorites);
  updateFavBadge();
  if (STATE.activePanel === 'favorites') renderFavorites();
}

function renderFavorites() {
  const list  = document.getElementById('favorites-list');
  const empty = document.getElementById('fav-empty');
  const total = document.getElementById('fav-total');
  total.textContent = `${STATE.favorites.length}件`;

  if (STATE.favorites.length === 0) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');
  list.innerHTML = '';
  const frag = document.createDocumentFragment();
  STATE.favorites.forEach(fav => {
    const card = document.createElement('div');
    card.className = 'list-card';
    card.innerHTML = `
      <img class="list-card-photo" src="${fav.photo_url||''}" alt="${fav.name}" onerror="this.src='';this.style.background='var(--g-pale)'">
      <div class="list-card-info">
        <div class="list-card-name">${fav.name}</div>
        <div class="list-card-meta">${[fav.area, fav.genre, fav.budget].filter(Boolean).join(' · ')}</div>
      </div>
      <button class="list-card-remove" data-id="${fav.id}" aria-label="お気に入りから削除" title="削除">✕</button>`;
    card.querySelector('.list-card-info').addEventListener('click', () => openStoreModal(fav.id));
    card.querySelector('.list-card-remove').addEventListener('click', (e) => {
      e.stopPropagation();
      toggleFavorite(fav.id);
      syncCardFavBtn(fav.id, false);
    });
    frag.appendChild(card);
  });
  list.appendChild(frag);
}

function updateFavBadge() {
  const n = STATE.favorites.length;
  const badge = document.getElementById('fav-nav-badge');
  badge.textContent = n;
  badge.classList.toggle('hidden', n === 0);
}

/* ─────────────────────────────────────────
   HISTORY
───────────────────────────────────────── */
function addHistory(store) {
  STATE.history = STATE.history.filter(h => h.id !== store.id);
  STATE.history.unshift({
    id: store.id, name: store.name, photo_url: store.photo_url||'',
    area: store.area||'', genre: store.genre||'',
    date: new Date().toLocaleDateString('ja-JP', { month:'numeric', day:'numeric', hour:'2-digit', minute:'2-digit' }),
  });
  if (STATE.history.length > 30) STATE.history = STATE.history.slice(0, 30);
  LS.saveHistory(STATE.history);
}

function renderHistory() {
  const list  = document.getElementById('history-list');
  const empty = document.getElementById('history-empty');
  if (STATE.history.length === 0) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');
  list.innerHTML = '';
  const frag = document.createDocumentFragment();
  STATE.history.forEach(h => {
    const card = document.createElement('div');
    card.className = 'list-card';
    card.innerHTML = `
      <img class="list-card-photo" src="${h.photo_url||''}" alt="${h.name}" onerror="this.src='';this.style.background='var(--g-pale)'">
      <div class="list-card-info">
        <div class="list-card-name">${h.name}</div>
        <div class="list-card-meta">${[h.area, h.genre].filter(Boolean).join(' · ')}</div>
        <div class="list-card-date">🕐 ${h.date}</div>
      </div>`;
    card.addEventListener('click', () => openStoreModal(h.id));
    frag.appendChild(card);
  });
  list.appendChild(frag);
}

/* ─────────────────────────────────────────
   GEOLOCATION
───────────────────────────────────────── */
function getCurrentLocation() {
  if (!navigator.geolocation) {
    alert('このブラウザは位置情報に対応していません。\n目的地で探す機能をお使いください。');
    return;
  }
  const btn = document.getElementById('btn-current');
  const origHtml = btn.innerHTML;
  btn.innerHTML = `<div class="loc-icon-wrap"><div class="spin" style="width:26px;height:26px;border:3px solid rgba(255,255,255,0.3);border-top-color:white;border-radius:50%;"></div></div><div class="loc-text"><strong>取得中...</strong><span>少々お待ちください</span></div>`;
  btn.disabled = true;

  navigator.geolocation.getCurrentPosition(
    (pos) => {
      STATE.searchLat   = pos.coords.latitude;
      STATE.searchLng   = pos.coords.longitude;
      STATE.searchLabel = '現在地';
      showLocationStatus('📍 現在地を取得しました');
      btn.innerHTML = origHtml;
      btn.disabled = false;
      document.getElementById('dest-input-area').classList.add('hidden');
    },
    (err) => {
      btn.innerHTML = origHtml;
      btn.disabled = false;
      const msgs = ['', '位置情報の利用が許可されていません。\nブラウザの設定からGPSを許可してください。', '位置情報の取得がタイムアウトしました。', '位置情報を取得できませんでした。'];
      alert(msgs[err.code] || '位置情報の取得に失敗しました。');
    },
    { enableHighAccuracy: true, timeout: 10000, maximumAge: 60000 }
  );
}

function showLocationStatus(label) {
  const status = document.getElementById('loc-status');
  document.getElementById('loc-label').textContent = label;
  status.classList.remove('hidden');
}

/* ─────────────────────────────────────────
   NOMINATIM GEOCODING
───────────────────────────────────────── */
async function geocodeDestination() {
  const query = document.getElementById('dest-text').value.trim();
  if (!query) { alert('場所名・駅名を入力してください。'); return; }

  const btn = document.getElementById('btn-geocode');
  const origHtml = btn.innerHTML;
  btn.innerHTML = '<div class="spin" style="width:18px;height:18px;border:2px solid rgba(30,57,50,0.3);border-top-color:#1E3932;border-radius:50%;"></div>';
  btn.disabled = true;

  try {
    const url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(query + ' 日本')}&format=json&limit=1&accept-language=ja`;
    const res  = await fetch(url, { headers: { 'Accept-Language': 'ja', 'User-Agent': 'KaishokuSelect/1.0' } });
    const data = await res.json();

    if (!data.length) {
      alert(`「${query}」の場所が見つかりませんでした。\n別のキーワードをお試しください。`);
      return;
    }
    STATE.searchLat   = parseFloat(data[0].lat);
    STATE.searchLng   = parseFloat(data[0].lon);
    STATE.searchLabel = data[0].display_name.split(',')[0];
    showLocationStatus(`📍 ${STATE.searchLabel}`);
  } catch (err) {
    alert('場所の検索中にエラーが発生しました。\nネットワーク接続をご確認ください。');
  } finally {
    btn.innerHTML = origHtml;
    btn.disabled = false;
  }
}

/* ─────────────────────────────────────────
   PANEL NAVIGATION
───────────────────────────────────────── */
function switchPanel(panelId) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(`panel-${panelId}`).classList.add('active');
  document.querySelector(`.nav-item[data-panel="${panelId}"]`).classList.add('active');
  STATE.activePanel = panelId;

  if (panelId === 'favorites') renderFavorites();
  if (panelId === 'history')   renderHistory();

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ─────────────────────────────────────────
   CONFIG / SHEET ID
───────────────────────────────────────── */
function openConfigModal() {
  document.getElementById('sheet-id-input').value = STATE.sheetId;
  openModal('config-modal');
}

async function saveConfig() {
  const id = document.getElementById('sheet-id-input').value.trim();
  if (!id) { alert('スプレッドシートIDを入力してください。'); return; }
  LS.saveSheetId(id);
  LS.saveUseDemo(false);
  STATE.sheetId = id;
  STATE.usingDemo = false;
  closeModal('config-modal');
  await reloadStores();
}

async function loadDemoData() {
  LS.saveUseDemo(true);
  STATE.usingDemo = true;
  STATE.stores = [...DEMO_STORES];
  STATE.filteredStores = [...DEMO_STORES];
  buildFilterOptions(STATE.stores);
  closeModal('config-modal');
  showToast('デモデータを読み込みました！「お店を探す」ボタンを押してください。');
}

async function reloadStores() {
  if (STATE.usingDemo || !STATE.sheetId) return;
  const loadingScreen = document.getElementById('loading-screen');
  loadingScreen.classList.remove('fade-out');
  try {
    const stores = await loadStoresFromSheet(STATE.sheetId);
    STATE.stores = stores;
    STATE.filteredStores = [...stores];
    buildFilterOptions(STATE.stores);
    showToast(`${stores.length}件の店舗データを読み込みました！`);
  } catch (err) {
    console.error(err);
    alert('データの読み込みに失敗しました。\n\nスプレッドシートIDが正しいか、シートが「全員に公開（閲覧）」に設定されているか確認してください。\n\nデモデータで試すことも可能です。');
    openConfigModal();
  } finally {
    loadingScreen.classList.add('fade-out');
  }
}

/* ─────────────────────────────────────────
   TOAST NOTIFICATION
───────────────────────────────────────── */
function showToast(msg, duration = 3000) {
  let toast = document.getElementById('app-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'app-toast';
    toast.style.cssText = `
      position:fixed; bottom:calc(var(--nav-h) + 16px); left:50%; transform:translateX(-50%);
      background:var(--g-dark); color:var(--g-light);
      padding:12px 20px; border-radius:var(--r-full); font-size:0.85rem; font-weight:500;
      box-shadow:0 4px 20px rgba(0,0,0,0.3); z-index:500; max-width:90vw; text-align:center;
      transition:opacity 0.3s ease; white-space:nowrap;`;
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.style.opacity = '1';
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { toast.style.opacity = '0'; }, duration);
}

/* ─────────────────────────────────────────
   SEARCH MAIN ACTION
───────────────────────────────────────── */
function doSearch() {
  if (STATE.stores.length === 0) {
    openConfigModal();
    return;
  }
  applyFilters();
  renderResults();
  const resultsEl = document.getElementById('results-section');
  setTimeout(() => resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
}

/* ─────────────────────────────────────────
   EVENT LISTENERS
───────────────────────────────────────── */
function attachEvents() {
  // Location buttons
  document.getElementById('btn-current').addEventListener('click', getCurrentLocation);
  document.getElementById('btn-destination').addEventListener('click', () => {
    document.getElementById('dest-input-area').classList.toggle('hidden');
    document.getElementById('dest-text').focus();
  });
  document.getElementById('btn-geocode').addEventListener('click', geocodeDestination);
  document.getElementById('dest-text').addEventListener('keydown', e => {
    if (e.key === 'Enter') geocodeDestination();
  });
  document.getElementById('btn-clear-loc').addEventListener('click', () => {
    STATE.searchLat = STATE.searchLng = null;
    STATE.searchLabel = '';
    document.getElementById('loc-status').classList.add('hidden');
    document.getElementById('dest-input-area').classList.add('hidden');
    document.getElementById('dest-text').value = '';
  });

  // Filter toggle
  document.getElementById('filter-toggle').addEventListener('click', () => {
    STATE.filterOpen = !STATE.filterOpen;
    document.getElementById('filter-body').classList.toggle('hidden', !STATE.filterOpen);
    document.getElementById('filter-chevron').classList.toggle('open', STATE.filterOpen);
  });
  document.getElementById('btn-clear-filter').addEventListener('click', () => {
    ['f-area','f-genre','f-budget','f-atmosphere'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('f-keyword').value = '';
    document.getElementById('filter-badge').classList.add('hidden');
  });

  // Search
  document.getElementById('btn-search').addEventListener('click', doSearch);

  // Map
  document.getElementById('btn-show-map').addEventListener('click', openMapModal);

  // Bottom nav
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => switchPanel(btn.dataset.panel));
  });

  // History clear
  document.getElementById('btn-clear-history').addEventListener('click', () => {
    if (!STATE.history.length) return;
    if (confirm('閲覧履歴をすべて削除しますか？')) {
      STATE.history = [];
      LS.saveHistory([]);
      renderHistory();
    }
  });

  // Config
  document.getElementById('config-btn').addEventListener('click', openConfigModal);
  document.getElementById('btn-save-config').addEventListener('click', saveConfig);
  document.getElementById('btn-demo').addEventListener('click', loadDemoData);

  // Store card clicks (event delegation)
  document.getElementById('store-grid').addEventListener('click', e => {
    const favBtn    = e.target.closest('.card-fav-btn');
    const detailBtn = e.target.closest('.btn-card-detail');
    const mapBtn    = e.target.closest('.btn-card-map');
    const card      = e.target.closest('.store-card');

    if (favBtn) {
      e.stopPropagation();
      const id = favBtn.dataset.id;
      toggleFavorite(id);
      const faved = isFav(id);
      favBtn.classList.toggle('active', faved);
      favBtn.innerHTML = `<svg width="17" height="17" viewBox="0 0 24 24" fill="${faved ? '#e53e3e' : 'none'}" stroke="${faved ? '#e53e3e' : '#555'}" stroke-width="2" stroke-linecap="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`;
      showToast(faved ? '♡ お気に入りに追加しました' : 'お気に入りから削除しました');
    } else if (detailBtn) {
      openStoreModal(detailBtn.dataset.id);
    } else if (mapBtn) {
      window.open(mapBtn.dataset.map, '_blank', 'noopener');
    } else if (card) {
      openStoreModal(card.dataset.id);
    }
  });

  // Modal closes
  document.getElementById('store-close').addEventListener('click', () => closeModal('store-modal'));
  document.getElementById('store-backdrop').addEventListener('click', () => closeModal('store-modal'));
  document.getElementById('map-close').addEventListener('click', () => closeModal('map-modal'));
  document.getElementById('map-backdrop').addEventListener('click', () => closeModal('map-modal'));
  document.getElementById('config-backdrop').addEventListener('click', () => closeModal('config-modal'));

  // ESC key
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeAllModals(); });
}

/* ─────────────────────────────────────────
   INIT
───────────────────────────────────────── */
async function init() {
  // Load persisted data
  STATE.favorites = LS.loadFavorites();
  STATE.history   = LS.loadHistory();
  STATE.sheetId   = LS.loadSheetId();
  STATE.usingDemo = LS.loadUseDemo();

  updateFavBadge();
  attachEvents();

  // Load store data
  const loadingScreen = document.getElementById('loading-screen');

  if (STATE.usingDemo) {
    STATE.stores = [...DEMO_STORES];
    buildFilterOptions(STATE.stores);
    loadingScreen.classList.add('fade-out');
  } else if (STATE.sheetId) {
    try {
      const stores = await loadStoresFromSheet(STATE.sheetId);
      STATE.stores = stores;
      buildFilterOptions(STATE.stores);
      loadingScreen.classList.add('fade-out');
    } catch {
      loadingScreen.classList.add('fade-out');
      setTimeout(openConfigModal, 400);
    }
  } else {
    // First launch — fade out and show config
    loadingScreen.classList.add('fade-out');
    setTimeout(openConfigModal, 600);
  }
}

document.addEventListener('DOMContentLoaded', () => { /* handled by AuthUI.init() above */ });

/* Called by AuthUI after successful auth */
