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
  selectedPref: '',  // 都道府県タイル選択
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
    initDiscovery();
    initPremium();

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
   TAG KEYWORD MAPPINGS
   タグ選択 → 検索キーワード変換テーブル
───────────────────────────────────────── */
const PREF_KEYWORDS = {
  // ── 会食の目的（シーン別） ──
  '広告主との会食':         ['接待','高級','個室','落ち着き','VIP','格式'],
  'パートナー企業との商談': ['個室','落ち着き','ビジネス','接待','会話'],
  '重要クライアント接待':   ['高級','接待','個室','VIP','一流','格式'],
  '大事な謝罪・関係修復':   ['個室','静か','落ち着き','高級','プライベート'],
  '初回商談':               ['カジュアル','落ち着き','明るい','清潔'],
  '採用候補との面談':       ['カジュアル','落ち着き','会話','明るい'],
  '採用候補との食事':       ['カジュアル','おしゃれ','活気','若者'],
  'インフルエンサー打ち合わせ': ['おしゃれ','インスタ','スタイリッシュ','写真'],
  '少人数役員会食':         ['高級','個室','静か','格式','プレミアム'],
};

const ATMOS_KEYWORDS = {
  // ── 場所・環境特性 ──
  '撮影しやすい':           ['おしゃれ','インスタ映え','スタイリッシュ','内装'],
  'SNS映え':                ['インスタ映え','フォトジェニック','おしゃれ','SNS'],
  '会話しやすい静かめ空間': ['静か','落ち着き','会話'],
  '役員会食向きの高級感':   ['高級','格式','接待','一流'],
  '夜景':                   ['夜景','ルーフトップ','眺望'],
  '隠れ家':                 ['隠れ家','穴場','こっそり'],
  '駅近で移動ロスが少ない': ['駅近','アクセス','便利'],
};

/* こだわり条件キーワード（rescueグループ） */
const RESCUE_KEYWORDS = {
  '個室重視':               ['個室','プライベート','完全個室'],
  'うるさすぎない':         ['静か','落ち着き'],
  '接待OK':                 ['接待','高級','VIP'],
  '投稿映え':               ['インスタ映え','おしゃれ','フォトジェニック'],
  '客単価1.2万以上でも許容': ['高級','プレミアム','贅沢'],
  '失敗しにくい定番':       ['人気','定番','老舗'],
  '採用面談向き':           ['カジュアル','落ち着き','明るい'],
  '4名会食で予算内':        ['コース','宴会'],
};

/* ─────────────────────────────────────────
   FILTER STATE
───────────────────────────────────────── */
const FILTER_STATE = {
  area:       '',
  distanceM:  99999,  // 距離フィルター（メートル）99999=無制限
  prefs:      new Set(),
  rescues:    new Set(),
  atmos:      new Set(),
  budget:     null,
  pax:        null,
  keyword:    '',
};

function parseBudget(str) {
  if (!str) return Infinity;
  const m = str.match(/[\d,]+/);
  if (!m) return Infinity;
  return parseInt(m[0].replace(/,/g,''), 10);
}

function storeMatchesTags(store, keywords) {
  if (!keywords.length) return true;
  const haystack = [store.name, store.genre, store.description, store.atmosphere, store.area]
    .filter(Boolean).join(' ').toLowerCase();
  return keywords.some(kw => haystack.includes(kw.toLowerCase()));
}

function applyFilters() {
  const kw = FILTER_STATE.keyword.toLowerCase();

  // Collect pref keywords (会食シーン)
  const prefKws = [];
  FILTER_STATE.prefs.forEach(tag => {
    (PREF_KEYWORDS[tag] || []).forEach(k => prefKws.push(k));
  });

  // Collect rescue/condition keywords (こだわり条件)
  const rescueKws = [];
  FILTER_STATE.rescues.forEach(tag => {
    (RESCUE_KEYWORDS[tag] || []).forEach(k => rescueKws.push(k));
  });

  // Rescue flags (photo required etc.) - now none by default
  const onlyWithPhoto = false;

  // Collect atmos keywords
  const atmosKws = [];
  FILTER_STATE.atmos.forEach(tag => {
    (ATMOS_KEYWORDS[tag] || []).forEach(k => atmosKws.push(k));
  });

  // Budget ceiling
  const budgetCeil = FILTER_STATE.budget;

  STATE.filteredStores = STATE.stores.filter(s => {
    // Area (only used when no location set)
    if (!STATE.searchLat && FILTER_STATE.area && s.area !== FILTER_STATE.area) return false;

    // Distance filter (only when location is set)
    if (STATE.searchLat && STATE.searchLng && s.lat && s.lng) {
      const distM = haversine(STATE.searchLat, STATE.searchLng, s.lat, s.lng) * 1000;
      if (FILTER_STATE.distanceM < 99999 && distM > FILTER_STATE.distanceM) return false;
    }

    // Pref tags (会食シーン - any keyword matches)
    if (prefKws.length && !storeMatchesTags(s, prefKws)) return false;

    // Rescue/condition keywords (こだわり条件 - any keyword matches)
    if (rescueKws.length && !storeMatchesTags(s, rescueKws)) return false;

    // Photo required (rescue)
    if (onlyWithPhoto && !s.photo_url) return false;

    // Atmos tags
    if (atmosKws.length && !storeMatchesTags(s, atmosKws)) return false;

    // Budget
    if (budgetCeil != null) {
      const storeMin = parseBudget(s.budget);
      if (storeMin > budgetCeil) return false;
    }

    // Keyword
    if (kw) {
      const hay = [s.name,s.description,s.area,s.genre,s.atmosphere,s.address]
        .filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(kw)) return false;
    }

    return true;
  });

  // Sort by distance if location set
  if (STATE.searchLat && STATE.searchLng) {
    STATE.filteredStores.forEach(s => {
      s._dist = (s.lat&&s.lng) ? haversine(STATE.searchLat,STATE.searchLng,s.lat,s.lng) : Infinity;
    });
    STATE.filteredStores.sort((a,b) => a._dist - b._dist);
  }

  // Update badge count
  let cnt = 0;
  if (!STATE.searchLat && FILTER_STATE.area) cnt++;
  if (STATE.searchLat && FILTER_STATE.distanceM < 99999) cnt++;
  if (FILTER_STATE.prefs.size)     cnt += FILTER_STATE.prefs.size;
  if (FILTER_STATE.rescues.size)   cnt += FILTER_STATE.rescues.size;
  if (FILTER_STATE.atmos.size)     cnt += FILTER_STATE.atmos.size;
  if (FILTER_STATE.budget != null) cnt++;
  if (FILTER_STATE.pax != null)    cnt++;
  if (FILTER_STATE.keyword)        cnt++;

  const b = document.getElementById('filter-badge');
  b.textContent = cnt;
  b.classList.toggle('hidden', cnt === 0);
}

/* ─────────────────────────────────────────
   TAG CHIP INTERACTION
───────────────────────────────────────── */
function initTagChips() {
  document.querySelectorAll('.tag-chip').forEach(chip => {
    chip.addEventListener('click', () => handleTagClick(chip));
  });

  // Distance filter chips
  document.querySelectorAll('.f-dist-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.f-dist-chip').forEach(c => c.classList.remove('selected'));
      chip.classList.add('selected');
      FILTER_STATE.distanceM = parseInt(chip.dataset.dist, 10);
    });
  });

  // Budget custom input
  document.getElementById('f-budget-custom').addEventListener('input', e => {
    const v = parseInt(e.target.value, 10);
    FILTER_STATE.budget = isNaN(v) ? null : v;
  });
}

function handleTagClick(chip) {
  const group = chip.dataset.group;
  const val   = chip.dataset.val;

  if (group === 'budget') {
    // Single select for budget
    document.querySelectorAll('[data-group="budget"]').forEach(c => c.classList.remove('selected'));
    const customWrap = document.getElementById('budget-custom-wrap');
    if (chip.classList.contains('selected')) {
      chip.classList.remove('selected');
      FILTER_STATE.budget = null;
      customWrap.classList.add('hidden');
    } else {
      chip.classList.add('selected');
      FILTER_STATE.budget = parseInt(val, 10);
      customWrap.classList.add('hidden');
    }

  } else if (group === 'pax') {
    // Single select for pax
    document.querySelectorAll('[data-group="pax"]').forEach(c => c.classList.remove('selected'));
    if (chip.classList.contains('selected')) {
      chip.classList.remove('selected');
      FILTER_STATE.pax = null;
    } else {
      chip.classList.add('selected');
      FILTER_STATE.pax = parseInt(val, 10);
    }

  } else if (group === 'rescue') {
    // ③ こだわり条件 → 複数選択OK（pref・atmosと同様の動作）
    chip.classList.toggle('selected');
    if (chip.classList.contains('selected')) FILTER_STATE.rescues.add(val);
    else FILTER_STATE.rescues.delete(val);

  } else if (group === 'pref') {
    // Multi select: toggle; clears rescue
    document.querySelectorAll('[data-group="rescue"]').forEach(c => c.classList.remove('selected'));
    FILTER_STATE.rescues.clear();
    chip.classList.toggle('selected');
    if (chip.classList.contains('selected')) FILTER_STATE.prefs.add(val);
    else FILTER_STATE.prefs.delete(val);

  } else if (group === 'atmos') {
    // Multi select
    chip.classList.toggle('selected');
    if (chip.classList.contains('selected')) FILTER_STATE.atmos.add(val);
    else FILTER_STATE.atmos.delete(val);
  }
}

function clearAllFilters() {
  FILTER_STATE.area      = '';
  FILTER_STATE.distanceM = 99999;
  FILTER_STATE.prefs     = new Set();
  FILTER_STATE.rescues   = new Set();
  FILTER_STATE.atmos     = new Set();
  FILTER_STATE.budget    = null;
  FILTER_STATE.pax       = null;
  FILTER_STATE.keyword   = '';

  document.querySelectorAll('.tag-chip.selected').forEach(c => c.classList.remove('selected'));
  // Reset distance chip to "絞らない"
  document.querySelectorAll('.f-dist-chip').forEach(c => c.classList.remove('selected'));
  const defaultDistChip = document.querySelector('.f-dist-chip[data-dist="99999"]');
  if (defaultDistChip) defaultDistChip.classList.add('selected');

  document.getElementById('f-area').value = '';
  document.getElementById('f-keyword').value = '';
  document.getElementById('f-budget-custom').value = '';
  document.getElementById('budget-custom-wrap').classList.add('hidden');
  document.getElementById('filter-badge').classList.add('hidden');
}

/* 場所設定有無でフィルターUIを切り替え */
function switchFilterLocationMode(hasLocation, locationName) {
  const distMode = document.getElementById('f-distance-mode');
  const areaMode = document.getElementById('f-area-mode');
  if (hasLocation) {
    distMode.classList.remove('hidden');
    areaMode.classList.add('hidden');
    const label = document.getElementById('f-loc-name-label');
    const short = locationName ? locationName.slice(0, 10) : '現在地';
    label.textContent = `📍 ${short}`;
  } else {
    distMode.classList.add('hidden');
    areaMode.classList.remove('hidden');
    // Reset distance filter
    FILTER_STATE.distanceM = 99999;
    document.querySelectorAll('.f-dist-chip').forEach(c => c.classList.remove('selected'));
    const d = document.querySelector('.f-dist-chip[data-dist="99999"]');
    if (d) d.classList.add('selected');
  }
}

function haversine(a, b, c, d) {
  const R=6371, dLat=(c-a)*Math.PI/180, dLng=(d-b)*Math.PI/180;
  const x=Math.sin(dLat/2)**2 + Math.cos(a*Math.PI/180)*Math.cos(c*Math.PI/180)*Math.sin(dLng/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(x), Math.sqrt(1-x));
}
function fmt(km) { return km < 1 ? `${Math.round(km*1000)}m` : `${km.toFixed(1)}km`; }

/* エリアのみスプレッドシートから動的取得 */
function buildFilterOptions(stores) {
  const sel  = document.getElementById('f-area');
  if (!sel) return;
  const vals = [...new Set(stores.map(s => s.area).filter(Boolean))].sort();
  while (sel.options.length > 1) sel.remove(1);
  vals.forEach(v => { const o = document.createElement('option'); o.value = o.textContent = v; sel.appendChild(o); });
}

/* ─────────────────────────────────────────
   SNS PLATFORM HELPERS
   アカウントあり → カラーボタン（リンク）
   アカウントなし → グレーアウト不活性
───────────────────────────────────────── */

/* OSMタグからInstagram/TikTok URLを正規化して抽出 */
function extractSnsUrls(tags) {
  const rawIg = tags['contact:instagram'] || tags['website:instagram'] || tags['social:instagram'] || '';
  const rawTk = tags['contact:tiktok']    || tags['website:tiktok']    || tags['social:tiktok']    || '';
  const rawWeb= tags.website              || tags['contact:website']   || '';

  const toUrl = (raw, base) => {
    if (!raw) return '';
    if (raw.startsWith('http')) return raw;
    return base + raw.replace(/^@/,'');
  };

  return {
    instagram: toUrl(rawIg, 'https://www.instagram.com/'),
    tiktok:    toUrl(rawTk, 'https://www.tiktok.com/@'),
    website:   rawWeb,
  };
}

/* SNSボタン生成（3状態: active / none / search-fallback） */
const SNS_ICONS = {
  instagram: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="5"/><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/></svg>`,
  tiktok:    `<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 01-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 01-2.88 2.5 2.89 2.89 0 01-2.89-2.89 2.89 2.89 0 012.89-2.89c.28 0 .54.04.79.1V9.01a6.3 6.3 0 00-.79-.05 6.34 6.34 0 00-6.34 6.34 6.34 6.34 0 006.34 6.34 6.34 6.34 0 006.33-6.34V9.37a8.16 8.16 0 004.77 1.52v-3.4a4.85 4.85 0 01-1-.8z"/></svg>`,
  website:   `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
};

/**
 * SNSアクションボタンを生成
 * @param {'instagram'|'tiktok'|'website'} platform
 * @param {string} url  - 確定URL（あれば）
 * @param {string} name - 店舗名（検索フォールバック用）
 * @param {'compact'|'full'} size
 */
function snsBtnHtml(platform, url, name, size = 'compact') {
  const icon  = SNS_ICONS[platform] || '';
  const label = { instagram:'Instagram', tiktok:'TikTok', website:'公式サイト' }[platform];
  const cls   = size === 'full' ? 'sns-btn sns-btn-full' : 'sns-btn';

  if (url) {
    // ✅ アカウント確認済み → カラー有効ボタン
    return `<a href="${url}" target="_blank" rel="noopener"
      class="${cls} sns-active sns-${platform}"
      title="${label}のアカウントを見る">
      ${icon}
      <span>${label}</span>
      <span class="sns-check">✓</span>
    </a>`;
  } else {
    // ❌ アカウントなし → グレー無効
    return `<span class="${cls} sns-inactive" title="${label}は未登録または不明" aria-disabled="true">
      <span class="sns-inactive-icon">${icon}</span>
      <span>${label}</span>
      <span class="sns-cross">×</span>
    </span>`;
  }
}

/** カード用ミニSNSステータスバー（コンパクト） */
function snsStatusBar(igUrl, tkUrl, webUrl) {
  return `<div class="sns-status-bar">
    ${snsBtnHtml('instagram', igUrl, '', 'compact')}
    ${snsBtnHtml('tiktok',    tkUrl, '', 'compact')}
    ${webUrl ? snsBtnHtml('website', webUrl, '', 'compact') : ''}
  </div>`;
}

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
      ${snsStatusBar(store.instagram_url||'', store.tiktok_url||'', '')}
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
  const featWrap= document.getElementById('featured-wrap');
  const discView= document.getElementById('discovery-view');

  section.classList.remove('hidden');
  discView.classList.add('hidden');
  grid.innerHTML = '';
  if (featWrap) featWrap.innerHTML = '';

  if (!STATE.filteredStores.length) {
    noRes.classList.remove('hidden');
    count.innerHTML = '0件のお店';
    const discBtn = document.getElementById('btn-no-res-open-disc');
    if (discBtn) discBtn.addEventListener('click', openDiscoverModal);
    return;
  }
  noRes.classList.add('hidden');
  count.innerHTML = `<strong>${STATE.filteredStores.length}</strong>件`;

  // 最初の1件はフィーチャードカード
  const [first, ...rest] = STATE.filteredStores;
  if (featWrap && first) featWrap.appendChild(buildFeaturedCard(first));

  // 残りは2列グリッド
  const frag = document.createDocumentFragment();
  rest.forEach(s => frag.appendChild(buildCard(s)));
  grid.appendChild(frag);

  // フィーチャードカードのクリック
  if (featWrap) {
    featWrap.addEventListener('click', e => {
      const fab  = e.target.closest('.fc-fav');
      const det  = e.target.closest('.fc-detail-btn');
      const card = e.target.closest('.featured-card');
      if (fab) {
        e.stopPropagation();
        const id = fab.dataset.id; toggleFavorite(id); const f = isFav(id);
        fab.classList.toggle('active', f);
        fab.querySelector('svg').setAttribute('fill', f ? '#e53e3e' : 'none');
        fab.querySelector('svg').setAttribute('stroke', f ? '#e53e3e' : 'rgba(0,0,0,.5)');
        showToast(f ? '♡ お気に入りに追加' : 'お気に入りから削除');
      } else if (det) { openStoreModal(det.dataset.id); }
      else if (card && !e.target.closest('a'))  { openStoreModal(card.dataset.id); }
    }, { once: false });
  }
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
  const sns = `
    <div class="modal-divider"></div>
    <p class="modal-section-title">SNS・公式情報</p>
    <div class="modal-sns-wrap modal-sns-grid">
      ${snsBtnHtml('instagram', store.instagram_url||'', store.name, 'full')}
      ${snsBtnHtml('tiktok',    store.tiktok_url||'',    store.name, 'full')}
    </div>`;

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
    ${sns}`;

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
  if (!navigator.geolocation) {
    showToast('このブラウザはGPS機能に対応していません。「目的地で探す」をご利用ください。');
    return;
  }

  const btn  = document.getElementById('btn-current');
  const save = btn.innerHTML;
  const SPINNER = `<div class="loc-icon-wrap"><div style="width:24px;height:24px;border:3px solid rgba(255,255,255,.3);border-top-color:white;border-radius:50%;animation:spin 0.8s linear infinite"></div></div><div class="loc-text"><strong id="loc-progress-msg">現在地を取得中...</strong><span>少々お待ちください</span></div>`;

  btn.innerHTML = SPINNER;
  btn.disabled  = true;

  function setMsg(msg) {
    const el = document.getElementById('loc-progress-msg');
    if (el) el.textContent = msg;
  }

  function onSuccess(pos) {
    STATE.searchLat   = pos.coords.latitude;
    STATE.searchLng   = pos.coords.longitude;
    STATE.searchLabel = '現在地';
    showLocStatus('📍 現在地を取得しました');
    switchFilterLocationMode(true, '現在地');
    btn.innerHTML = save;
    btn.disabled  = false;
  }

  function onFinalError(err) {
    btn.innerHTML = save;
    btn.disabled  = false;
    const msgs = {
      1: 'GPSの利用が許可されていません。\nブラウザのアドレスバー横の🔒アイコンから「位置情報」を「許可」に変更してください。',
      2: '現在地を取得できませんでした。\n「目的地で探す」で場所を指定してお試しください。',
      3: '現在地の取得がタイムアウトしました。\n「目的地で探す」で場所名を入力するか、Wi-Fiに接続してお試しください。',
    };
    const msg = msgs[err.code] || '現在地の取得に失敗しました。';
    // アラートの代わりにトーストで表示し、ユーザーフローを止めない
    showLocError(msg);
  }

  // ── Stage 1: 高精度GPS（10秒）──
  navigator.geolocation.getCurrentPosition(
    onSuccess,
    (err1) => {
      if (err1.code === 1) { onFinalError(err1); return; } // 権限拒否は即終了
      // タイムアウト or 取得不可 → Stage 2 へフォールバック
      setMsg('通常精度で再試行中...');
      // ── Stage 2: 低精度（ネットワーク位置・高速）──
      navigator.geolocation.getCurrentPosition(
        onSuccess,
        onFinalError,
        { enableHighAccuracy: false, timeout: 10000, maximumAge: 300000 }
      );
    },
    { enableHighAccuracy: true, timeout: 8000, maximumAge: 60000 }
  );
}

function showLocError(msg) {
  // アラートではなくヒーロー内に赤いバナーで表示
  let banner = document.getElementById('loc-error-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'loc-error-banner';
    banner.style.cssText = `
      background:rgba(220,38,38,0.15);border:1px solid rgba(220,38,38,0.4);
      border-radius:var(--r-md);padding:10px 14px;margin-top:12px;
      font-size:.82rem;color:#fecaca;line-height:1.6;position:relative;z-index:1;`;
    document.querySelector('.hero').appendChild(banner);
  }
  banner.innerHTML = `⚠ ${msg.replace(/\n/g,'<br>')} <button onclick="this.parentElement.remove()" style="float:right;background:none;border:none;color:#fecaca;font-size:1rem;cursor:pointer;margin-top:-2px">✕</button>`;
  // 10秒後に自動消去
  setTimeout(() => { if (banner.parentElement) banner.remove(); }, 10000);
}

async function geocodeDestination() {
  const q    = document.getElementById('dest-text').value.trim();
  const pref = document.getElementById('dest-pref').value.trim();
  if (!q) { alert('場所名を入力してください'); return; }

  // 都道府県が選択されていれば先頭に付加して同名地名の混同を防ぐ
  const searchQuery = pref ? `${pref} ${q}` : q;

  const btn = document.getElementById('btn-geocode'), save = btn.innerHTML;
  btn.innerHTML='<div style="width:18px;height:18px;border:2px solid rgba(30,57,50,.3);border-top-color:#1E3932;border-radius:50%;animation:spin 0.8s linear infinite"></div>';
  btn.disabled=true;
  try {
    const res  = await fetch(`https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(searchQuery+' 日本')}&format=json&limit=3&countrycodes=jp&accept-language=ja`,
      {headers:{'Accept-Language':'ja','User-Agent':'KaishokuSelect/1.0'}});
    const data = await res.json();
    if (!data.length) { alert(`「${searchQuery}」が見つかりませんでした\n都道府県を選択して再試行してください`); return; }
    // 都道府県が選択されていれば同県の結果を優先
    const best = pref
      ? (data.find(d => d.display_name.includes(pref.replace('県','').replace('府','').replace('都',''))) || data[0])
      : data[0];
    STATE.searchLat   = parseFloat(best.lat);
    STATE.searchLng   = parseFloat(best.lon);
    STATE.searchLabel = best.display_name.split(',')[0];
    showLocStatus(`📍 ${STATE.searchLabel}`);
    switchFilterLocationMode(true, STATE.searchLabel);
    document.getElementById('dest-input-area').classList.add('hidden');
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
  document.getElementById('config-error-msg').classList.add('hidden');
  document.getElementById('diagnose-result').classList.add('hidden');
  // Reset to first tab
  switchCfgTab('cfg-tab-id');
  openModal('config-modal');
}

function switchCfgTab(tabId) {
  document.querySelectorAll('.cfg-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
  document.querySelectorAll('.cfg-panel').forEach(p => p.classList.toggle('active', p.id === tabId));
}

async function saveConfig() {
  const id = document.getElementById('sheet-id-input').value.trim();
  const errEl = document.getElementById('config-error-msg');
  errEl.classList.add('hidden');

  if (!id) {
    errEl.textContent = 'スプレッドシートIDを入力してください';
    errEl.classList.remove('hidden');
    return;
  }

  // Validate ID format (should be ~40-60 alphanumeric chars)
  if (!/^[A-Za-z0-9_-]{20,}$/.test(id)) {
    errEl.innerHTML = 'IDの形式が正しくありません。<br>URLの <code style="background:var(--cream-dark);padding:1px 4px;border-radius:3px">/d/</code> と <code style="background:var(--cream-dark);padding:1px 4px;border-radius:3px">/edit</code> の間の文字列のみを入力してください。';
    errEl.classList.remove('hidden');
    return;
  }

  // Show loading
  document.getElementById('cfg-save-text').style.display = 'none';
  document.getElementById('cfg-save-spinner').classList.remove('hidden');
  document.getElementById('btn-save-config').disabled = true;

  try {
    const stores = await loadStoresFromSheet(id);

    // Success
    localStorage.setItem(LS.KEY_SHEET, id);
    localStorage.removeItem(LS.KEY_DEMO);
    STATE.sheetId   = id;
    STATE.usingDemo = false;
    STATE.stores    = stores;
    buildFilterOptions(STATE.stores);
    closeModal('config-modal');
    showToast(`✓ ${stores.length}件の店舗データを読み込みました`);

  } catch (e) {
    const msg = buildSheetErrorMessage(id, e);
    errEl.innerHTML = msg;
    errEl.classList.remove('hidden');
  } finally {
    document.getElementById('cfg-save-text').style.display = '';
    document.getElementById('cfg-save-spinner').classList.add('hidden');
    document.getElementById('btn-save-config').disabled = false;
  }
}

function buildSheetErrorMessage(id, err) {
  const errStr = String(err.message || err);

  if (errStr.includes('Failed to fetch') || errStr.includes('NetworkError')) {
    return `<strong>ネットワークエラー</strong><br>インターネット接続を確認してください。または、このアプリはGitHub Pages(https)での利用が必要です。`;
  }
  if (errStr.includes('parse error') || errStr.includes('setResponse')) {
    return `<strong>シートが非公開です</strong><br>スプレッドシートの共有設定を「リンクを知っている全員が閲覧可」に変更してください。<br><span style="color:var(--g-primary);cursor:pointer;text-decoration:underline" onclick="switchCfgTab('cfg-tab-howto')">→ 設定方法を見る</span>`;
  }
  if (errStr.includes('404') || errStr.includes('not found')) {
    return `<strong>IDが見つかりません</strong><br>スプレッドシートIDが正しいか確認してください（URLの /d/ と /edit の間の文字列）。`;
  }
  return `<strong>読み込みエラー</strong><br>IDとシートの公開設定を確認してください。<br><small style="color:var(--text-hint)">${errStr}</small><br><span style="color:var(--g-primary);cursor:pointer;text-decoration:underline" onclick="switchCfgTab('cfg-tab-debug')">→ 自動診断を実行する</span>`;
}

/* ── 自動診断 ── */
async function runDiagnose() {
  const id  = document.getElementById('sheet-id-input').value.trim();
  const res = document.getElementById('diagnose-result');
  res.classList.remove('hidden');
  res.innerHTML = '<div class="diag-item diag-warn"><span class="diag-icon">⏳</span><div class="diag-text">診断中...</div></div>';

  const items = [];

  // Check 1: ID format
  if (!id) {
    items.push({ type:'err', icon:'✗', title:'IDが未入力', desc:'「IDを入力」タブでスプレッドシートIDを入力してください。' });
  } else if (!/^[A-Za-z0-9_-]{20,}$/.test(id)) {
    items.push({ type:'err', icon:'✗', title:'IDの形式が不正', desc:'URLの /d/ と /edit の間の文字列のみを入力してください。スラッシュや余分な文字が含まれていませんか？' });
  } else {
    items.push({ type:'ok', icon:'✓', title:'IDの形式 — OK', desc:`入力されたID: ${id.slice(0,12)}...` });
  }

  // Check 2: HTTPS
  if (!window.isSecureContext) {
    items.push({ type:'warn', icon:'⚠', title:'HTTP環境（非推奨）', desc:'GitHub Pagesではhttpsで動作します。ローカルでのテスト時はこのエラーが出ますが、GitHub Pages上では解決します。' });
  } else {
    items.push({ type:'ok', icon:'✓', title:'HTTPS — OK', desc:'セキュアな接続で動作しています。' });
  }

  // Check 3: Fetch test
  if (id && /^[A-Za-z0-9_-]{20,}$/.test(id)) {
    try {
      const url = `https://docs.google.com/spreadsheets/d/${id}/gviz/tq?tqx=out:json`;
      const r   = await fetch(url);
      const txt = await r.text();

      if (!r.ok) {
        items.push({ type:'err', icon:'✗', title:`HTTP ${r.status} エラー`, desc: r.status === 404 ? 'スプレッドシートが見つかりません。IDが正しいか確認してください。' : `サーバーエラーが発生しました (${r.status})。` });
      } else if (txt.includes('google.visualization.Query.setResponse')) {
        const m = txt.match(/google\.visualization\.Query\.setResponse\(([\s\S]*)\)/);
        if (m) {
          try {
            const data = JSON.parse(m[1]);
            const rows = data.table?.rows?.length || 0;
            items.push({ type:'ok', icon:'✓', title:'シートへのアクセス — OK', desc:`${rows}行のデータを確認しました（ヘッダー行を除く）。` });
            if (rows === 0) {
              items.push({ type:'warn', icon:'⚠', title:'データが0件', desc:'シートにデータ行がありません。1行目がヘッダー（id, name, area...）、2行目以降にデータを入力してください。' });
            }
            const cols = data.table?.cols?.map(c => c.label) || [];
            const required = ['name','area','genre'];
            const missing  = required.filter(c => !cols.map(x=>x.toLowerCase()).includes(c));
            if (missing.length) {
              items.push({ type:'warn', icon:'⚠', title:'必須列が見つからない', desc:`列名 「${missing.join('、')}」 が見つかりません。1行目のヘッダーを確認してください。` });
            } else {
              items.push({ type:'ok', icon:'✓', title:'列構造 — OK', desc:'必須列 (name, area, genre) が確認できました。' });
            }
          } catch {
            items.push({ type:'err', icon:'✗', title:'データの解析に失敗', desc:'シートの形式が正しくありません。1行目がヘッダー行になっているか確認してください。' });
          }
        }
      } else if (txt.includes('Signin') || txt.includes('ServiceLogin')) {
        items.push({ type:'err', icon:'✗', title:'シートが非公開', desc:'共有設定が「限定公開」になっています。「リンクを知っている全員が閲覧可」に変更してください。' });
      } else {
        items.push({ type:'err', icon:'✗', title:'予期しないレスポンス', desc:'シートの公開設定またはIDを確認してください。' });
      }
    } catch (e) {
      items.push({ type:'err', icon:'✗', title:'接続失敗', desc:`ネットワークエラー: ${e.message}。インターネット接続を確認してください。` });
    }
  }

  res.innerHTML = items.map(item => `
    <div class="diag-item diag-${item.type}">
      <span class="diag-icon">${item.icon}</span>
      <div class="diag-text"><strong>${item.title}</strong>${item.desc}</div>
    </div>`).join('');
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
  document.getElementById('discovery-view')?.classList.add('hidden');
  applyFilters(); renderResults();
  setTimeout(()=>document.getElementById('results-section')?.scrollIntoView({behavior:'smooth',block:'start'}),100);
}

/* ─────────────────────────────────────────
   EVENT LISTENERS
───────────────────────────────────────── */
function attachEvents() {
  document.getElementById('btn-current').addEventListener('click', getCurrentLocation);
  // location bar buttons
  document.getElementById('btn-destination').addEventListener('click', ()=>{
    document.getElementById('dest-input-area').classList.toggle('hidden');
    setTimeout(()=>document.getElementById('dest-text').focus(), 200);
  });
  document.getElementById('btn-dest-close')?.addEventListener('click', ()=>{
    document.getElementById('dest-input-area').classList.add('hidden');
  });
  // 都道府県タイルクリック
  document.querySelectorAll('.drl-pref').forEach(btn => {
    btn.addEventListener('click', () => {
      // 選択状態トグル
      const isSelected = btn.classList.contains('selected');
      document.querySelectorAll('.drl-pref').forEach(b => b.classList.remove('selected'));
      if (isSelected) {
        STATE.selectedPref = '';
        document.getElementById('dest-pref-status').classList.add('hidden');
      } else {
        btn.classList.add('selected');
        STATE.selectedPref = btn.dataset.pref;
        const label = document.getElementById('dest-pref-label');
        if (label) label.textContent = btn.dataset.pref;
        document.getElementById('dest-pref-status').classList.remove('hidden');
      }
    });
  });
  // 都道府県クリア
  document.getElementById('btn-clear-pref')?.addEventListener('click', () => {
    STATE.selectedPref = '';
    document.querySelectorAll('.drl-pref').forEach(b => b.classList.remove('selected'));
    document.getElementById('dest-pref-status').classList.add('hidden');
  });
  // 背景クリックでモーダルを閉じる
  document.getElementById('dest-input-area').addEventListener('click', e => {
    if (e.target === document.getElementById('dest-input-area')) {
      document.getElementById('dest-input-area').classList.add('hidden');
    }
  });
  // Enterキー検索
  document.getElementById('dest-text').addEventListener('keydown', e => {
    if (e.key === 'Enter') geocodeDestination();
  });
  // filter bottom sheet
  document.getElementById('btn-filter-open').addEventListener('click', () => openModal('filter-modal'));
  document.getElementById('filter-close').addEventListener('click', () => closeModal('filter-modal'));
  document.getElementById('filter-backdrop').addEventListener('click', () => closeModal('filter-modal'));
  document.getElementById('filter-apply-btn').addEventListener('click', () => { closeModal('filter-modal'); doSearch(); });
  // scene bar
  document.querySelectorAll('.scene-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.scene-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      const scene = pill.dataset.scene;
      FILTER_STATE.prefs.clear();
      document.querySelectorAll('[data-group="pref"]').forEach(c => c.classList.remove('selected'));
      if (scene !== 'all') {
        FILTER_STATE.prefs.add(scene);
        const chip = document.querySelector(`[data-group="pref"][data-val="${scene}"]`);
        if (chip) chip.classList.add('selected');
      }
      // auto-search if location set
      if (STATE.stores.length) doSearch();
    });
  });
  // discovery view action cards
  document.getElementById('btn-search').addEventListener('click', doSearch);
  document.getElementById('btn-no-res-open-disc')?.addEventListener('click', openDiscoverModal);
  document.getElementById('btn-geocode').addEventListener('click', geocodeDestination);
  document.getElementById('dest-text').addEventListener('keydown', e=>{if(e.key==='Enter')geocodeDestination();});
  document.getElementById('btn-clear-loc').addEventListener('click', ()=>{
    STATE.searchLat=STATE.searchLng=null; STATE.searchLabel='';
    document.getElementById('loc-status').classList.add('hidden');
    document.getElementById('dest-input-area').classList.add('hidden');
    document.getElementById('dest-text').value='';
    switchFilterLocationMode(false, '');
  });
  // filter is now a bottom sheet - toggle handled by btn-filter-open
  document.getElementById('btn-clear-filter').addEventListener('click', clearAllFilters);
  document.getElementById('f-area').addEventListener('change', e => { FILTER_STATE.area = e.target.value; });
  document.getElementById('f-keyword').addEventListener('input', e => { FILTER_STATE.keyword = e.target.value.trim(); });
  initTagChips();
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
  // Config tabs
  document.querySelectorAll('.cfg-tab').forEach(btn =>
    btn.addEventListener('click', () => switchCfgTab(btn.dataset.tab))
  );
  // Diagnose
  document.getElementById('btn-diagnose').addEventListener('click', runDiagnose);

  document.getElementById('store-grid').addEventListener('click', e=>{
    const fab  = e.target.closest('.mc-fav');
    const card = e.target.closest('.m-card');
    if (fab) {
      e.stopPropagation(); toggleFavorite(fab.dataset.id); const f=isFav(fab.dataset.id);
      fab.classList.toggle('active',f);
      const svg = fab.querySelector('svg');
      if(svg){ svg.setAttribute('fill',f?'#e53e3e':'none'); svg.setAttribute('stroke',f?'#e53e3e':'rgba(0,0,0,.5)'); }
      showToast(f?'♡ お気に入りに追加':'お気に入りから削除');
    } else if (card) { openStoreModal(card.dataset.id); }
  });

  document.getElementById('store-close').addEventListener('click', ()=>closeModal('store-modal'));
  document.getElementById('store-backdrop').addEventListener('click', ()=>closeModal('store-modal'));
  document.getElementById('map-close').addEventListener('click', ()=>closeModal('map-modal'));
  document.getElementById('map-backdrop').addEventListener('click', ()=>closeModal('map-modal'));
  document.getElementById('config-backdrop').addEventListener('click', ()=>closeModal('config-modal'));
  document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeAllModals(); });
}

/* ─────────────────────────────────────────
   DISCOVERY: OVERPASS API + SNS SEARCH
───────────────────────────────────────── */

/* ── Overpass API cuisine type mapping ── */
const OVERPASS_TYPES = {
  all:        `["amenity"~"restaurant|bar|pub|cafe|food_court|fast_food|izakaya"]`,
  restaurant: `["amenity"="restaurant"]`,
  bar:        `["amenity"~"bar|pub"]`,
  cafe:       `["amenity"="cafe"]`,
  sushi:      `["cuisine"~"sushi|japanese"]`,
  ramen:      `["cuisine"~"ramen|noodle"]`,
  yakiniku:   `["cuisine"~"bbq|yakiniku|korean"]`,
};

let discoverRadius = 500;
let discoverType   = 'all';

async function runOverpassSearch() {
  const lat = STATE.searchLat;
  const lng = STATE.searchLng;
  if (!lat || !lng) {
    alert('先に「現在地から探す」または「目的地で探す」で場所を設定してください。');
    return;
  }

  const btn     = document.getElementById('btn-run-overpass');
  const spinner = document.getElementById('overpass-spinner');
  const btnText = document.getElementById('overpass-btn-text');
  btn.disabled  = true;
  btnText.style.display = 'none';
  spinner.classList.remove('hidden');

  const typeFilter = OVERPASS_TYPES[discoverType] || OVERPASS_TYPES.all;
  const query = `[out:json][timeout:20];(node${typeFilter}(around:${discoverRadius},${lat},${lng});way${typeFilter}(around:${discoverRadius},${lat},${lng}););out center 60;`;

  try {
    const res  = await fetch('https://overpass-api.de/api/interpreter', {
      method: 'POST',
      body:   'data=' + encodeURIComponent(query),
    });
    const data = await res.json();
    renderOverpassResults(data.elements || [], lat, lng);
  } catch (e) {
    document.getElementById('overpass-results').innerHTML =
      `<div class="disc-error">⚠ 取得に失敗しました。ネットワークを確認して再試行してください。<br><small>${e.message}</small></div>`;
  } finally {
    btn.disabled = false;
    btnText.style.display = '';
    spinner.classList.add('hidden');
  }
}

function renderOverpassResults(elements, searchLat, searchLng) {
  const container = document.getElementById('overpass-results');
  if (!elements.length) {
    container.innerHTML = '<div class="disc-empty">周辺に該当するお店が見つかりませんでした。<br>検索範囲を広げてお試しください。</div>';
    return;
  }

  // ハード距離上限 = 指定半径 × 1.5 km
  const maxDistKm = (discoverRadius / 1000) * 1.5;

  const stores = elements
    .filter(e => e.tags && e.tags.name)
    .map(e => {
      // 座標の確実な取得・バリデーション
      const eLat = parseFloat(e.lat ?? e.center?.lat ?? NaN);
      const eLng = parseFloat(e.lon ?? e.center?.lon ?? NaN);
      if (!isFinite(eLat) || !isFinite(eLng)) return null; // 座標不明は除外

      const dist = haversine(searchLat, searchLng, eLat, eLng);
      if (dist > maxDistKm) return null; // 半径外は絶対除外

      return {
        name:    e.tags.name,
        cuisine: e.tags.cuisine || e.tags.amenity || '',
        address: [e.tags['addr:city'], e.tags['addr:suburb'], e.tags['addr:street']].filter(Boolean).join(' '),
        tags:    e.tags,
        lat: eLat, lng: eLng, dist,
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.dist - b.dist);

  if (!stores.length) {
    container.innerHTML = '<div class="disc-empty">周辺に該当するお店が見つかりませんでした。<br>検索範囲を広げてお試しください。</div>';
    return;
  }

  container.innerHTML = `<p class="disc-result-count">${stores.length}件のお店が見つかりました（${discoverRadius >= 1000 ? discoverRadius/1000+'km' : discoverRadius+'m'}以内）</p>`;

  const frag = document.createDocumentFragment();
  stores.forEach(s => {
    const mapQ   = encodeURIComponent(`${s.name} ${s.address}`);
    const gQ     = encodeURIComponent(`"${s.name}" インスタ映え OR TikTok グルメ 口コミ`);
    const snsUrls = extractSnsUrls(s.tags || {});

    const card = document.createElement('div');
    card.className = 'overpass-card';
    card.innerHTML = `
      <div class="opc-top">
        <div class="opc-info">
          <p class="opc-name">${s.name}</p>
          <p class="opc-meta">${[cuisineLabel(s.cuisine), s.address].filter(Boolean).join(' · ')}</p>
        </div>
        <span class="opc-dist">${fmt(s.dist)}</span>
      </div>
      <div class="opc-sns-row">
        ${snsBtnHtml('instagram', snsUrls.instagram, s.name, 'compact')}
        ${snsBtnHtml('tiktok',    snsUrls.tiktok,    s.name, 'compact')}
        ${snsUrls.website ? snsBtnHtml('website', snsUrls.website, s.name, 'compact') : ''}
      </div>
      <div class="opc-actions">
        <a href="https://maps.google.com/maps?q=${mapQ}&near=${s.lat},${s.lng}" target="_blank" rel="noopener" class="opc-btn btn-opc-map">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/></svg>
          Googleマップ
        </a>
        <a href="https://www.google.com/search?q=${gQ}" target="_blank" rel="noopener" class="opc-btn btn-opc-g">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          SNS口コミ検索
        </a>
      </div>`;
    frag.appendChild(card);
  });
  container.appendChild(frag);
}

function cuisineLabel(raw) {
  if (!raw) return '';
  const map = {
    restaurant:'レストラン', bar:'バー', pub:'バー', cafe:'カフェ',
    sushi:'寿司', japanese:'和食', ramen:'ラーメン', bbq:'焼肉',
    yakiniku:'焼肉', korean:'韓国料理', chinese:'中華', french:'フレンチ',
    italian:'イタリアン', pizza:'ピザ', burger:'バーガー', izakaya:'居酒屋',
    seafood:'シーフード', steak:'ステーキ', fast_food:'ファストフード',
  };
  return map[raw.toLowerCase()] || raw;
}

/* ── SNS Smart Search URL Generator ── */
const SNS_PLATFORMS = [
  {
    id:    'google-insta',
    label: 'Google × Instagram',
    icon:  '🔍',
    color: '#4285F4',
    desc:  'Instagramで話題の店を発見',
    build: (area, prefs, scene) => {
      const q = buildSnsQuery(area, prefs, ['インスタ映え','インスタ話題','グルメ','絶品'], scene);
      return `https://www.google.com/search?q=${encodeURIComponent(q + ' site:instagram.com')}`;
    },
  },
  {
    id:    'tiktok-direct',
    label: 'TikTok グルメ検索',
    icon:  '🎵',
    color: '#000000',
    desc:  'TikTokで話題の飲食店',
    build: (area, prefs, scene) => {
      const q = buildSnsQuery(area, prefs, ['グルメ','飯テロ','おすすめ'], scene);
      return `https://www.tiktok.com/search?q=${encodeURIComponent(q)}`;
    },
  },
  {
    id:    'instagram-tag',
    label: 'Instagram ハッシュタグ',
    icon:  '📸',
    color: '#C13584',
    desc:  '最新の投稿でお店を発見',
    build: (area, prefs, scene) => {
      const tag = (area || 'グルメ').replace(/\s/g,'') + 'グルメ';
      return `https://www.instagram.com/explore/tags/${encodeURIComponent(tag)}/`;
    },
  },
  {
    id:    'google-hidden',
    label: '隠れ家・穴場を発掘',
    icon:  '🚪',
    color: '#1E3932',
    desc:  'SNSでしか知られていない名店',
    build: (area, prefs, scene) => {
      const q = buildSnsQuery(area, prefs, ['隠れ家','穴場','知る人ぞ知る','絶対行くべき'], scene);
      return `https://www.google.com/search?q=${encodeURIComponent(q)}`;
    },
  },
  {
    id:    'google-foodie',
    label: 'こだわり飯 × SNS評価',
    icon:  '⭐',
    color: '#E67E22',
    desc:  '食へのこだわりが強い名店',
    build: (area, prefs, scene) => {
      const q = buildSnsQuery(area, prefs, ['食べログ','こだわり','絶品','予約困難'], scene);
      return `https://www.google.com/search?q=${encodeURIComponent(q)}`;
    },
  },
  {
    id:    'youtube-foodie',
    label: 'YouTube グルメ動画',
    icon:  '▶️',
    color: '#FF0000',
    desc:  'グルメ系YouTuberが紹介した店',
    build: (area, prefs, scene) => {
      const q = buildSnsQuery(area, prefs, ['グルメ','おすすめレストラン','絶品'], scene);
      return `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}`;
    },
  },
  {
    id:    'tabelog',
    label: '食べログ エリア検索',
    icon:  '🍽',
    color: '#C0392B',
    desc:  '食べログ3.5以上の評価店',
    build: (area, prefs, scene) => {
      const encoded = encodeURIComponent((area || '東京') + ' ' + (prefs[0] || 'ディナー'));
      return `https://tabelog.com/tokyo/A1301/A130101/R5174/rstLst/?vs=1&sw=${encoded}&sk=&vac_net=&svd=20240101&svt=1900&svps=2&po=&hfc=1&hs=1`;
    },
  },
  {
    id:    'retty',
    label: 'Retty × 実名口コミ',
    icon:  '👥',
    color: '#E74C3C',
    desc:  'グルメ通の実名レビューから発見',
    build: (area, prefs, scene) => {
      const q = (area || '東京') + ' ' + (prefs[0] || 'ディナー');
      return `https://retty.me/search/?q=${encodeURIComponent(q)}`;
    },
  },
];

function buildSnsQuery(area, prefs, keywords, scene) {
  const parts = [];
  if (area)              parts.push(area);
  if (scene)             parts.push(...scene.split(' ').slice(0,2));
  else if (prefs.length) parts.push(prefs[0]);
  parts.push(...keywords.slice(0, 2));
  return parts.join(' ');
}

function getPrefLabels() {
  const labels = [];
  // 会食シーン → キーワード変換
  FILTER_STATE.prefs.forEach(tag => {
    const kws = PREF_KEYWORDS[tag] || [];
    if (kws[0]) labels.push(kws[0]);
  });
  // こだわり条件 → キーワード変換
  FILTER_STATE.rescues.forEach(tag => {
    const kws = (typeof RESCUE_KEYWORDS !== 'undefined' ? RESCUE_KEYWORDS[tag] : null) || [];
    if (kws[0]) labels.push(kws[0]);
  });
  return [...new Set(labels)];
}

/* 会食シーンタグを読みやすい日本語に変換（SNSクエリ用） */
function getSceneLabels() {
  const sceneMap = {
    '広告主との会食':         '接待 会食',
    'パートナー企業との商談': 'ビジネス 商談',
    '重要クライアント接待':   '接待 高級',
    '大事な謝罪・関係修復':   '個室 静か',
    '初回商談':               'カジュアル 商談',
    '採用候補との面談':       'カジュアル 面談',
    '採用候補との食事':       'カジュアル おしゃれ',
    'インフルエンサー打ち合わせ': 'おしゃれ インスタ映え',
    '少人数役員会食':         '個室 高級 役員',
  };
  const condMap = {
    '個室重視': '個室', 'うるさすぎない': '静か', '接待OK': '接待',
    '投稿映え': 'インスタ映え', '失敗しにくい定番': '人気', '採用面談向き': 'カジュアル',
  };
  const parts = [];
  FILTER_STATE.prefs.forEach(t => { if (sceneMap[t]) parts.push(sceneMap[t]); });
  FILTER_STATE.rescues.forEach(t => { if (condMap[t]) parts.push(condMap[t]); });
  return parts.join(' ');
}

function generateSnsCards() {
  // ② GPS情報・会食目的・こだわりを自動入力
  const areaEl = document.getElementById('disc-area-input');

  // 場所が未入力なら自動セット
  if (!areaEl.value.trim()) {
    if (STATE.searchLabel && STATE.searchLabel !== '現在地') {
      areaEl.value = STATE.searchLabel;
    }
  }

  const area     = areaEl.value.trim();
  const scene    = getSceneLabels();
  const prefs    = getPrefLabels();
  const locInfo  = STATE.searchLat
    ? `📍 ${STATE.searchLabel || '現在地'}から検索中`
    : '';

  const container = document.getElementById('sns-search-cards');
  container.innerHTML = '';

  // 自動セット状態の表示
  if (locInfo || scene) {
    const info = document.createElement('div');
    info.className = 'sns-auto-info';
    info.innerHTML = [
      locInfo ? `<span class="sai-loc">${locInfo}</span>` : '',
      scene   ? `<span class="sai-scene">🎯 ${[...FILTER_STATE.prefs, ...FILTER_STATE.rescues].slice(0,3).join(' · ')}</span>` : '',
    ].filter(Boolean).join('');
    container.appendChild(info);
  }

  const frag = document.createDocumentFragment();
  SNS_PLATFORMS.forEach(p => {
    const url  = p.build(area, prefs, scene);
    const card = document.createElement('a');
    card.href = url; card.target = '_blank'; card.rel = 'noopener';
    card.className = 'sns-card';
    card.innerHTML = `
      <div class="sns-card-icon" style="background:${p.color}">${p.icon}</div>
      <div class="sns-card-body">
        <p class="sns-card-label">${p.label}</p>
        <p class="sns-card-desc">${p.desc}</p>
        ${area  ? `<p class="sns-card-query">📍 ${area}</p>` : ''}
        ${scene ? `<p class="sns-card-query">🎯 ${scene.split(' ').slice(0,3).join(' · ')}</p>` : ''}
      </div>
      <svg class="sns-card-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>`;
    frag.appendChild(card);
  });
  container.appendChild(frag);
}

/* ── Discovery Modal Init ── */
function initDiscovery() {
  // Radius chips
  document.querySelectorAll('.disc-r-chip[data-r]').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.disc-r-chip[data-r]').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      discoverRadius = parseInt(chip.dataset.r, 10);
    });
  });

  // Type chips
  document.querySelectorAll('.disc-r-chip[data-type]').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.disc-r-chip[data-type]').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      discoverType = chip.dataset.type;
    });
  });

  // Tab switching
  document.querySelectorAll('.disc-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.disc-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.disc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(tab.dataset.dtab).classList.add('active');
    });
  });

  document.getElementById('btn-run-overpass').addEventListener('click', runOverpassSearch);
  document.getElementById('btn-gen-sns').addEventListener('click', generateSnsCards);
  document.getElementById('btn-discover').addEventListener('click', openDiscoverModal);
  document.getElementById('discover-close').addEventListener('click', () => closeModal('discover-modal'));
  document.getElementById('discover-backdrop').addEventListener('click', () => closeModal('discover-modal'));
}

function openDiscoverModal() {
  // Sync location label
  const locLabel = document.getElementById('disc-loc-label');
  if (STATE.searchLat && STATE.searchLng) {
    locLabel.textContent = `📍 ${STATE.searchLabel || '場所設定済み'} — 周辺を検索できます`;
    locLabel.style.color = 'var(--g-primary)';
  } else {
    locLabel.textContent = '先に「現在地から探す」または「目的地で探す」で場所を設定してください';
    locLabel.style.color = 'var(--text-soft)';
  }

  // Pre-fill area input
  if (STATE.searchLabel && STATE.searchLabel !== '現在地') {
    document.getElementById('disc-area-input').value = STATE.searchLabel;
  }

  // Auto-generate SNS cards
  generateSnsCards();
  openModal('discover-modal');
}

/* ─────────────────────────────────────────
   PREMIUM SEARCH — Overpass API + OSM
   完全無料・APIキー不要
   OSM発見スコア = データ充実度の複合指標
   （著名店ほどOSMデータが豊富）
───────────────────────────────────────── */

/* OSMのcuisineタグ → 日本語ラベル変換 */
const CUISINE_JA = {
  sushi:'寿司', japanese:'和食', french:'フレンチ', italian:'イタリアン',
  chinese:'中華', steak_house:'ステーキ', yakiniku:'焼肉', bbq:'焼肉',
  seafood:'シーフード', ramen:'ラーメン', izakaya:'居酒屋', bar:'バー',
  pub:'バー', cafe:'カフェ', pizza:'ピザ', burger:'バーガー',
  korean:'韓国料理', thai:'タイ料理', vietnamese:'ベトナム料理',
  indian:'インド料理', turkish:'トルコ料理', mexican:'メキシコ料理',
  noodle:'麺類', tempura:'天ぷら', teppanyaki:'鉄板焼き',
  kaiseki:'懐石', curry:'カレー', udon:'うどん', soba:'蕎麦',
};

/* OSM amenityタグ → 業態ラベル */
const AMENITY_JA = {
  restaurant:'レストラン', bar:'バー', pub:'パブ',
  cafe:'カフェ', fast_food:'ファストフード', food_court:'フードコート',
};

/* OSM発見スコア（高いほど実力・著名店）*/
function osmScore(tags) {
  let s = 0;
  // 最強シグナル：Wikipedia/Wikidata = 社会的に著名な店
  if (tags.wikidata)              s += 6;
  if (tags.wikipedia)             s += 5;
  // 強シグナル：公式情報が整備されている
  if (tags.website || tags['contact:website']) s += 3;
  if (tags['contact:instagram'] || tags['website:instagram']) s += 2;
  // 運営情報シグナル
  if (tags.opening_hours)         s += 2;
  if (tags.phone || tags['contact:phone']) s += 1;
  // 予約関連（高需要・人気店シグナル）
  if (tags.reservation === 'required')    s += 3;
  if (tags.reservation === 'recommended') s += 2;
  if (tags.reservation === 'yes')         s += 1;
  // 住所情報
  if (tags['addr:street'] || tags['addr:full']) s += 1;
  // プレミアムジャンル加点
  const premCuisines = ['sushi','japanese','french','italian','steak_house',
                        'fine_dining','seafood','yakiniku','kaiseki','teppanyaki'];
  const cuisine = (tags.cuisine || '').toLowerCase();
  if (premCuisines.some(c => cuisine.includes(c))) s += 2;
  // 快適性タグ
  if (tags.outdoor_seating === 'yes') s += 0.5;
  if (tags.air_conditioning === 'yes') s += 0.5;
  // OSMスターレーティング（稀だが存在する）
  if (tags.stars) s += Math.min(parseInt(tags.stars) || 0, 3);
  // 名前の多言語化（国際的知名度）
  if (tags['name:en'] || tags['name:ja_rm']) s += 0.5;

  return Math.round(s * 10) / 10;
}

/* 営業時間テキストを日本語で簡易表示 */
function formatOpeningHours(oh) {
  if (!oh) return '';
  if (oh.length > 60) return oh.substring(0, 60) + '...';
  return oh
    .replace(/Mo/g,'月').replace(/Tu/g,'火').replace(/We/g,'水')
    .replace(/Th/g,'木').replace(/Fr/g,'金').replace(/Sa/g,'土').replace(/Su/g,'日')
    .replace(/off/g,'休').replace(/,/g,' ');
}

/* Overpass最適クエリ生成 */
function buildPremiumOverpassQuery(lat, lng, radius, cuisines, attrs) {
  // cuisine条件のOR構築
  const cuisineArr = [...cuisines];
  const cuisineRegex = cuisineArr.length > 0
    ? cuisineArr.map(c => c.split(';')).flat().join('|')
    : null;

  const cuisineFilter = cuisineRegex
    ? `["cuisine"~"${cuisineRegex}",i]`
    : '';

  // attr条件（websiteなど）でスコアを上げるため、条件なし全取得 → クライアント側でフィルタ
  return `[out:json][timeout:25];
(
  node["amenity"~"restaurant|bar|pub|izakaya|cafe"]${cuisineFilter}(around:${radius},${lat},${lng});
  way["amenity"~"restaurant|bar|pub|izakaya|cafe"]${cuisineFilter}(around:${radius},${lat},${lng});
);
out center tags;`;
}

const OverpassPremium = {
  radius:   1500,
  cuisines: new Set(),
  attrs:    new Set(),   // website, opening_hours, reservation, outdoor_seating, wikidata

  async search(lat, lng) {
    const query = buildPremiumOverpassQuery(lat, lng, this.radius, this.cuisines, this.attrs);
    const res = await fetch('https://overpass-api.de/api/interpreter', {
      method: 'POST',
      body:   'data=' + encodeURIComponent(query),
    });
    const data = await res.json();
    return (data.elements || []).filter(e => e.tags && e.tags.name);
  },

  filterAndScore(elements, searchLat, searchLng) {
    // ハード距離上限 = 指定半径 × 1.5 (km)
    const maxDistKm = (this.radius / 1000) * 1.5;

    return elements
      .map(e => {
        const t = e.tags;

        // ── 座標の確実な取得 ──
        const eLat = parseFloat(e.lat ?? e.center?.lat ?? NaN);
        const eLng = parseFloat(e.lon ?? e.center?.lon ?? NaN);

        // 座標不明・NaN のものは除外（これが遠方混入の原因）
        if (!isFinite(eLat) || !isFinite(eLng)) return null;

        const dist = haversine(searchLat, searchLng, eLat, eLng);

        // ハード距離カットオフ（半径外は絶対に除外）
        if (dist > maxDistKm) return null;

        // attr filter
        if (this.attrs.size > 0) {
          const attrMap = {
            website:         t.website || t['contact:website'],
            opening_hours:   t.opening_hours,
            reservation:     t.reservation,
            outdoor_seating: t.outdoor_seating === 'yes',
            wikidata:        t.wikidata,
          };
          if (![...this.attrs].some(a => attrMap[a])) return null;
        }

        return { name:t.name, tags:t, lat:eLat, lng:eLng, dist, score: osmScore(t) };
      })
      .filter(Boolean)
      .sort((a, b) => {
        // スコア差が大きい時はスコア優先、接近時は距離優先
        if (Math.abs(b.score - a.score) > 1.0) return b.score - a.score;
        return a.dist - b.dist;
      });
  },
};

/* 結果カード描画 */
function renderPremiumResults(stores) {
  const container = document.getElementById('premium-results');
  if (!stores.length) {
    container.innerHTML = `
      <div class="prem-empty">
        <p>条件に合うお店が見つかりませんでした。</p>
        <p style="font-size:.8rem;margin-top:6px;color:var(--text-hint)">検索範囲を広げるか、ジャンル条件を減らしてみてください。</p>
      </div>`;
    return;
  }

  container.innerHTML = `<p class="prem-result-count">OSM発見スコア順 <strong>${stores.length}件</strong></p>`;
  const maxScore = stores[0].score || 1;

  const frag = document.createDocumentFragment();
  stores.forEach((s, idx) => {
    const t = s.tags;
    const cuisine    = t.cuisine ? cuisineLabel(t.cuisine) : (AMENITY_JA[t.amenity] || 'レストラン');
    const oh         = formatOpeningHours(t.opening_hours);
    const hasWiki    = !!(t.wikidata || t.wikipedia);
    const needsRes   = t.reservation === 'required' || t.reservation === 'recommended';
    const outdoor    = t.outdoor_seating === 'yes';
    const mapsQ      = encodeURIComponent(`${s.name} ${t['addr:full'] || t['addr:city'] || ''}`);
    const tabelogQ   = encodeURIComponent(s.name);
    const pct        = Math.min(100, Math.round(s.score / Math.max(maxScore, 6) * 100));

    // OSMからSNS URLを抽出・正規化
    const snsUrls = extractSnsUrls(t);

    // Badges
    const badges = [];
    if (hasWiki)      badges.push('<span class="prem-badge badge-wiki">📚 著名店</span>');
    if (needsRes)     badges.push('<span class="prem-badge badge-res">📞 要予約</span>');
    if (outdoor)      badges.push('<span class="prem-badge badge-out">🌿 テラス</span>');
    if (snsUrls.website) badges.push('<span class="prem-badge badge-web">🌐 公式サイト</span>');
    if (snsUrls.instagram) badges.push('<span class="prem-badge badge-ig">📸 Instagram公式</span>');

    const card = document.createElement('div');
    card.className = 'prem-card';
    card.innerHTML = `
      <div class="prem-card-head">
        <div class="prem-rank-num">#${idx + 1}</div>
        <div class="prem-card-info">
          <h3 class="prem-card-name">${s.name}</h3>
          <p class="prem-cuisine-tag">${cuisine}</p>
        </div>
        <span class="prem-dist-pill">${fmt(s.dist)}</span>
      </div>

      ${badges.length ? `<div class="prem-badges">${badges.join('')}</div>` : ''}

      <div class="prem-score-row">
        <span class="prem-score-label">OSM発見スコア</span>
        <div class="prem-score-track"><div class="prem-score-fill" style="width:${pct}%"></div></div>
        <span class="prem-score-val">${s.score.toFixed(1)}</span>
      </div>

      ${t['addr:full'] || t['addr:street'] ? `
        <p class="prem-addr">📍 ${t['addr:full'] || [t['addr:city'],t['addr:suburb'],t['addr:street']].filter(Boolean).join(' ')}</p>` : ''}
      ${oh ? `<p class="prem-oh">🕐 ${oh}</p>` : ''}

      <div class="prem-sns-row">
        ${snsBtnHtml('instagram', snsUrls.instagram, s.name, 'compact')}
        ${snsBtnHtml('tiktok',    snsUrls.tiktok,    s.name, 'compact')}
        ${snsUrls.website ? snsBtnHtml('website', snsUrls.website, s.name, 'compact') : ''}
      </div>

      <div class="prem-card-actions">
        <a href="https://maps.google.com/maps?q=${mapsQ}" target="_blank" rel="noopener" class="prem-action-btn prem-map-btn">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/></svg>
          ナビ開始
        </a>
        <a href="https://tabelog.com/rst/search/?vs=1&sw=${tabelogQ}" target="_blank" rel="noopener" class="prem-action-btn prem-tbl-btn">🍽 食べログ</a>
      </div>`;
    frag.appendChild(card);
  });
  container.appendChild(frag);
}

function cuisineLabel(raw) {
  if (!raw) return 'レストラン';
  const first = raw.split(';')[0].trim().toLowerCase();
  return CUISINE_JA[first] || AMENITY_JA[first] || raw.split(';')[0];
}

/* Premium Search Execute */
async function runPremiumSearch() {
  if (!STATE.searchLat) { alert('先に場所を設定してください（現在地 or 目的地）'); return; }

  const btn = document.getElementById('btn-run-premium');
  const sp  = document.getElementById('prem-spinner');
  const tx  = document.getElementById('prem-btn-text');
  const res = document.getElementById('premium-results');

  btn.disabled = true;
  tx.style.display = 'none';
  sp.classList.remove('hidden');
  res.innerHTML = `
    <div class="prem-loading">
      <div class="prem-loading-dots"><span></span><span></span><span></span></div>
      <p>Overpass APIで周辺を検索中...</p>
      <p style="font-size:.75rem;margin-top:4px;color:var(--text-hint)">※ OSMデータを取得しています（数秒かかる場合があります）</p>
    </div>`;

  try {
    const elements = await OverpassPremium.search(STATE.searchLat, STATE.searchLng);
    const scored   = OverpassPremium.filterAndScore(elements, STATE.searchLat, STATE.searchLng);
    renderPremiumResults(scored.slice(0, 30));
  } catch (e) {
    res.innerHTML = `<div class="prem-error">⚠ ${e.message}<br><small style="color:var(--text-hint)">しばらく待ってから再試行してください（Overpass API一時制限）</small></div>`;
  } finally {
    btn.disabled = false;
    tx.style.display = '';
    tx.textContent = '✦ 再検索';
    sp.classList.add('hidden');
  }
}

function initPremium() {
  // Radius chips
  document.querySelectorAll('.prem-chip[data-radius]').forEach(c =>
    c.addEventListener('click', () => {
      document.querySelectorAll('.prem-chip[data-radius]').forEach(x => x.classList.remove('active'));
      c.classList.add('active');
      OverpassPremium.radius = parseInt(c.dataset.radius, 10);
    })
  );

  // Cuisine chips (multi)
  document.querySelectorAll('.prem-chip.prem-osm').forEach(c =>
    c.addEventListener('click', () => {
      c.classList.toggle('active');
      if (c.classList.contains('active')) OverpassPremium.cuisines.add(c.dataset.cuisine);
      else OverpassPremium.cuisines.delete(c.dataset.cuisine);
    })
  );

  // Attr chips (multi)
  document.querySelectorAll('.prem-chip.prem-attr').forEach(c =>
    c.addEventListener('click', () => {
      c.classList.toggle('active');
      if (c.classList.contains('active')) OverpassPremium.attrs.add(c.dataset.attr);
      else OverpassPremium.attrs.delete(c.dataset.attr);
    })
  );

  document.getElementById('btn-run-premium').addEventListener('click', runPremiumSearch);
  document.getElementById('btn-premium-search').addEventListener('click', openPremiumModal);
  document.getElementById('premium-close').addEventListener('click', () => closeModal('premium-modal'));
  document.getElementById('premium-backdrop').addEventListener('click', () => closeModal('premium-modal'));
}

function openPremiumModal() {
  const locText = document.getElementById('prem-loc-text');
  if (STATE.searchLat) {
    locText.textContent = `📍 ${STATE.searchLabel || '場所設定済み'}周辺を検索`;
    locText.style.color = 'var(--g-primary)';
  } else {
    locText.textContent = '⚠ まず「現在地から探す」または「目的地で探す」で場所を設定してください';
    locText.style.color = '#DC2626';
  }
  document.getElementById('premium-results').innerHTML = '';
  openModal('premium-modal');
}

document.addEventListener('DOMContentLoaded', () => {
  AuthUI.init();
});
