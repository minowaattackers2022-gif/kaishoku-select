const stores = [
  {
    id: "s1",
    name: "銀座 鮨 真田",
    area: "銀座",
    genre: "寿司・鮨",
    budgetBand: "premium",
    atmosphere: "高級・静か",
    pax: "2〜4名",
    scenes: ["important-client", "executive"],
    strengths: ["quiet", "private", "safe"],
    description: "失礼の少ない王道の高級鮨。大事な相手との会話を邪魔しにくい空気感です。"
  },
  {
    id: "s2",
    name: "丸の内 個室和牛 一頭",
    area: "丸の内",
    genre: "和牛・会食",
    budgetBand: "premium",
    atmosphere: "個室・重厚",
    pax: "2〜6名",
    scenes: ["important-client", "executive"],
    strengths: ["private", "safe", "access"],
    description: "個室感と安定感が強い一軒。『外したくない』会食と相性が良いです。"
  },
  {
    id: "s3",
    name: "恵比寿 Bistro 葉月",
    area: "恵比寿",
    genre: "ビストロ",
    budgetBand: "high",
    atmosphere: "大人カジュアル",
    pax: "2〜4名",
    scenes: ["first-meeting", "creator"],
    strengths: ["photo", "safe"],
    description: "硬すぎず砕けすぎないので、初回商談や関係構築の食事に向いています。"
  },
  {
    id: "s4",
    name: "六本木 The Rooftop",
    area: "六本木",
    genre: "モダン・ダイニング",
    budgetBand: "high",
    atmosphere: "映える・開放的",
    pax: "2〜4名",
    scenes: ["creator", "first-meeting"],
    strengths: ["photo", "access"],
    description: "見映えが強いので、クリエイターや感度の高い相手との食事向きです。"
  },
  {
    id: "s5",
    name: "新宿 割烹 月夜",
    area: "新宿",
    genre: "和食・割烹",
    budgetBand: "high",
    atmosphere: "静か・和モダン",
    pax: "2〜5名",
    scenes: ["important-client", "recruitment"],
    strengths: ["quiet", "safe"],
    description: "落ち着いて話せるので、採用面談や重要な相談ごとにも使いやすいです。"
  },
  {
    id: "s6",
    name: "渋谷 青山ラウンジ",
    area: "渋谷",
    genre: "ラウンジ・ダイニング",
    budgetBand: "moderate",
    atmosphere: "都会的・話しやすい",
    pax: "2〜4名",
    scenes: ["first-meeting", "creator", "leave-it"],
    strengths: ["access", "photo"],
    description: "アクセスと雰囲気のバランスが良く、迷った時の無難な選択肢です。"
  },
  {
    id: "s7",
    name: "恵比寿 茶寮 しずく",
    area: "恵比寿",
    genre: "和食・茶寮",
    budgetBand: "moderate",
    atmosphere: "静か・上品",
    pax: "2〜3名",
    scenes: ["recruitment", "important-client"],
    strengths: ["quiet", "safe"],
    description: "話を丁寧にしたい場に向く静かな一軒。面談や信頼形成に向いています。"
  },
  {
    id: "s8",
    name: "銀座 クラシックグリル",
    area: "銀座",
    genre: "洋食・グリル",
    budgetBand: "high",
    atmosphere: "王道・安心感",
    pax: "2〜6名",
    scenes: ["leave-it", "executive", "important-client"],
    strengths: ["safe", "access"],
    description: "派手すぎず地味すぎない、安心感重視の王道店です。"
  }
];

const state = {
  scene: "important-client",
  area: "all",
  pax: "all",
  budget: "all",
  priority: "safe",
  top3: false,
  sortMode: "score-desc"
};

const summaryMap = {
  "important-client": {
    title: "いまの条件なら、失敗しにくい店を優先します",
    text: "重要クライアント向けに、静かさ・安心感・会話のしやすさを重視して並べます。"
  },
  "first-meeting": {
    title: "初回商談向けに、硬すぎない店を優先します",
    text: "印象は良くしつつ、会話が自然に進みやすい店を優先して表示します。"
  },
  "recruitment": {
    title: "採用面談向けに、話しやすい店を優先します",
    text: "威圧感よりも、落ち着いて話せる空気感を重視して並べます。"
  },
  "creator": {
    title: "感度の高い相手向けに、見映えも重視します",
    text: "雰囲気・写真映え・会話の作りやすさがある候補を優先します。"
  },
  "executive": {
    title: "代表・役員会食向けに、格と安定感を重視します",
    text: "個室感、高級感、アクセスの良さを重視して並べます。"
  },
  "leave-it": {
    title: "迷ったとき用に、外しにくい候補を優先します",
    text: "汎用性が高く、変に尖りすぎていない店を上位に出します。"
  }
};

const sceneLabelMap = {
  "important-client": "重要クライアント",
  "first-meeting": "初回商談",
  "recruitment": "採用面談",
  "creator": "クリエイター会食",
  "executive": "役員・代表会食",
  "leave-it": "おまかせ"
};

const budgetLabelMap = {
  moderate: "抑えめ",
  high: "しっかり使う",
  premium: "かなり大事な席"
};

const els = {
  sceneButtons: document.getElementById("sceneButtons"),
  areaSelect: document.getElementById("areaSelect"),
  paxSelect: document.getElementById("paxSelect"),
  budgetSelect: document.getElementById("budgetSelect"),
  prioritySelect: document.getElementById("prioritySelect"),
  recommendBtn: document.getElementById("recommendBtn"),
  top3Btn: document.getElementById("top3Btn"),
  sortBtn: document.getElementById("sortBtn"),
  resetBtn: document.getElementById("resetBtn"),
  summaryTitle: document.getElementById("summaryTitle"),
  summaryText: document.getElementById("summaryText"),
  resultCount: document.getElementById("resultCount"),
  resultsGrid: document.getElementById("resultsGrid"),
  template: document.getElementById("storeCardTemplate")
};

function init() {
  bindEvents();
  render();
}

function bindEvents() {
  els.sceneButtons.addEventListener("click", (e) => {
    const btn = e.target.closest(".scene-btn");
    if (!btn) return;
    state.scene = btn.dataset.scene;
    document.querySelectorAll(".scene-btn").forEach((node) => {
      node.classList.toggle("active", node === btn);
    });
    state.top3 = false;
    render();
  });

  els.areaSelect.addEventListener("change", (e) => {
    state.area = e.target.value;
  });

  els.paxSelect.addEventListener("change", (e) => {
    state.pax = e.target.value;
  });

  els.budgetSelect.addEventListener("change", (e) => {
    state.budget = e.target.value;
  });

  els.prioritySelect.addEventListener("change", (e) => {
    state.priority = e.target.value;
  });

  els.recommendBtn.addEventListener("click", () => {
    state.top3 = false;
    render();
  });

  els.top3Btn.addEventListener("click", () => {
    state.top3 = true;
    render();
  });

  els.sortBtn.addEventListener("click", () => {
    state.sortMode = state.sortMode === "score-desc" ? "area" : "score-desc";
    els.sortBtn.textContent = state.sortMode === "score-desc" ? "打率順" : "エリア順";
    render();
  });

  els.resetBtn.addEventListener("click", () => {
    state.scene = "important-client";
    state.area = "all";
    state.pax = "all";
    state.budget = "all";
    state.priority = "safe";
    state.top3 = false;
    state.sortMode = "score-desc";

    els.areaSelect.value = "all";
    els.paxSelect.value = "all";
    els.budgetSelect.value = "all";
    els.prioritySelect.value = "safe";

    document.querySelectorAll(".scene-btn").forEach((node) => {
      node.classList.toggle("active", node.dataset.scene === state.scene);
    });

    render();
  });
}

function render() {
  const summary = summaryMap[state.scene];
  els.summaryTitle.textContent = summary.title;
  els.summaryText.textContent = summary.text;

  let results = stores
    .map((store) => ({
      ...store,
      score: calcScore(store),
      reason: buildReason(store)
    }))
    .filter((store) => filterStore(store));

  if (state.sortMode === "area") {
    results.sort((a, b) => a.area.localeCompare(b.area, "ja"));
  } else {
    results.sort((a, b) => b.score - a.score);
  }

  if (state.top3) results = results.slice(0, 3);

  els.resultCount.textContent = results.length;
  els.resultsGrid.innerHTML = "";

  if (!results.length) {
    els.resultsGrid.innerHTML = `
      <div class="store-card">
        <div class="store-top">
          <div>
            <p class="store-area">候補なし</p>
            <h4 class="store-name">条件が少し厳しそうです</h4>
          </div>
        </div>
        <p class="store-desc">
          エリアを「指定しない」に戻すか、予算感を広げると候補が出やすくなります。
        </p>
      </div>
    `;
    return;
  }

  results.forEach((store) => {
    const node = els.template.content.firstElementChild.cloneNode(true);
    node.querySelector(".store-area").textContent = store.area;
    node.querySelector(".store-name").textContent = store.name;
    node.querySelector(".match-score").textContent = `打率 ${store.score}`;
    node.querySelector(".genre-pill").textContent = store.genre;
    node.querySelector(".budget-pill").textContent = budgetLabelMap[store.budgetBand];
    node.querySelector(".mood-pill").textContent = store.atmosphere;
    node.querySelector(".store-desc").textContent = store.description;
    node.querySelector(".reason-text").textContent = store.reason;
    node.querySelector(".pax-text").textContent = store.pax;
    node.querySelector(".scene-text").textContent =
      store.scenes.map((scene) => sceneLabelMap[scene]).slice(0, 2).join(" / ");
    els.resultsGrid.appendChild(node);
  });
}

function filterStore(store) {
  const areaOk = state.area === "all" || store.area === state.area;
  const budgetOk = state.budget === "all" || store.budgetBand === state.budget;
  const paxOk = state.pax === "all" || matchPax(store.pax, state.pax);
  return areaOk && budgetOk && paxOk;
}

function matchPax(storePaxText, selectedPax) {
  if (selectedPax === "all") return true;
  if (selectedPax === "5") return /5|6/.test(storePaxText);
  return storePaxText.includes(selectedPax);
}

function calcScore(store) {
  let score = 60;

  if (store.scenes.includes(state.scene)) score += 20;
  if (state.scene === "leave-it" && store.strengths.includes("safe")) score += 10;

  if (store.strengths.includes(state.priority)) score += 10;

  if (state.budget !== "all" && store.budgetBand === state.budget) score += 6;
  if (state.area !== "all" && store.area === state.area) score += 6;
  if (state.pax !== "all" && matchPax(store.pax, state.pax)) score += 4;

  if (store.strengths.includes("safe")) score += 4;
  if (store.strengths.includes("quiet")) score += 2;
  if (store.strengths.includes("private")) score += 2;

  return Math.min(score, 99);
}

function buildReason(store) {
  const reasons = [];

  if (store.scenes.includes(state.scene)) {
    reasons.push(`${sceneLabelMap[state.scene]}に合いやすい店です`);
  }

  if (store.strengths.includes(state.priority)) {
    const priorityTextMap = {
      safe: "失敗しにくさ",
      quiet: "静かさ",
      private: "個室感",
      photo: "見映え",
      access: "アクセス"
    };
    reasons.push(`${priorityTextMap[state.priority]}を重視した条件に合っています`);
  }

  if (store.strengths.includes("safe")) {
    reasons.push("王道で安心感があります");
  }

  if (state.scene === "important-client" && store.strengths.includes("quiet")) {
    reasons.push("大事な話をしやすい空気感です");
  }

  if (state.scene === "creator" && store.strengths.includes("photo")) {
    reasons.push("雰囲気づくりと見映えが強いです");
  }

  if (state.scene === "executive" && store.strengths.includes("private")) {
    reasons.push("代表同士の会食でも使いやすい個室寄りです");
  }

  return reasons.slice(0, 2).join("。") + "。";
}

init();
