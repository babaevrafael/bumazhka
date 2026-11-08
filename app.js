'use strict';
/*
 * Бумажка — «Кто я?» с бумажкой на лбу.
 *
 * Бэкенда нет: браузеры общаются через публичные MQTT-брокеры (WebSocket).
 * Всё, что уходит в брокер, зашифровано AES-GCM ключом из пароля лобби,
 * поэтому без пароля сообщения не прочитать. Состояние лобби хранится
 * в retained-сообщениях (по одному на ключ), конфликты — last-write-wins по ts.
 *
 * Ключи:
 *   p/<pid>   игрок {id, name, joinedAt, left?, kicked?}
 *   state     игра  {phase, mode, round, assign{setter:target}, order[], hostId}
 *   w/<pid>   слово для игрока {round, word, by}
 *   s/<pid>   итог игрока в раунде {round, result: 'guessed'|'gaveup'|null, at}
 *   turn      чей ход {round, pid}
 */
(() => {
  const BROKERS = ['wss://broker.emqx.io:8084/mqtt', 'wss://broker.hivemq.com:8884/mqtt'];
  const NS = 'bmzk1';
  const HEARTBEAT_MS = 15000;
  const ONLINE_MS = 45000;          // зелёный — в сети
  const ACTIVE_MS = 10 * 60000;     // жёлтый — телефон уснул, но игрок в игре
  const EXPIRY_S = 3 * 24 * 3600;   // брокер забудет лобби через 3 дня
  const CODE_ABC = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const MODES = [
    ['next', '⬇️ Тому, кто ниже'],
    ['prev', '⬆️ Тому, кто выше'],
    ['random', '🎲 Случайно'],
  ];

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const $app = document.getElementById('app');
  const $toast = document.getElementById('toast');

  const ls = {
    get(k, d = null) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
    del(k) { try { localStorage.removeItem(k); } catch {} },
  };

  let session = ls.get('bmzk:session');   // {code, pass, pid, name, joinedAt}
  let conn = null;
  let store = {};
  const drafts = {};
  const ui = { screen: 'start', tab: 'create', error: '', busy: false, editingWord: false, filling: null };
  let timers = [];
  let lastTurn = null;

  // ---------- utils ----------
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  function rnd(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  function uid(n = 10) { return Array.from(rnd(n), (b) => 'abcdefghijklmnopqrstuvwxyz0123456789'[b % 36]).join(''); }
  function genCode() { return Array.from(rnd(5), (b) => CODE_ABC[b % CODE_ABC.length]).join(''); }
  function normCode(s) { return String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); }
  function esc(s) { return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  function shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }
  function b64(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); }
  function unb64(s) { const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
  async function sha256hex(s) { const h = await crypto.subtle.digest('SHA-256', enc.encode(s)); return Array.from(new Uint8Array(h), (b) => b.toString(16).padStart(2, '0')).join(''); }
  function hashCode() { return normCode(decodeURIComponent(location.hash.slice(1))).slice(0, 5); }

  function toast(msg) {
    $toast.textContent = msg;
    $toast.classList.add('show');
    clearTimeout(toast.t);
    toast.t = setTimeout(() => {
      $toast.classList.remove('show');
      setTimeout(() => { if (!$toast.classList.contains('show')) $toast.textContent = ''; }, 300);
    }, 2600);
  }

  // ---------- crypto ----------
  async function deriveKey(code, pass) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode(NS + ':' + code), iterations: 150000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function seal(key, obj) {
    const iv = rnd(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj))));
    const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
    return b64(out);
  }
  async function unseal(key, s) {
    const u = unb64(s);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12));
    return JSON.parse(dec.decode(pt));
  }

  // ---------- network ----------
  function connect(code, key, base) {
    const c = { code, key, base, clients: [], good: 0, bad: 0, subs: 0, live: new Set(), joined: false, waiters: [] };
    BROKERS.forEach((url, i) => {
      let cl;
      try {
        cl = mqtt.connect(url, { protocolVersion: 5, clean: true, reconnectPeriod: 3000, connectTimeout: 10000, keepalive: 30, clientId: 'bmzk_' + uid(14) });
      } catch { return; }
      cl.on('connect', () => {
        c.live.add(i);
        cl.subscribe(base + '/#', { qos: 1 }, (err) => {
          if (err) return;
          c.subs++;
          c.waiters.splice(0).forEach((f) => f());
        });
        if (c.joined) publishPresence();
        scheduleRender();
      });
      const down = () => { c.live.delete(i); scheduleRender(); };
      cl.on('close', down);
      cl.on('offline', down);
      cl.on('error', () => {});
      cl.on('message', (topic, payload) => onMessage(c, topic, payload));
      c.clients.push(cl);
    });
    return c;
  }
  function waitSub(c, ms) {
    return new Promise((res) => {
      if (c.subs) return res(true);
      const t = setTimeout(() => res(false), ms);
      c.waiters.push(() => { clearTimeout(t); res(true); });
    });
  }
  function closeConn() {
    if (conn) conn.clients.forEach((cl) => { try { cl.end(true); } catch {} });
    conn = null;
    store = {};
    timers.forEach(clearInterval);
    timers = [];
    lastTurn = null;
  }
  function newer(a, b) { // a новее b?
    if (!b) return true;
    if (a.ts !== b.ts) return a.ts > b.ts;
    return JSON.stringify(a) > JSON.stringify(b);
  }
  async function onMessage(c, topic, payload) {
    if (c !== conn) return;
    const s = payload.toString();
    if (!s) return;
    let data;
    try { data = await unseal(c.key, s); } catch { c.bad++; return; }
    if (c !== conn || !data || typeof data.ts !== 'number') return;
    c.good++;
    const k = topic.slice(c.base.length + 1);
    if (!newer(data, store[k])) return;
    store[k] = data;
    onStoreChange(k, data);
    scheduleRender();
  }
  async function publish(k, data) {
    const c = conn;
    if (!c) return;
    const msg = { ...data, ts: Math.max(Date.now(), ((store[k] && store[k].ts) || 0) + 1) };
    store[k] = msg;
    onStoreChange(k, msg);
    scheduleRender();
    const payload = await seal(c.key, msg);
    await Promise.all(c.clients.map((cl) => new Promise((res) => {
      setTimeout(res, 4000);
      try {
        cl.publish(c.base + '/' + k, payload, { qos: 1, retain: true, properties: { messageExpiryInterval: EXPIRY_S } }, () => res());
      } catch { res(); }
    })));
  }
  function publishPresence(force = false) {
    if (!conn || !conn.joined || !session) return;
    const cur = store['p/' + session.pid];
    if (cur && cur.left && !force) return;
    return publish('p/' + session.pid, { id: session.pid, name: session.name, joinedAt: session.joinedAt });
  }

  function onStoreChange(k, data) {
    if (!session || !conn || !conn.joined) return;
    if (k === 'p/' + session.pid && data.left && data.kicked) {
      closeConn();
      clearSession();
      ui.screen = 'start';
      ui.tab = 'join';
      ui.error = 'Хост удалил тебя из лобби.';
      return;
    }
    if (k === 'turn' || k === 'state') {
      const t = gstate().phase === 'game' ? turnPid() : null;
      if (t && t === session.pid && lastTurn !== t) {
        toast('🎤 Твой ход — задавай вопрос!');
        try { navigator.vibrate && navigator.vibrate([120, 60, 120]); } catch {}
      }
      lastTurn = t;
    }
  }

  // ---------- derived state ----------
  const me = () => session && session.pid;
  function players() {
    const out = [];
    for (const k in store) {
      if (!k.startsWith('p/')) continue;
      const p = store[k];
      if (p.left) continue;
      out.push({ ...p, id: k.slice(2) });
    }
    return out;
  }
  function pById(id) { const p = store['p/' + id]; return p && !p.left ? { ...p, id } : null; }
  const age = (p) => Date.now() - p.ts;
  const isOnline = (p) => age(p) < ONLINE_MS;
  const isActive = (p) => age(p) < ACTIVE_MS;
  const dotClass = (p) => (isOnline(p) ? 'on' : isActive(p) ? 'away' : 'off');
  const dotTitle = (p) => (isOnline(p) ? 'в сети' : isActive(p) ? 'отошёл' : 'не в сети');
  function gstate() { return store.state || { phase: 'lobby', mode: 'next', round: 0, order: [], hostId: null, assign: {} }; }
  function ordered() {
    const byId = {};
    for (const p of players()) byId[p.id] = p;
    const out = [];
    for (const id of gstate().order || []) if (byId[id]) { out.push(byId[id]); delete byId[id]; }
    out.push(...Object.values(byId).sort((a, b) => (a.joinedAt - b.joinedAt) || a.id.localeCompare(b.id)));
    return out;
  }
  function hostId() {
    const st = gstate();
    const ord = ordered();
    const h = ord.find((p) => p.id === st.hostId);
    if (h && isOnline(h)) return h.id;
    const first = ord.find(isOnline);
    return first ? first.id : h ? h.id : null;
  }
  const amHost = () => hostId() === me();
  function wordFor(pid) { const w = store['w/' + pid]; return w && w.round === gstate().round && w.word ? w : null; }
  function statusOf(pid) { const s = store['s/' + pid]; return s && s.round === gstate().round && s.result ? s : null; }
  function turnPid() { const t = store.turn; return t && t.round === gstate().round ? t.pid : null; }
  function setterOf(pid) { const a = gstate().assign || {}; return Object.keys(a).find((s) => a[s] === pid) || null; }
  function nameOf(pid) { const p = store['p/' + pid]; return p ? p.name : '???'; }
  function rankOf(pid) {
    const guessed = players().map((p) => p.id).filter((id) => statusOf(id) && statusOf(id).result === 'guessed')
      .sort((a, b) => statusOf(a).at - statusOf(b).at);
    return guessed.indexOf(pid) + 1;
  }
  function inPlay(pid) { return !!wordFor(pid) && !statusOf(pid); }

  // ---------- actions ----------
  function fail(msg) { ui.error = msg; ui.busy = false; render(); }
  function clearSession() { session = null; ls.del('bmzk:session'); }

  async function submitStart() {
    if (ui.busy) return;
    const name = String(drafts.name ?? ls.get('bmzk:name', '')).trim().slice(0, 20);
    const pass = String(drafts.pass ?? '').trim();
    if (!name) return fail('Введи своё имя');
    if (!pass) return fail(ui.tab === 'create' ? 'Придумай пароль для лобби' : 'Введи пароль лобби');
    ls.set('bmzk:name', name);
    if (ui.tab === 'create') return enterRoom('create', genCode(), pass, name);
    const code = normCode(drafts.code ?? hashCode());
    if (code.length !== 5) return fail('Код лобби — 5 символов');
    return enterRoom('join', code, pass, name);
  }

  async function enterRoom(mode, code, pass, name, attempt = 0) {
    ui.busy = true; ui.error = ''; render();
    closeConn();
    let c;
    try {
      const [key, h] = await Promise.all([deriveKey(code, pass), sha256hex(NS + ':' + code)]);
      c = conn = connect(code, key, NS + '/' + h.slice(0, 24));
    } catch {
      return fail('Браузер не поддерживает нужное шифрование. Открой сайт по https в свежем браузере.');
    }
    const ok = await waitSub(c, 12000);
    if (c !== conn) return;
    if (!ok) { closeConn(); return fail('Нет связи с сервером. Проверь интернет и попробуй ещё раз.'); }
    await sleep(1500); // ждём retained-сообщения лобби
    if (c !== conn) return;

    if (mode === 'create' && (c.good || c.bad) && attempt < 3) return enterRoom('create', genCode(), pass, name, attempt + 1);
    if (mode !== 'create' && !c.good) {
      closeConn();
      if (mode === 'rejoin') clearSession();
      return fail(c.bad ? 'Неверный пароль' : 'Лобби не найдено — проверь код');
    }

    const reuse = session && session.code === code && session.pid;
    let pid = reuse ? session.pid : uid(10);
    let joinedAt = (reuse && session.joinedAt) || Date.now();
    const prev = store['p/' + pid];
    if (prev && prev.kicked) {
      if (mode === 'rejoin') { closeConn(); clearSession(); ui.tab = 'join'; return fail('Хост удалил тебя из лобби.'); }
      pid = uid(10); joinedAt = Date.now();
    }
    session = { code, pass, pid, name: mode === 'rejoin' ? session.name : name, joinedAt };
    ls.set('bmzk:session', session);
    c.joined = true;
    ui.screen = 'room'; ui.busy = false; ui.editingWord = false; ui.filling = null;
    history.replaceState(null, '', '#' + code);
    lastTurn = gstate().phase === 'game' ? turnPid() : null;
    publishPresence(true);
    if (mode === 'create') publish('state', { phase: 'lobby', mode: 'next', round: 0, order: [pid], hostId: pid, assign: {} });
    timers.push(setInterval(() => publishPresence(), HEARTBEAT_MS));
    timers.push(setInterval(scheduleRender, 5000));
    render();
  }

  async function leaveRoom() {
    if (!confirm('Выйти из лобби?')) return;
    const s = session;
    if (conn && s) await publish('p/' + s.pid, { id: s.pid, name: s.name, joinedAt: s.joinedAt, left: true });
    closeConn();
    clearSession();
    ui.screen = 'start'; ui.tab = 'join'; ui.error = '';
    render();
  }

  async function shareInvite() {
    const url = location.origin + location.pathname + '#' + session.code;
    const text = `Го играть в «Бумажку»! Лобби ${session.code}, пароль: ${session.pass}`;
    if (navigator.share && matchMedia('(pointer: coarse)').matches) {
      try { await navigator.share({ title: 'Бумажка', text, url }); return; } catch (e) { if (e && e.name === 'AbortError') return; }
    }
    try { await navigator.clipboard.writeText(text + '\n' + url); toast('Приглашение скопировано'); }
    catch { prompt('Скопируй приглашение:', text + ' ' + url); }
  }

  function setMode(mode) { if (amHost()) publish('state', { ...gstate(), mode }); }

  function movePlayer(pid, dir) {
    if (!amHost()) return;
    const ids = ordered().map((p) => p.id);
    const i = ids.indexOf(pid), j = i + dir;
    if (i < 0 || j < 0 || j >= ids.length) return;
    [ids[i], ids[j]] = [ids[j], ids[i]];
    publish('state', { ...gstate(), order: ids });
  }

  function kick(pid) {
    const p = pById(pid);
    if (!p || !amHost() || pid === me()) return;
    if (!confirm(`Удалить «${p.name}» из лобби?`)) return;
    publish('p/' + pid, { id: pid, name: p.name, joinedAt: p.joinedAt, left: true, kicked: true });
  }

  function startRound() {
    if (!amHost()) return;
    const parts = ordered().filter(isActive);
    if (parts.length < 2) return toast('Нужно хотя бы 2 игрока в сети');
    const st = gstate();
    const ids = parts.map((p) => p.id);
    const cyc = st.mode === 'random' ? shuffle(ids.slice()) : ids.slice();
    const n = cyc.length;
    const assign = {};
    cyc.forEach((id, i) => { assign[id] = st.mode === 'prev' ? cyc[(i - 1 + n) % n] : cyc[(i + 1) % n]; });
    const round = (st.round || 0) + 1;
    ui.editingWord = false; ui.filling = null; drafts.word = '';
    publish('state', { ...st, phase: 'game', round, assign, order: ordered().map((p) => p.id), hostId: st.hostId || me() });
    publish('turn', { round, pid: ids[0] });
  }

  function toLobby() {
    if (!amHost()) return;
    const st = gstate();
    const unfinished = Object.keys(st.assign || {}).some((id) => pById(id) && inPlay(id));
    if (unfinished && !confirm('Не все ещё угадали. Закончить раунд?')) return;
    publish('state', { ...st, phase: 'lobby' });
  }

  function submitWord() {
    const target = (gstate().assign || {})[me()];
    const word = String(drafts.word || '').trim().slice(0, 60);
    if (!target) return;
    if (!word) return toast('Напиши слово');
    publish('w/' + target, { round: gstate().round, word, by: me() });
    ui.editingWord = false; drafts.word = '';
  }

  function saveFill(pid) {
    const word = String(drafts['fill-' + pid] || '').trim().slice(0, 60);
    if (!word) return toast('Напиши слово');
    if (pid === me()) return;
    publish('w/' + pid, { round: gstate().round, word, by: me() });
    ui.filling = null; drafts['fill-' + pid] = '';
  }

  function setResult(pid, result) {
    const p = pById(pid);
    if (!p) return;
    if (result === 'guessed' && pid !== me() && !confirm(`${p.name} угадал(а) своё слово?`)) return;
    if (result === 'gaveup' && !confirm('Точно сдаёшься? Слово откроется.')) return;
    const wasTurn = turnPid() === pid;
    publish('s/' + pid, { round: gstate().round, result, at: Date.now(), by: me() });
    if (result === 'guessed' && pid === me()) toast('🎉 Угадал(а)!');
    if (wasTurn) passTurn();
  }

  function undoResult(pid) {
    if (!confirm('Отменить отметку? Игрок снова будет угадывать.')) return;
    publish('s/' + pid, { round: gstate().round, result: null, at: 0, by: me() });
  }

  function passTurn() {
    const ord = ordered();
    const cur = turnPid();
    const start = Math.max(0, ord.findIndex((p) => p.id === cur));
    for (let step = 1; step <= ord.length; step++) {
      const p = ord[(start + step) % ord.length];
      if (inPlay(p.id) && isActive(p) && (p.id !== cur || step === ord.length)) {
        return publish('turn', { round: gstate().round, pid: p.id });
      }
    }
    publish('turn', { round: gstate().round, pid: null });
  }

  // ---------- theme ----------
  const THEMES = { auto: ['🌗', 'Тема: как в системе'], dark: ['🌙', 'Тема: тёмная'], light: ['☀️', 'Тема: светлая'] };
  const getTheme = () => { const t = ls.get('bmzk:theme', 'auto'); return THEMES[t] ? t : 'auto'; };
  function applyTheme() {
    const t = getTheme();
    if (t === 'auto') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = t;
    const dark = t === 'dark' || (t === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = dark ? '#141312' : '#ffd84d';
  }
  function cycleTheme() {
    const order = ['auto', 'dark', 'light'];
    const next = order[(order.indexOf(getTheme()) + 1) % order.length];
    ls.set('bmzk:theme', next);
    applyTheme();
    toast(THEMES[next][1]);
    render();
  }
  const themeBtn = () => `<button class="ghost theme-btn" data-act="theme" title="${THEMES[getTheme()][1]}" aria-label="${THEMES[getTheme()][1]}">${THEMES[getTheme()][0]}</button>`;
  applyTheme();
  try { matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyTheme); } catch {}

  const actions = {
    theme: cycleTheme,
    tab:(el) => { ui.tab = el.dataset.tab; ui.error = ''; render(); },
    go: submitStart,
    share: shareInvite,
    leave: leaveRoom,
    mode: (el) => setMode(el.dataset.mode),
    up: (el) => movePlayer(el.dataset.pid, -1),
    down: (el) => movePlayer(el.dataset.pid, 1),
    kick: (el) => kick(el.dataset.pid),
    start: startRound,
    lobby: toLobby,
    word: submitWord,
    editWord: () => { const t = (gstate().assign || {})[me()]; const w = t && wordFor(t); drafts.word = w ? w.word : ''; ui.editingWord = true; render(); focusSoon('word'); },
    cancelEdit: () => { ui.editingWord = false; render(); },
    fill: (el) => { ui.filling = el.dataset.pid; render(); focusSoon('fill-' + el.dataset.pid); },
    fillSave: (el) => saveFill(el.dataset.pid),
    fillCancel: () => { ui.filling = null; render(); },
    guessed: (el) => setResult(el.dataset.pid, 'guessed'),
    giveup: (el) => setResult(el.dataset.pid, 'gaveup'),
    undo: (el) => undoResult(el.dataset.pid),
    pass: passTurn,
    clearNotes: () => { if (!confirm('Стереть заметки?')) return; ls.del(notesKey()); const n = document.getElementById('notes'); if (n) n.value = ''; },
  };
  function focusSoon(id) { setTimeout(() => { const el = document.getElementById(id); if (el) el.focus(); }, 30); }
  const notesKey = () => `bmzk:notes:${session && session.code}:${gstate().round}`;

  // ---------- views ----------
  function viewStart() {
    const join = ui.tab === 'join';
    return [['start', `
      <div class="start-tools">${themeBtn()}</div>
      <div class="hero" style="padding-top:4px">
        <div class="logo-note">Кто я?</div>
        <h1>Бумажка</h1>
        <p class="muted">Каждому «приклеивают» слово. Все видят чужие слова, кроме своего. Задавай вопросы «да / нет» и угадай, кто ты.</p>
      </div>
      <div class="card start-card">
        <label>Твоё имя
          <input id="name" maxlength="20" autocomplete="nickname" placeholder="Например, Рафаэль" data-default="${esc(ls.get('bmzk:name', ''))}" data-enter="go">
        </label>
        <div class="tabs">
          <button data-act="tab" data-tab="create" class="${join ? '' : 'on'}">Создать лобби</button>
          <button data-act="tab" data-tab="join" class="${join ? 'on' : ''}">Войти по коду</button>
        </div>
        ${join ? `<label>Код лобби
          <input id="code" class="code-input" maxlength="5" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="ABCDE" data-default="${esc(hashCode())}" data-enter="go">
        </label>` : ''}
        <label>${join ? 'Пароль лобби' : 'Придумай пароль'}
          <input id="pass" maxlength="40" autocomplete="off" spellcheck="false" placeholder="${join ? 'Скажет хост' : 'Например, банан'}" data-enter="go">
        </label>
        ${ui.error ? `<p class="err">${esc(ui.error)}</p>` : ''}
        <button class="primary wide" data-act="go" ${ui.busy ? 'disabled' : ''}>${ui.busy ? 'Подключаемся…' : join ? 'Войти' : 'Создать'}</button>
      </div>`]];
  }

  function viewHeader() {
    const live = conn && conn.live.size > 0;
    return ['header', `
      <div class="top">
        <button class="code-btn" data-act="share" title="Пригласить">Лобби <b>${esc(session.code)}</b> <span>🔗</span></button>
        <span class="grow"></span>
        <span class="net"><span class="dot ${live ? 'on' : 'off'}"></span>${live ? 'онлайн' : 'нет связи…'}</span>
        ${themeBtn()}
        <button class="ghost small" data-act="leave">Выйти</button>
      </div>`];
  }

  function viewPlayers() {
    const ord = ordered();
    const host = hostId();
    const canEdit = amHost();
    const items = ord.map((p, i) => `
      <li class="${p.id === me() ? 'me' : ''}">
        <span class="num">${i + 1}</span>
        <span class="dot ${dotClass(p)}" title="${dotTitle(p)}"></span>
        <span class="pname">${esc(p.name)}${p.id === me() ? ' <span class="muted">(ты)</span>' : ''}${p.id === host ? ' 👑' : ''}</span>
        ${canEdit ? `
          <button class="icon" data-act="up" data-pid="${p.id}" ${i === 0 ? 'disabled' : ''} aria-label="Выше">↑</button>
          <button class="icon" data-act="down" data-pid="${p.id}" ${i === ord.length - 1 ? 'disabled' : ''} aria-label="Ниже">↓</button>
          ${p.id !== me() ? `<button class="icon danger" data-act="kick" data-pid="${p.id}" aria-label="Удалить">✕</button>` : '<span style="width:34px"></span>'}` : ''}
      </li>`).join('');
    return ['players', `
      <section class="card">
        <div class="row between"><h2>Игроки · ${ord.length}</h2><span class="muted small">пароль: <b>${esc(session.pass)}</b></span></div>
        <ol class="plist">${items}</ol>
        <p class="muted small">${canEdit ? 'Расставь игроков так, как вы сидите по кругу (или как угодно) — стрелками.' : 'Порядок расставляет хост 👑.'} Кто отошёл (жёлтый) — всё равно играет, серых в раунд не берём.</p>
        <button class="small" data-act="share">🔗 Пригласить друзей</button>
      </section>`];
  }

  function viewMode() {
    const st = gstate();
    const host = amHost();
    const act = ordered().filter(isActive);
    const i = act.findIndex((p) => p.id === me());
    let preview = '';
    if (st.mode === 'random') preview = 'Кому загадываешь — узнаешь после старта.';
    else if (act.length >= 2 && i >= 0) {
      const n = act.length;
      const t = act[st.mode === 'prev' ? (i - 1 + n) % n : (i + 1) % n];
      preview = `Ты будешь загадывать для <b>${esc(t.name)}</b>.`;
    }
    const hp = pById(hostId());
    return ['mode', `
      <section class="card">
        <h2>Кому загадываем слово</h2>
        <div class="seg">${MODES.map(([m, label]) => `<button data-act="mode" data-mode="${m}" class="${st.mode === m ? 'on' : ''}" ${host ? '' : 'disabled'}>${label}</button>`).join('')}</div>
        <p class="muted small">${st.mode === 'random' ? 'Перемешаем по кругу: каждый загадывает ровно одному и получает ровно одно слово.' : 'По списку игроков, по кругу: последний загадывает первому.'} ${preview}</p>
        ${host
          ? `<button class="primary wide" data-act="start" ${act.length < 2 ? 'disabled' : ''}>${st.round ? 'Начать новый раунд' : 'Начать игру'}</button>${act.length < 2 ? '<p class="muted small">Нужно хотя бы 2 игрока — позови друзей.</p>' : ''}`
          : `<p class="muted">Ждём, пока ${hp ? esc(hp.name) : 'хост'} 👑 начнёт игру…</p>`}
      </section>`];
  }

  function viewRules() {
    return ['rules', `
      <section class="card">
        <details>
          <summary>Как играть</summary>
          <ol>
            <li>Каждый загадывает слово (персонажа, предмет, животное…) другому игроку.</li>
            <li>Ты видишь слова всех, кроме своего, — у тебя на карточке «❓».</li>
            <li>По очереди задавайте вопросы, на которые можно ответить «да» или «нет»: «Я человек?», «Я реальный?»…</li>
            <li>Ответили «да» — можно спросить ещё. «Нет» — ход переходит дальше (кнопка «Передать ход»).</li>
            <li>Угадал — жми «Я угадал!», слово откроется. Кто раньше угадал, тот выше в таблице.</li>
            <li>Свои догадки записывай в «Мои заметки» — их видишь только ты.</li>
          </ol>
        </details>
      </section>`];
  }

  function viewTask() {
    const st = gstate();
    const assign = st.assign || {};
    const target = assign[me()];
    let body;
    if (!target) {
      body = `<p>Ты зашёл(ла) посреди раунда. Слово тебе впишут прямо на карточке, а загадывать сам(а) будешь со следующего раунда.</p>`;
    } else if (!pById(target)) {
      body = `<p>Игрок, которому ты загадывал(а), вышел из лобби. Отдыхай 🙂</p>`;
    } else {
      const w = wordFor(target);
      const tn = esc(nameOf(target));
      if (w && !ui.editingWord) {
        const locked = !!statusOf(target);
        body = `<div class="row between">
          <p>Ты загадал(а) для <b>${tn}</b>: <span class="chip">${esc(w.word)}</span>${w.by !== me() ? ` <span class="muted small">(вписал(а) ${esc(nameOf(w.by))})</span>` : ''}</p>
          ${locked ? '' : '<button class="small" data-act="editWord">Изменить</button>'}
        </div>`;
      } else {
        body = `<h2>Загадай слово для ${tn}</h2>
          <div class="row">
            <input id="word" class="grow" maxlength="60" autocomplete="off" placeholder="Например, Гарри Поттер" data-enter="word" style="flex:1 1 180px">
            <button class="primary" data-act="word">${w ? 'Сохранить' : 'Загадать'}</button>
            ${w ? '<button class="ghost" data-act="cancelEdit">Отмена</button>' : ''}
          </div>
          <p class="muted small">${tn} не увидит слово, остальные — увидят.</p>`;
      }
    }
    // Ключ блока зависит только от того, что в нём; счётчик живёт отдельно,
    // чтобы поле ввода не пересоздавалось, когда загадывают другие.
    return ['task', `<section class="card ${target && !wordFor(target) && pById(target) ? 'task' : ''}">${body}</section>`];
  }

  function viewProgress() {
    const assign = gstate().assign || {};
    const all = players().map((p) => p.id);
    const done = all.filter((id) => wordFor(id)).length;
    const waiting = Object.keys(assign).filter((s) => pById(s) && pById(assign[s]) && !wordFor(assign[s])).map(nameOf);
    return ['progress', `<p class="muted small" style="margin:-6px 4px 0">Загадано ${done} из ${all.length}${waiting.length ? ` · ждём: ${waiting.map(esc).join(', ')}` : ''}</p>`];
  }

  function viewTurn() {
    const st = gstate();
    const parts = Object.keys(st.assign || {});
    const all = players().map((p) => p.id);
    const withWord = all.filter((id) => wordFor(id));
    const allDone = withWord.length > 0 && withWord.every((id) => statusOf(id)) && parts.every((id) => !pById(id) || wordFor(id));
    if (allDone) {
      const res = withWord.slice().sort((a, b) => {
        const sa = statusOf(a), sb = statusOf(b);
        const ra = sa.result === 'guessed' ? 0 : 1, rb = sb.result === 'guessed' ? 0 : 1;
        return ra - rb || sa.at - sb.at;
      });
      return ['turn', `
        <section class="card banner">
          <h2>🎉 Раунд ${st.round} окончен!</h2>
          <ol>${res.map((id) => `<li><b>${esc(nameOf(id))}</b> — ${esc(wordFor(id).word)} ${statusOf(id).result === 'guessed' ? '🏆' : '🏳️ сдался(ась)'}</li>`).join('')}</ol>
          ${amHost() ? '<button class="primary" data-act="lobby">К новому раунду</button>' : '<p class="small">Хост скоро начнёт новый раунд.</p>'}
        </section>`];
    }
    const t = turnPid();
    const tp = t && pById(t);
    if (tp && t === me()) {
      return ['turn', `
        <section class="card turncard mine">
          <div class="who">🎤 Твой ход!</div>
          <p class="hint">Задавай вопросы. Ответили «нет» — передавай ход.</p>
          <button class="pass" data-act="pass">Передать ход →</button>
        </section>`];
    }
    return ['turn', `
      <section class="card turncard">
        <div class="who">${tp ? `🎤 Спрашивает: <b>${esc(tp.name)}</b>` : '🎤 Очередь ещё не назначена'}</div>
        ${amHost() ? `<button class="pass-host" data-act="pass">${tp ? `Передать ход за ${esc(tp.name)} →` : 'Назначить ход'}</button>` : ''}
      </section>`];
  }

  function viewCard(p) {
    const isMe = p.id === me();
    const w = wordFor(p.id);
    const s = statusOf(p.id);
    const t = turnPid();
    const setter = setterOf(p.id);
    let sticky, meta = '', acts = '';

    if (isMe && !s) {
      sticky = `<div class="sticky hidden"><span class="q">❓</span>${w ? 'Это ты. Угадывай!' : 'Тебе загадывают…'}</div>`;
    } else if (w) {
      sticky = `<div class="sticky ${isMe ? 'mine-revealed' : ''}">${esc(w.word)}</div>`;
    } else if (ui.filling === p.id && !isMe) {
      sticky = `<div class="sticky hidden" style="gap:8px">
        <input id="fill-${p.id}" maxlength="60" autocomplete="off" placeholder="Слово для ${esc(p.name)}" data-enter="fillSave" data-pid="${p.id}">
        <div class="row" style="width:100%"><button class="small primary grow" data-act="fillSave" data-pid="${p.id}">Ок</button><button class="small ghost" data-act="fillCancel">✕</button></div>
      </div>`;
    } else {
      const who = setter && pById(setter) ? (setter === me() ? 'тебя ↑' : esc(nameOf(setter))) : null;
      sticky = `<div class="sticky hidden">${who ? `Ждём слово от ${who}…` : 'Слова пока нет'}</div>`;
    }

    if (w && !(isMe && !s)) meta = `загадал(а): ${esc(w.by === me() ? 'ты' : nameOf(w.by))}`;
    else if (w && isMe) meta = `загадал(а): ${esc(nameOf(w.by))}`;

    if (s) {
      const badge = s.result === 'guessed' ? `<span class="badge win">🏆 ${rankOf(p.id)} место</span>` : '<span class="badge">🏳️ сдался(ась)</span>';
      acts = `${badge}${isMe || amHost() ? `<button class="small ghost" data-act="undo" data-pid="${p.id}" title="Отменить">↺</button>` : ''}`;
    } else if (w) {
      acts = isMe
        ? `<button class="small ok" data-act="guessed" data-pid="${p.id}">Я угадал!</button><button class="small ghost" data-act="giveup" data-pid="${p.id}">Сдаюсь</button>`
        : `<button class="small" data-act="guessed" data-pid="${p.id}">✓ Угадал(а)</button>`;
    } else if (!isMe && setter !== me() && ui.filling !== p.id) {
      acts = `<button class="small" data-act="fill" data-pid="${p.id}">✍️ Загадать</button>`;
    }

    return `
      <div class="pcard ${isMe ? 'me' : ''} ${t === p.id ? 'turn' : ''} ${s ? 'done' : ''}">
        <div class="head"><span class="dot ${dotClass(p)}" title="${dotTitle(p)}"></span><span class="nm">${esc(p.name)}</span>${isMe ? '<span class="muted small">(ты)</span>' : ''}${t === p.id ? ' 🎤' : ''}</div>
        ${sticky}
        ${meta ? `<div class="meta">${meta}</div>` : ''}
        ${acts ? `<div class="acts">${acts}</div>` : ''}
      </div>`;
  }

  function viewBoard() {
    return ['board', `<div class="board">${ordered().map(viewCard).join('')}</div>`];
  }

  function viewNotes() {
    return ['notes-' + gstate().round, `
      <section class="card">
        <div class="row between"><h2>📝 Мои заметки</h2><button class="small ghost" data-act="clearNotes">Стереть</button></div>
        <textarea id="notes" placeholder="Что уже выяснил(а): «я человек», «не реальный», «из мультика»… Видишь только ты."></textarea>
      </section>`];
  }

  function viewHostControls() {
    if (!amHost()) return null;
    return ['hostctl', `
      <section class="card">
        <div class="row between">
          <span class="muted small">Ты хост 👑 · раунд ${gstate().round}</span>
          <button class="small" data-act="lobby">Закончить раунд → лобби</button>
        </div>
      </section>`];
  }

  function regions() {
    if (ui.screen !== 'room' || !conn || !conn.joined || !session) return viewStart();
    const st = gstate();
    const out = [viewHeader()];
    if (st.phase === 'game') out.push(viewTask(), viewProgress(), viewTurn(), viewBoard(), viewNotes(), viewHostControls());
    else out.push(viewPlayers(), viewMode(), viewRules());
    return out.filter(Boolean);
  }

  // Перерисовываем только изменившиеся блоки, чтобы не сбивать ввод.
  let renderQueued = false;
  function scheduleRender() {
    if (renderQueued) return;
    renderQueued = true;
    // microtask, а не rAF/setTimeout: те спят или тормозятся в фоновых вкладках.
    queueMicrotask(() => { renderQueued = false; render(); });
  }
  function render() {
    const active = document.activeElement;
    const aid = active && active.id && $app.contains(active) ? active.id : null;
    let selS = null, selE = null;
    try { selS = active.selectionStart; selE = active.selectionEnd; } catch {}

    const existing = new Map([...$app.children].map((el) => [el.dataset.key, el]));
    const keep = new Set();
    let prev = null;
    for (const [key, html] of regions()) {
      keep.add(key);
      let el = existing.get(key);
      if (!el) { el = document.createElement('div'); el.dataset.key = key; }
      if (el._html !== html) { el.innerHTML = html; el._html = html; }
      const ref = prev ? prev.nextSibling : $app.firstChild;
      if (el !== ref) $app.insertBefore(el, ref);
      prev = el;
    }
    for (const [key, el] of existing) if (!keep.has(key)) el.remove();

    // Значения полей держим в drafts, а не в HTML.
    $app.querySelectorAll('input[id], textarea[id]').forEach((el) => {
      if (el._init) return;
      el._init = true;
      if (el.id === 'notes') el.value = ls.get(notesKey(), '');
      else el.value = drafts[el.id] ?? el.dataset.default ?? '';
    });
    if (aid) {
      const n = document.getElementById(aid);
      if (n && n !== active) {
        n.focus({ preventScroll: true });
        try { if (selS != null) n.setSelectionRange(selS, selE); } catch {}
      }
    }
  }

  // ---------- events ----------
  $app.addEventListener('click', (e) => {
    const el = e.target.closest('[data-act]');
    if (!el || el.disabled || !$app.contains(el)) return;
    const fn = actions[el.dataset.act];
    if (fn) fn(el);
  });
  $app.addEventListener('input', (e) => {
    const el = e.target;
    if (!el.id) return;
    if (el.id === 'notes') ls.set(notesKey(), el.value);
    else drafts[el.id] = el.value;
  });
  $app.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || e.isComposing) return;
    const el = e.target;
    if (el.tagName !== 'INPUT' || !el.dataset.enter) return;
    e.preventDefault();
    const fn = actions[el.dataset.enter];
    if (fn) fn(el);
  });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') { publishPresence(); scheduleRender(); }
  });
  window.addEventListener('hashchange', () => {
    if (ui.screen === 'start') { const c = hashCode(); if (c) { ui.tab = 'join'; drafts.code = c; const el = document.getElementById('code'); if (el) el.value = c; render(); } }
  });

  // ---------- boot ----------
  if (typeof mqtt === 'undefined') {
    $app.innerHTML = '<div class="card"><p class="err">Не загрузилась библиотека связи. Обнови страницу.</p></div>';
    return;
  }
  const hc = hashCode();
  if (session && session.code && session.pass && (!hc || hc === session.code)) {
    enterRoom('rejoin', session.code, session.pass, session.name);
  } else {
    if (hc) ui.tab = 'join';
    render();
  }
})();
