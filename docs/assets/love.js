/* Our Story: unlock, decrypt and render. Everything private arrives AES-GCM encrypted. */
(() => {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const KEY_STORE = 'ourstory.key.v1';
  const DAY = 86400000;
  const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const finePointer = matchMedia('(hover: hover) and (pointer: fine)').matches;
  const HEART = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 21.2s-7.8-4.6-9.9-10C.7 7.6 2.9 3.6 6.8 3.6c2.2 0 3.9 1.2 5.2 3 1.3-1.8 3-3 5.2-3 3.9 0 6.1 4 4.7 7.6-2.1 5.4-9.9 10-9.9 10z"/></svg>';
  const PLAY = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M6 4l14 8-14 8z"/></svg>';
  const ZH_MONTH = ['一月', '二月', '三月', '四月', '五月', '六月', '七月', '八月', '九月', '十月', '十一月', '十二月'];

  const lock = $('#lock');
  const form = $('#lock-form');
  const pw = $('#pw');
  const err = $('#err');
  const story = $('#story');

  let meta = null;
  let key = null;
  let data = null;
  const byId = new Map();

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const store = {
    get() { try { return JSON.parse(localStorage.getItem(KEY_STORE)); } catch (e) { return null; } },
    set(v) { try { localStorage.setItem(KEY_STORE, JSON.stringify(v)); } catch (e) { /* private mode */ } },
    clear() { try { localStorage.removeItem(KEY_STORE); } catch (e) { /* ignore */ } },
  };

  /* ---------- crypto ---------- */
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const toB64 = (buf) => { let s = ''; new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); }); return btoa(s); };

  async function deriveKey(password) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.trim().normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: fromB64(meta.salt), iterations: meta.iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, true, ['decrypt'],
    );
  }

  async function decrypt(k, buf) {
    const u = new Uint8Array(buf);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.subarray(0, 12) }, k, u.subarray(12));
  }

  async function readManifest(k) {
    const r = await fetch('vault/m.bin', { cache: 'no-cache' });
    if (!r.ok) throw new Error('missing');
    const plain = await decrypt(k, await r.arrayBuffer());
    return JSON.parse(new TextDecoder().decode(plain));
  }

  async function readBlob(id) {
    const r = await fetch(`vault/${id}.bin`);
    if (!r.ok) throw new Error(r.status);
    return decrypt(key, await r.arrayBuffer());
  }

  /* The Chinese serif is subset to exactly the characters in the story, so it is encrypted too. */
  function loadStoryFont() {
    if (!data.font || !('FontFace' in window)) return;
    readBlob(data.font)
      .then((buf) => new FontFace('Story Kai', buf, { display: 'swap' }).load())
      .then((face) => { document.fonts.add(face); })
      .catch(() => {});
  }

  /* Encrypted blobs are fetched through a small queue so a long page never floods the network. */
  const blobs = new Map();
  const queue = [];
  let active = 0;
  function blobURL(id, type, urgent) {
    if (!blobs.has(id)) {
      blobs.set(id, new Promise((resolve, reject) => {
        const job = { id, type, resolve, reject };
        if (urgent) queue.unshift(job); else queue.push(job);
        pump();
      }));
    } else if (urgent) {
      const i = queue.findIndex((j) => j.id === id);
      if (i > 0) queue.unshift(queue.splice(i, 1)[0]);
    }
    return blobs.get(id);
  }
  function pump() {
    while (active < 6 && queue.length) {
      const job = queue.shift();
      active += 1;
      readBlob(job.id)
        .then((plain) => job.resolve(URL.createObjectURL(new Blob([plain], { type: job.type }))))
        .catch((e) => { blobs.delete(job.id); job.reject(e); })
        .finally(() => { active -= 1; pump(); });
    }
  }

  /* ---------- lock screen ---------- */
  async function boot() {
    if (!window.crypto || !crypto.subtle) {
      err.textContent = '这个页面需要用 https 打开。';
      return;
    }
    try {
      meta = await (await fetch('vault/meta.json', { cache: 'no-cache' })).json();
    } catch (e) {
      err.textContent = '内容还没准备好，稍后再来。';
      return;
    }
    if (meta.title) { $('#lock-title').innerHTML = `<em>${esc(meta.title)}</em>`; document.title = meta.title; }
    if (meta.subtitle) $('#lock-sub').textContent = meta.subtitle;
    if (meta.hint) { const h = $('#hint'); h.textContent = `提示：${meta.hint}`; h.hidden = false; }

    const saved = store.get();
    if (saved && saved.salt === meta.salt) {
      try {
        key = await crypto.subtle.importKey('raw', fromB64(saved.k), 'AES-GCM', false, ['decrypt']);
        data = await readManifest(key);
        open(true);
        return;
      } catch (e) {
        store.clear();
      }
    }
    key = null;
    document.documentElement.classList.remove('has-key');
    if (finePointer) pw.focus();
  }

  let busy = false;
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (busy || !meta) return;
    const value = pw.value;
    if (!value.trim()) { pw.focus(); return; }
    busy = true;
    err.textContent = '';
    lock.classList.remove('is-wrong');
    lock.classList.add('is-checking');
    try {
      const k = await deriveKey(value);
      data = await readManifest(k);
      key = k;
      if ($('#remember').checked) {
        store.set({ salt: meta.salt, k: toB64(await crypto.subtle.exportKey('raw', k)) });
      }
    } catch (e) {
      lock.classList.remove('is-checking');
      void lock.offsetWidth;
      lock.classList.add('is-wrong');
      err.textContent = '密码不对哦，再想想？';
      pw.select();
      busy = false;
      return;
    }
    pw.blur();
    open(false);
  });

  function open(remembered) {
    loadStoryFont();
    data.media.forEach((m, i) => { m.i = i; byId.set(m.id, m); });
    render();
    lock.classList.remove('is-checking');
    lock.classList.add('is-open');
    const wait = reduceMotion ? 0 : remembered ? 900 : 1500;
    setTimeout(() => {
      story.hidden = false;
      document.body.classList.remove('is-locked');
      document.documentElement.classList.remove('has-key');
      startReveal();
      setTimeout(() => lock.remove(), 1100);
    }, wait);
  }

  /* ---------- helpers ---------- */
  const parseDay = (s) => { const [y, m, d] = s.split('T')[0].split('-').map(Number); return new Date(y, m - 1, d); };
  const pad2 = (n) => String(n).padStart(2, '0');
  const fmtDate = (s) => (s instanceof Date
    ? `${s.getFullYear()}.${pad2(s.getMonth() + 1)}.${pad2(s.getDate())}`
    : s.slice(0, 10).replace(/-/g, '.'));
  const nf = new Intl.NumberFormat('en-US');

  function photoButton(m, opts = {}) {
    const ar = (m.w / m.h).toFixed(4);
    const extra = opts.more ? `<span class="more">+${opts.more}</span>` : (m.type === 'video' ? `<span class="play">${PLAY}</span>` : '');
    const label = m.cap ? esc(m.cap) : `${fmtDate(m.date)} 的${m.type === 'video' ? '视频' : '照片'}`;
    return `<button class="ph" type="button" data-id="${m.id}" data-set="${opts.set || ''}" style="--c:${m.c};--ar:${ar}" aria-label="${label}"><img alt="" decoding="async">${extra}</button>`;
  }

  /* ---------- render ---------- */
  const sets = {};

  function render() {
    const media = data.media;
    const [a, b] = data.names || [];
    const since = data.since ? parseDay(data.since) : null;
    const months = groupByMonth(media);
    sets.all = media.map((m) => m.id);

    let html = '';

    /* hero */
    html += `<section class="hero" id="top">
      <div class="hero-media"><img alt="" id="hero-img"></div>
      <div class="hero-inner">
        ${since ? `<p class="kicker">Together since ${fmtDate(data.since)}</p>` : ''}
        <h1 class="names">${a || b ? `<span>${esc(a)}</span><span class="amp">&amp;</span><span>${esc(b)}</span>` : '<span>Us</span>'}</h1>
        ${data.tagline ? `<p class="tagline">${esc(data.tagline)}</p>` : ''}
        ${since ? `<div class="counter" aria-live="off">
          <span class="lbl">我们已经在一起</span>
          <div class="big"><b id="c-days">0</b><span>天</span></div>
          <div class="hms"><span><b id="c-h">00</b>时</span><span><b id="c-m">00</b>分</span><span><b id="c-s">00</b>秒</span></div>
        </div>` : ''}
      </div>
      <a class="scroll-cue" href="#stats">SCROLL<i></i></a>
    </section>`;

    /* stats */
    const together = since ? Math.floor((Date.now() - since) / DAY) : null;
    const next = since ? nextAnniversary(since) : null;
    const places = new Set(months.map((g) => g.key)).size;
    html += `<section class="sec" id="stats"><div class="wrap"><div class="stats reveal">
      ${since ? `<div class="stat"><b>${nf.format(together)}</b><span>天在一起</span><small>DAYS</small></div>` : ''}
      <div class="stat"><b>${nf.format(media.length)}</b><span>张照片和视频</span><small>MOMENTS</small></div>
      <div class="stat"><b>${places}</b><span>个留下回忆的月份</span><small>MONTHS</small></div>
      ${next ? `<div class="stat"><b>${next.days}</b><span>${next.days === 0 ? `今天就是 ${next.n} 周年` : `天后是 ${next.n} 周年`}</span><small>ANNIVERSARY</small></div>` : ''}
    </div></div></section>`;

    /* timeline */
    const items = timelineItems(months, data.milestones || [], data.chapters || {});
    if (items.length) {
      let lastYear = null;
      let flip = false;
      html += `<section class="sec" id="timeline"><div class="wrap">
        <header class="sec-head reveal"><p class="kicker">Chapters</p><h2>我们的时间线</h2></header>
        <div class="tl"><i class="tl-fill"></i>`;
      for (const it of items) {
        const y = it.date.slice(0, 4);
        if (y !== lastYear) { html += `<div class="tl-year reveal"><span>${y}</span></div>`; lastYear = y; }
        html += it.kind === 'milestone' ? milestoneHTML(it, flip) : chapterHTML(it, flip);
        flip = !flip;
      }
      html += '</div></div></section>';
    }

    /* letter */
    if (data.letter && data.letter.body) {
      const paras = data.letter.body.trim().split(/\n\s*\n/).map((p) => `<p>${esc(p).replace(/\n/g, '<br>')}</p>`).join('');
      html += `<section class="sec letter" id="letter"><div class="paper">
        <svg class="seal" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 21.2s-7.8-4.6-9.9-10C.7 7.6 2.9 3.6 6.8 3.6c2.2 0 3.9 1.2 5.2 3 1.3-1.8 3-3 5.2-3 3.9 0 6.1 4 4.7 7.6-2.1 5.4-9.9 10-9.9 10z"/></svg>
        <p class="kicker">To you</p>
        <h2>${esc(data.letter.title || '写给你')}</h2>
        <div class="letter-body">${paras}</div>
        ${data.letter.sign ? `<p class="sign">${esc(data.letter.sign)}</p>` : ''}
      </div></section>`;
    }

    /* special days */
    const days = specialDays(since, data.days || []);
    if (days.length) {
      html += `<section class="sec" id="days"><div class="wrap">
        <header class="sec-head reveal"><p class="kicker">Days that matter</p><h2>重要的日子</h2></header>
        <div class="days">${days.map((d) => `<div class="day reveal${d.left === 0 ? ' today' : ''}">
          <div class="label">${esc(d.label)}</div>
          <b>${d.left === 0 ? '今天' : nf.format(d.left)}</b>
          <small>${d.left === 0 ? 'TODAY ♥' : `DAYS · ${fmtDate(d.when)}`}</small>
        </div>`).join('')}</div>
      </div></section>`;
    }

    /* gallery */
    if (media.length) {
      const years = [...new Set(media.map((m) => m.date.slice(0, 4)))];
      html += `<section class="sec" id="gallery"><div class="wrap">
        <header class="sec-head reveal"><p class="kicker">All of us</p><h2>所有的照片</h2><p class="lead">一共 ${nf.format(media.length)} 个瞬间。点开任意一张，可以左右翻看。</p></header>
        ${years.length > 1 ? `<div class="chips reveal" role="group" aria-label="按年份筛选"><button class="chip" aria-pressed="true" data-year="">全部</button>${years.map((y) => `<button class="chip" aria-pressed="false" data-year="${y}">${y}</button>`).join('')}</div>` : ''}
        <div class="wall" id="wall"></div>
        <div class="wall-more"><button class="btn" id="wall-more" hidden>再看更多</button></div>
      </div></section>`;
    }

    html += `<footer class="foot">
      <h3 class="grad">To be continued</h3>
      <p>${since ? `今天是我们在一起的第 ${nf.format(together + 1)} 天，故事还在继续。` : '故事还在继续。'}</p>
      <div class="heart">${HEART}</div>
      <button class="relock" type="button" id="relock">在这台设备上锁上</button>
    </footer>`;

    story.innerHTML = html;

    if (since) tick(since);
    if (data.cover && byId.has(data.cover)) {
      const c = byId.get(data.cover);
      blobURL(c.l, 'image/webp', true).then((u) => { const img = $('#hero-img'); img.onload = () => img.classList.add('ready'); img.src = u; }).catch(() => {});
    }
    if (media.length) setupWall();
    $('#relock').addEventListener('click', () => { store.clear(); location.reload(); });
  }

  function groupByMonth(media) {
    const map = new Map();
    for (const m of media) {
      const k = m.date.slice(0, 7);
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(m);
    }
    return [...map].map(([k, list]) => ({ key: k, list }));
  }

  function timelineItems(months, milestones, chapters) {
    // A chapter sorts after every day of its month, so a milestone such as "the day we met" opens its chapter.
    const out = months.map((g) => ({ kind: 'chapter', date: `${g.key}-99`, key: g.key, list: g.list, ch: chapters[g.key] || {} }));
    milestones.forEach((ms) => { if (ms.date) out.push({ kind: 'milestone', date: ms.date, ms }); });
    return out.sort((x, y) => (x.date < y.date ? -1 : x.date > y.date ? 1 : 0));
  }

  function pick(list, n) {
    if (list.length <= n) return list;
    const fav = list.filter((m) => m.fav);
    const rest = list.filter((m) => !m.fav);
    const need = Math.max(0, n - fav.length);
    const spread = [];
    for (let i = 0; i < need; i += 1) spread.push(rest[Math.floor((i * rest.length) / need)]);
    return [...fav.slice(0, n), ...spread].sort((x, y) => x.i - y.i);
  }

  function chapterHTML(it, flip) {
    const [y, mo] = it.key.split('-').map(Number);
    const setName = `m${it.key}`;
    sets[setName] = it.list.map((m) => m.id);
    const shown = pick(it.list, 5);
    const more = it.list.length - shown.length;
    const title = it.ch.title || ZH_MONTH[mo - 1];
    const count = it.list.length;
    return `<article class="tl-item chapter reveal${flip ? ' flip' : ''}">
      <div class="tl-text">
        <div class="tl-date">${y} · ${String(mo).padStart(2, '0')}</div>
        <h3 class="tl-title">${esc(title)}</h3>
        ${it.ch.text ? `<p class="tl-body">${esc(it.ch.text)}</p>` : ''}
        <div class="tl-count">${count} 个瞬间</div>
      </div>
      <div class="tl-media"><div class="collage n${shown.length}">
        ${shown.map((m, i) => photoButton(m, { set: setName, more: i === shown.length - 1 && more > 0 ? more : 0 })).join('')}
      </div></div>
    </article>`;
  }

  function milestoneHTML(it, flip) {
    const ms = it.ms;
    const m = ms.photo && byId.get(ms.photo);
    return `<article class="tl-item milestone reveal${flip ? ' flip' : ''}">
      <div class="tl-text">
        <div class="tl-date">${fmtDate(ms.date)}</div>
        <h3 class="tl-title">${esc(ms.title || '')}</h3>
        ${ms.text ? `<p class="tl-body">${esc(ms.text)}</p>` : ''}
      </div>
      <div class="tl-media">${m ? `<div class="collage n1">${photoButton(m, { set: 'all' })}</div>` : ''}</div>
    </article>`;
  }

  function nextAnniversary(since) {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    let n = today.getFullYear() - since.getFullYear();
    let when = new Date(since.getFullYear() + n, since.getMonth(), since.getDate());
    if (when < today) { n += 1; when = new Date(since.getFullYear() + n, since.getMonth(), since.getDate()); }
    if (n < 1) { n = 1; when = new Date(since.getFullYear() + 1, since.getMonth(), since.getDate()); }
    return { n, when, days: Math.round((when - today) / DAY) };
  }

  function specialDays(since, extra) {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const out = [];
    if (since) {
      const a = nextAnniversary(since);
      out.push({ label: `在一起 ${a.n} 周年`, when: a.when, left: a.days });
      const dayNo = Math.round((today - since) / DAY) + 1;
      const target = (Math.floor(dayNo / 100) + 1) * 100;
      const when = new Date(since.getTime() + (target - 1) * DAY);
      out.push({ label: `在一起的第 ${nf.format(target)} 天`, when, left: Math.round((when - today) / DAY) });
    }
    for (const d of extra) {
      if (!d.date) continue;
      const parts = d.date.split('-').map(Number);
      let when;
      if (parts.length === 2) {
        when = new Date(today.getFullYear(), parts[0] - 1, parts[1]);
        if (when < today) when = new Date(today.getFullYear() + 1, parts[0] - 1, parts[1]);
      } else {
        when = new Date(parts[0], parts[1] - 1, parts[2]);
        if (when < today) continue;
      }
      out.push({ label: d.label, when, left: Math.round((when - today) / DAY) });
    }
    return out.sort((x, y) => x.left - y.left);
  }

  /* ---------- live counter ---------- */
  function tick(since) {
    const els = { d: $('#c-days'), h: $('#c-h'), m: $('#c-m'), s: $('#c-s') };
    const pad = (n) => String(n).padStart(2, '0');
    const update = () => {
      let t = Math.max(0, Date.now() - since.getTime());
      const d = Math.floor(t / DAY); t -= d * DAY;
      const h = Math.floor(t / 3600000); t -= h * 3600000;
      const m = Math.floor(t / 60000); t -= m * 60000;
      els.d.textContent = nf.format(d);
      els.h.textContent = pad(h);
      els.m.textContent = pad(m);
      els.s.textContent = pad(Math.floor(t / 1000));
    };
    update();
    setInterval(update, 1000);
  }

  /* ---------- gallery wall ---------- */
  function setupWall() {
    const wall = $('#wall');
    const moreBtn = $('#wall-more');
    const PAGE = 60;
    let list = data.media;
    let shown = 0;
    const more = () => {
      const next = list.slice(shown, shown + PAGE);
      wall.insertAdjacentHTML('beforeend', next.map((m) => photoButton(m, { set: 'wall' })).join(''));
      shown += next.length;
      moreBtn.hidden = shown >= list.length;
      moreBtn.textContent = `再看更多（还有 ${list.length - shown} 张）`;
      observeImages(wall);
    };
    const reset = (year) => {
      list = year ? data.media.filter((m) => m.date.startsWith(year)) : data.media;
      sets.wall = list.map((m) => m.id);
      wall.innerHTML = '';
      shown = 0;
      more();
    };
    moreBtn.addEventListener('click', more);
    story.querySelectorAll('.chip').forEach((chip) => chip.addEventListener('click', () => {
      story.querySelectorAll('.chip').forEach((c) => c.setAttribute('aria-pressed', String(c === chip)));
      reset(chip.dataset.year);
    }));
    reset('');
  }

  /* ---------- lazy images ---------- */
  const imgObserver = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      imgObserver.unobserve(e.target);
      const m = byId.get(e.target.dataset.id);
      const img = e.target.querySelector('img');
      blobURL(m.id, 'image/webp').then((u) => { img.onload = () => img.classList.add('ready'); img.src = u; }).catch(() => {});
    }
  }, { rootMargin: '800px 0px' });
  const observeImages = (root) => root.querySelectorAll('.ph:not([data-seen])').forEach((el) => { el.dataset.seen = '1'; imgObserver.observe(el); });

  /* ---------- reveal + timeline progress ---------- */
  function startReveal() {
    const ro = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) { e.target.classList.add('in'); ro.unobserve(e.target); }
    }, { rootMargin: '0px 0px -8% 0px' });
    story.querySelectorAll('.reveal, .paper').forEach((el) => ro.observe(el));
    observeImages(story);
    const tl = $('.tl');
    if (tl) {
      const onScroll = () => {
        const r = tl.getBoundingClientRect();
        const p = Math.min(1, Math.max(0, (innerHeight * 0.6 - r.top) / r.height));
        tl.style.setProperty('--p', p.toFixed(4));
      };
      addEventListener('scroll', onScroll, { passive: true });
      onScroll();
    }
  }

  /* ---------- lightbox ---------- */
  const lb = $('#lb');
  const stage = $('#lb-stage');
  let lbSet = [];
  let lbIndex = 0;
  let lastFocus = null;

  story.addEventListener('click', (ev) => {
    const btn = ev.target.closest('.ph');
    if (!btn) return;
    const set = sets[btn.dataset.set] || sets.all;
    openLightbox(set, Math.max(0, set.indexOf(btn.dataset.id)));
  });

  function openLightbox(set, index) {
    lastFocus = document.activeElement;
    lbSet = set;
    lb.classList.add('open');
    document.body.style.overflow = 'hidden';
    show(index);
    $('#lb-close').focus({ preventScroll: true });
  }
  function closeLightbox() {
    lb.classList.remove('open');
    document.body.style.overflow = '';
    stage.querySelectorAll('video').forEach((v) => v.pause());
    if (lastFocus) lastFocus.focus({ preventScroll: true });
  }
  function show(i) {
    lbIndex = (i + lbSet.length) % lbSet.length;
    const m = byId.get(lbSet[lbIndex]);
    $('#lb-n').textContent = `${lbIndex + 1} / ${lbSet.length}`;
    $('#lb-date').textContent = fmtDate(m.date);
    $('#lb-text').textContent = m.cap || '';
    stage.innerHTML = '<img alt="" class="ghost">';
    const ghost = stage.querySelector('img');
    blobURL(m.id, 'image/webp', true).then((u) => { if (lbSet[lbIndex] === m.id) ghost.src = u; }).catch(() => {});
    const full = m.type === 'video' ? blobURL(m.v, 'video/mp4', true) : blobURL(m.l, 'image/webp', true);
    full.then((u) => {
      if (lbSet[lbIndex] !== m.id) return;
      if (m.type === 'video') {
        stage.innerHTML = `<video src="${u}" controls playsinline autoplay></video>`;
      } else {
        const img = new Image();
        img.alt = m.cap || '';
        img.onload = () => { if (lbSet[lbIndex] === m.id) stage.replaceChildren(img); };
        img.src = u;
      }
    }).catch(() => {});
    // Warm up the neighbours so swiping feels instant.
    [lbIndex + 1, lbIndex - 1].forEach((j) => {
      const n = byId.get(lbSet[(j + lbSet.length) % lbSet.length]);
      if (n && n.type !== 'video') blobURL(n.l, 'image/webp');
    });
  }
  $('#lb-close').addEventListener('click', closeLightbox);
  $('#lb-prev').addEventListener('click', () => show(lbIndex - 1));
  $('#lb-next').addEventListener('click', () => show(lbIndex + 1));
  addEventListener('keydown', (e) => {
    if (!lb.classList.contains('open')) return;
    if (e.key === 'Escape') closeLightbox();
    else if (e.key === 'ArrowRight') show(lbIndex + 1);
    else if (e.key === 'ArrowLeft') show(lbIndex - 1);
  });
  stage.addEventListener('click', (e) => { if (e.target === stage) closeLightbox(); });

  let touch = null;
  let lastTap = 0;
  lb.addEventListener('touchstart', (e) => { const t = e.touches[0]; touch = { x: t.clientX, y: t.clientY, at: Date.now() }; }, { passive: true });
  lb.addEventListener('touchend', (e) => {
    if (!touch) return;
    const t = e.changedTouches[0];
    const dx = t.clientX - touch.x;
    const dy = t.clientY - touch.y;
    const quick = Date.now() - touch.at < 250;
    touch = null;
    if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy)) { show(lbIndex + (dx < 0 ? 1 : -1)); return; }
    if (dy > 90 && Math.abs(dy) > Math.abs(dx)) { closeLightbox(); return; }
    if (quick && Math.abs(dx) < 10 && Math.abs(dy) < 10 && e.target.closest('.lb-stage')) {
      const now = Date.now();
      if (now - lastTap < 320) { popHeart(); lastTap = 0; } else lastTap = now;
    }
  });
  stage.addEventListener('dblclick', popHeart);
  function popHeart() {
    const h = document.createElement('span');
    h.className = 'pop';
    h.innerHTML = HEART;
    stage.appendChild(h);
    setTimeout(() => h.remove(), 1000);
  }

  /* ---------- ambience: starfield, pointer glow, floating hearts ---------- */
  function sky() {
    const canvas = $('#sky');
    const ctx = canvas.getContext('2d');
    let w = 0; let h = 0; let stars = []; let shoot = null; let nextShoot = performance.now() + 4000;
    const dpr = Math.min(2, devicePixelRatio || 1);
    const resize = () => {
      w = innerWidth; h = innerHeight;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const n = Math.min(260, Math.round((w * h) / 7000));
      stars = Array.from({ length: n }, () => ({
        x: Math.random() * w, y: Math.random() * h, r: Math.random() * 1.2 + 0.25,
        p: Math.random() * Math.PI * 2, s: 0.4 + Math.random() * 1.4, z: Math.random(),
        warm: Math.random() < 0.18,
      }));
    };
    const draw = (t) => {
      ctx.clearRect(0, 0, w, h);
      const sy = scrollY;
      for (const st of stars) {
        const a = reduceMotion ? 0.6 : 0.35 + 0.65 * (0.5 + 0.5 * Math.sin(st.p + (t / 1000) * st.s));
        let y = (st.y - sy * (0.03 + st.z * 0.08)) % h; if (y < 0) y += h;
        ctx.globalAlpha = a * (0.4 + st.z * 0.6);
        ctx.fillStyle = st.warm ? '#ffc7b0' : '#fff4f7';
        ctx.beginPath(); ctx.arc(st.x, y, st.r, 0, Math.PI * 2); ctx.fill();
      }
      if (!reduceMotion) {
        if (!shoot && t > nextShoot) {
          shoot = { x: Math.random() * w * 0.7 + w * 0.2, y: Math.random() * h * 0.35, vx: -(6 + Math.random() * 4), vy: 2.6 + Math.random() * 2, life: 0 };
        }
        if (shoot) {
          shoot.life += 1; shoot.x += shoot.vx; shoot.y += shoot.vy;
          const g = ctx.createLinearGradient(shoot.x, shoot.y, shoot.x - shoot.vx * 14, shoot.y - shoot.vy * 14);
          g.addColorStop(0, 'rgba(255,240,245,.9)'); g.addColorStop(1, 'rgba(255,125,156,0)');
          ctx.globalAlpha = Math.max(0, 1 - shoot.life / 70);
          ctx.strokeStyle = g; ctx.lineWidth = 1.4;
          ctx.beginPath(); ctx.moveTo(shoot.x, shoot.y); ctx.lineTo(shoot.x - shoot.vx * 14, shoot.y - shoot.vy * 14); ctx.stroke();
          if (shoot.life > 70) { shoot = null; nextShoot = t + 7000 + Math.random() * 9000; }
        }
      }
      ctx.globalAlpha = 1;
    };
    let raf = 0;
    const loop = (t) => { draw(t); raf = requestAnimationFrame(loop); };
    resize();
    addEventListener('resize', () => { resize(); if (reduceMotion) draw(0); });
    if (reduceMotion) { draw(0); addEventListener('scroll', () => draw(0), { passive: true }); return; }
    raf = requestAnimationFrame(loop);
    document.addEventListener('visibilitychange', () => {
      cancelAnimationFrame(raf);
      if (!document.hidden) raf = requestAnimationFrame(loop);
    });
  }

  function pointerFX() {
    if (!finePointer || reduceMotion) return;
    const glow = $('.glow');
    let x = innerWidth / 2; let y = innerHeight / 2; let gx = x; let gy = y;
    addEventListener('pointermove', (e) => { x = e.clientX; y = e.clientY; document.body.classList.add('has-pointer'); }, { passive: true });
    const follow = () => {
      gx += (x - gx) * 0.12; gy += (y - gy) * 0.12;
      glow.style.transform = `translate3d(${gx}px, ${gy}px, 0)`;
      requestAnimationFrame(follow);
    };
    follow();
    addEventListener('click', (e) => {
      if (document.body.classList.contains('is-locked') || e.target.closest('button, a, input, label, .lb')) return;
      const n = 2 + Math.floor(Math.random() * 2);
      for (let i = 0; i < n; i += 1) {
        const h = document.createElement('div');
        h.className = 'float-heart';
        h.innerHTML = HEART;
        h.style.left = `${e.clientX}px`;
        h.style.top = `${e.clientY}px`;
        h.style.setProperty('--dx', `${(Math.random() - 0.5) * 80}px`);
        h.style.setProperty('--rot', `${(Math.random() - 0.5) * 50}deg`);
        h.style.animationDelay = `${i * 90}ms`;
        h.style.width = h.style.height = `${12 + Math.random() * 12}px`;
        document.body.appendChild(h);
        setTimeout(() => h.remove(), 1700);
      }
    });
  }

  sky();
  pointerFX();
  boot();
})();
