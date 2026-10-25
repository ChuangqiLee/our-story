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
  const PAUSE = '<svg class="ic-pause" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="6" y="4.5" width="4" height="15" rx="1.2"/><rect x="14" y="4.5" width="4" height="15" rx="1.2"/></svg>';
  const ZH_MONTH = ['一月', '二月', '三月', '四月', '五月', '六月', '七月', '八月', '九月', '十月', '十一月', '十二月'];
  const ic = (d) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
  const ICON = {
    us: ic('<path d="M12 20s-7-4.2-8.9-9C1.9 7.7 3.9 4.5 7.1 4.5c2 0 3.6 1.1 4.9 2.8 1.3-1.7 2.9-2.8 4.9-2.8 3.2 0 5.2 3.2 4 6.5C19 15.8 12 20 12 20z"/>'),
    time: ic('<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>'),
    map: ic('<path d="M12 21s-6.5-6.2-6.5-11.2a6.5 6.5 0 0 1 13 0C18.5 14.8 12 21 12 21z"/><circle cx="12" cy="9.8" r="2.3"/>'),
    moments: ic('<rect x="3.5" y="5.5" width="17" height="13" rx="2.5"/><circle cx="9" cy="10.5" r="1.6"/><path d="M20.5 15.5l-4.5-4.5-7.5 7.5"/>'),
    days: ic('<rect x="4" y="5.5" width="16" height="14" rx="2.5"/><path d="M8 3.5v4M16 3.5v4M4 10h16"/><path d="M12 17.4s-2.7-1.6-2.7-3.3c0-.9.7-1.6 1.5-1.6.5 0 .9.3 1.2.7.3-.4.7-.7 1.2-.7.8 0 1.5.7 1.5 1.6 0 1.7-2.7 3.3-2.7 3.3z" fill="currentColor" stroke="none"/>'),
    someday: ic('<path d="M12 3.5l2.4 5.3 5.8.6-4.4 3.9 1.3 5.7L12 16l-5.1 3 1.3-5.7-4.4-3.9 5.8-.6z"/>'),
  };
  const HEART_PATH = 'M12 21.2s-7.8-4.6-9.9-10C.7 7.6 2.9 3.6 6.8 3.6c2.2 0 3.9 1.2 5.2 3 1.3-1.8 3-3 5.2-3 3.9 0 6.1 4 4.7 7.6-2.1 5.4-9.9 10-9.9 10z';
  // ?today=2027-01-29 previews the site as it will look on another day: a birthday, "on this day".
  const PREVIEW_DAY = /^(\d{4})-(\d{2})-(\d{2})$/.exec(new URLSearchParams(location.search).get('today') || '');
  function todayDate() {
    const d = PREVIEW_DAY ? new Date(Number(PREVIEW_DAY[1]), Number(PREVIEW_DAY[2]) - 1, Number(PREVIEW_DAY[3])) : new Date();
    d.setHours(0, 0, 0, 0);
    return d;
  }

  const lock = $('#lock');
  const form = $('#lock-form');
  const pw = $('#pw');
  const err = $('#err');
  const story = $('#story');

  let meta = null;
  let key = null;
  let data = null;
  let baseTitle = document.title;
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
      base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'],
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
    if (meta.title) { $('#lock-title').innerHTML = `<em>${esc(meta.title)}</em>`; document.title = meta.title; baseTitle = meta.title; }
    if (meta.subtitle) $('#lock-sub').textContent = meta.subtitle;
    if (meta.hint) { const h = $('#hint'); h.textContent = `提示：${meta.hint}`; h.hidden = false; }

    const saved = store.get();
    if (saved && saved.salt === meta.salt) {
      try {
        key = await crypto.subtle.importKey('raw', fromB64(saved.k), 'AES-GCM', false, ['encrypt', 'decrypt']);
        data = await readManifest(key);
        if (music.has() && music.wanted() && !(await music.canAutoplay())) await waitForEnter();
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

  // A remembered device skips the password, but sound may only start from a tap: one tap on the door, and the song comes with it.
  function waitForEnter() {
    const b = $('#enter');
    if (!b) return Promise.resolve();
    lock.classList.add('can-enter');
    if (finePointer) b.focus({ preventScroll: true });
    return new Promise((resolve) => {
      b.addEventListener('click', () => {
        music.unlock();
        lock.classList.remove('can-enter');
        resolve();
      }, { once: true });
    });
  }

  let busy = false;
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (busy || !meta) return;
    const value = pw.value;
    if (!value.trim()) { pw.focus(); return; }
    music.unlock();
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

  async function open(remembered) {
    loadStoryFont();
    data.media.forEach((m, i) => { m.i = i; byId.set(m.id, m); });
    render();
    lock.classList.remove('is-checking');
    lock.classList.add('is-open');
    const intro = reduceMotion ? null : prepareIntro();
    music.auto();
    await sleep(reduceMotion ? 0 : remembered ? 800 : 1300);
    if (intro) {
      try { await intro.play(); return; } catch (e) { /* fall back to a plain reveal */ }
    }
    showStory();
  }

  function showStory() {
    if (!story.hidden) return;
    story.hidden = false;
    document.body.classList.remove('is-locked');
    $('#brand')?.classList.add('on');
    $('#nav')?.classList.add('on');
    document.documentElement.classList.remove('has-key');
    startReveal();
    hero.start();
    const days = specialDays(data.since ? parseDay(data.since) : null, data.days || []);
    const bd = birthdayToday(days);
    if (bd) setTimeout(() => confetti(220), 500);
    const month = todayDate().getMonth();
    weather(bd ? 'confetti' : days.some((d) => d.left === 0 && /周年/.test(d.label)) ? 'hearts'
      : [2, 3, 4].includes(month) ? 'petals' : [5, 6, 7].includes(month) ? 'fireflies' : [8, 9, 10].includes(month) ? 'leaves' : 'snow');
    setTimeout(() => lock.remove(), 1100);
    cloud.sync();
  }

  /* ---------- helpers ---------- */
  const parseDay = (s) => { const [y, m, d] = s.split('T')[0].split('-').map(Number); return new Date(y, m - 1, d); };
  const pad2 = (n) => String(n).padStart(2, '0');
  const fmtDate = (s) => (s instanceof Date
    ? `${s.getFullYear()}.${pad2(s.getMonth() + 1)}.${pad2(s.getDate())}`
    : s.slice(0, 10).replace(/-/g, '.'));
  const nf = new Intl.NumberFormat('en-US');
  const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
  const placeOf = (m) => (m && m.p != null && data.places ? data.places[m.p] : null);
  // A date worked out from file times is only trusted to the month.
  const dateLabel = (m) => (m.dq === 'unknown' ? '' : m.dq === 'approx' ? `约 ${m.date.slice(0, 7).replace('-', '.')}` : fmtDate(m.date));

  function photoButton(m, opts = {}) {
    const ar = (m.w / m.h).toFixed(4);
    const extra = opts.more ? `<span class="more">+${opts.more}</span>` : (m.type === 'video' ? `<span class="play">${PLAY}</span>` : '');
    const kind = m.type === 'video' ? '视频' : '照片';
    const label = m.cap ? esc(m.cap) : m.dq === 'unknown' ? kind : `${dateLabel(m)} 的${kind}`;
    return `<button class="ph" type="button" data-id="${m.id}" data-set="${opts.set || ''}" style="--c:${m.c};--ar:${ar}" aria-label="${label}"><img alt="" decoding="async">${extra}</button>`;
  }


  /* ---------- the seal ---------- */
  // Its strokes live in the encrypted story; this only knows how to draw them.
  const SEAL_DEFS = '<svg class="seal-defs" width="0" height="0" aria-hidden="true"><defs><linearGradient id="seal-grad" gradientUnits="userSpaceOnUse" x1="20" y1="20" x2="180" y2="180"><stop offset="0" stop-color="#ffd1dc"/><stop offset=".45" stop-color="#ff7d9c"/><stop offset="1" stop-color="#ffb68c"/></linearGradient></defs></svg>';
  const hasSeal = () => !!(data && data.seal && data.seal.svg);
  const sealSVG = (cls = '') => (hasSeal()
    ? `<svg class="seal-mark ${cls}" viewBox="0 0 200 200" fill="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${data.seal.svg}</svg>`
    : '');

  /* Write the strokes in order, let the four drops of rain fall in, then press it down like a stamp.
     k stretches or shrinks the whole thing; returns its length in ms. */
  function playSeal(svg, k = 1) {
    if (!svg || reduceMotion) return 0;
    svg.getAnimations({ subtree: true }).forEach((a) => a.cancel());
    const draw = (el, delay, dur) => {
      let len = 1;
      try { len = el.getTotalLength() || 1; } catch (e) { /* not rendered */ }
      el.style.strokeDasharray = `${len} ${len * 2}`;
      el.animate([{ strokeDashoffset: len }, { strokeDashoffset: 0 }], { duration: dur * k, delay: delay * k, easing: 'cubic-bezier(.5,0,.2,1)', fill: 'both' });
    };
    const frame = svg.querySelector('.frame');
    if (frame) draw(frame, 0, 900);
    let t = 500;
    svg.querySelectorAll('.st').forEach((p) => { draw(p, t, 300); t += 210; });
    const drops = svg.querySelectorAll('.drop');
    drops.forEach((d, i) => {
      d.style.transformBox = 'fill-box';
      d.style.transformOrigin = '50% 100%';
      d.animate([
        { opacity: 0, transform: 'translateY(-150px) scaleY(1.25)' },
        { opacity: 1, transform: 'translateY(-60px) scaleY(1.2)', offset: 0.45 },
        { opacity: 1, transform: 'translateY(2px) scale(1.15,.8)', offset: 0.86 },
        { opacity: 1, transform: 'none' },
      ], { duration: 520 * k, delay: (t + 120 + i * 170) * k, easing: 'cubic-bezier(.55,0,.9,.6)', fill: 'both' });
    });
    if (drops.length) t += 120 + drops.length * 170 + 420;
    svg.animate([{ transform: 'none' }, { transform: 'scale(.93)', offset: 0.35 }, { transform: 'scale(1.03)', offset: 0.7 }, { transform: 'none' }],
      { duration: 520, delay: t * k, easing: 'cubic-bezier(.2,.7,.1,1)' });
    svg.animate([{ filter: 'drop-shadow(0 0 0 rgba(255,125,156,0))' }, { filter: 'drop-shadow(0 0 22px rgba(255,125,156,.65))', offset: 0.3 }, { filter: 'drop-shadow(0 0 0 rgba(255,125,156,0))' }],
      { duration: 1500, delay: t * k });
    return t * k + 520;
  }

  /* ---------- music ---------- */
  const clock = (sec) => `${Math.floor(sec / 60)}:${pad2(Math.floor(sec % 60))}`;
  const music = (() => {
    const PREF = 'ourstory.music';
    // Every visit starts with the song; pausing it only lasts until the site is opened again.
    try { localStorage.removeItem(PREF); } catch (e) { /* private mode */ }
    const VOL = 0.6;
    // A few bytes of silence, played inside a tap so the real song may start later without one.
    const SILENCE = 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAAAAA=';
    let audio = null;
    let ctx = null;
    let gain = null;
    let ready = null;
    let want = false;
    let ducked = false;
    let away = false;
    let armed = false;
    let fadeTimer = 0;
    const pref = {
      get() { try { return sessionStorage.getItem(PREF); } catch (e) { return null; } },
      set(v) { try { sessionStorage.setItem(PREF, v); } catch (e) { /* private mode */ } },
    };
    const has = () => !!(data && data.music && data.music.id);

    function ensure() {
      if (audio) return;
      // iPhones mute Web Audio when the silent switch is on; music should play like a video does.
      try { if (navigator.audioSession) navigator.audioSession.type = 'playback'; } catch (e) { /* older Safari */ }
      audio = new Audio();
      audio.loop = true;
      audio.preload = 'auto';
      audio.setAttribute('playsinline', '');
      ['play', 'pause', 'timeupdate', 'seeked'].forEach((e) => audio.addEventListener(e, ui));
      const C = window.AudioContext || window.webkitAudioContext;
      if (C) {
        try {
          ctx = new C();
          gain = ctx.createGain();
          gain.gain.value = 0;
          ctx.createMediaElementSource(audio).connect(gain).connect(ctx.destination);
        } catch (e) { ctx = null; gain = null; }
      }
    }
    // Call synchronously from a tap or the password submit.
    function unlock() {
      ensure();
      if (ctx && ctx.state !== 'running') ctx.resume().catch(() => {});
      if (!audio.src) { audio.src = SILENCE; audio.play().catch(() => {}); }
    }
    function load() {
      if (!ready) ready = blobURL(data.music.id, data.music.type || 'audio/mp4');
      ready.catch(() => { ready = null; });
      return ready;
    }
    function fade(to, ms) {
      if (gain) {
        const t = ctx.currentTime;
        gain.gain.cancelScheduledValues(t);
        gain.gain.setValueAtTime(gain.gain.value, t);
        gain.gain.linearRampToValueAtTime(to, t + ms / 1000);
        return;
      }
      clearInterval(fadeTimer);
      const from = audio.volume;
      const t0 = performance.now();
      fadeTimer = setInterval(() => {
        const k = Math.min(1, (performance.now() - t0) / ms);
        audio.volume = from + (to - from) * k;
        if (k === 1) clearInterval(fadeTimer);
      }, 40);
    }
    async function play(at) {
      if (!has()) return false;
      want = true;
      ensure();
      ui();
      let url;
      try { url = await load(); } catch (e) { want = false; ui(); return false; }
      if (!want) return false;
      if (audio.src !== url) { audio.src = url; if (!gain) audio.volume = 0; }
      if (at != null) { try { audio.currentTime = at; } catch (e) { /* not seekable yet */ } }
      if (ctx && ctx.state !== 'running') await Promise.race([ctx.resume().catch(() => {}), sleep(400)]);
      if (ctx && ctx.state !== 'running') { want = false; ui(); arm(); return false; } // still needs a tap
      try {
        await audio.play();
      } catch (e) {
        want = false;
        ui();
        arm();
        return false;
      }
      fade(VOL, at != null ? 900 : 2600);
      pref.set('on');
      ui();
      return true;
    }
    function pause(byUser) {
      want = false;
      if (byUser) pref.set('off');
      if (audio && !audio.paused) {
        fade(0, 500);
        setTimeout(() => { if (!want) audio.pause(); }, 520);
      }
      ui();
    }
    const playing = () => !!(audio && !audio.paused && want);
    function toggle() { unlock(); if (playing()) pause(true); else play(); }
    // Autoplay with sound is usually blocked without a tap: start on the first one instead.
    function arm() {
      if (armed || pref.get() === 'off') return;
      armed = true;
      $('#music-btn')?.classList.add('ask');
      const first = (e) => {
        if (e.target.closest && e.target.closest('#music-btn, #song-play, .song-notes')) return;
        removeEventListener('pointerdown', first, true);
        removeEventListener('keydown', first, true);
        armed = false;
        unlock();
        play();
      };
      addEventListener('pointerdown', first, true);
      addEventListener('keydown', first, true);
    }
    function auto() {
      if (!has()) return;
      if (pref.get() === 'off') { ui(); return; }
      play();
    }
    // Whether sound may start without a tap here (some desktop browsers allow it for sites people come back to).
    async function canAutoplay() {
      try { if (navigator.getAutoplayPolicy) return navigator.getAutoplayPolicy('mediaelement') === 'allowed'; } catch (e) { /* not supported */ }
      const probe = new Audio(SILENCE);
      try {
        await Promise.race([probe.play(), sleep(400).then(() => { throw new Error('timeout'); })]);
        return true;
      } catch (e) {
        return false;
      }
    }
    function duck(on) {
      if (on && playing()) { ducked = true; pause(false); }
      else if (!on && ducked) { ducked = false; play(); }
    }
    document.addEventListener('visibilitychange', () => {
      if (document.hidden && playing()) { away = true; audio.pause(); }
      else if (!document.hidden && away) { away = false; play(); }
    });

    function ui() {
      const on = playing();
      const btn = $('#music-btn');
      if (btn) {
        btn.classList.toggle('playing', on);
        if (on) btn.classList.remove('ask');
        btn.setAttribute('aria-pressed', String(on));
        btn.setAttribute('aria-label', on ? '暂停音乐' : '播放音乐');
      }
      const sp = $('#song-play');
      if (sp) sp.classList.toggle('playing', on);
      if (!audio || !has()) return;
      const dur = data.music.dur || audio.duration || 1;
      const now = audio.src.startsWith('blob:') ? audio.currentTime : 0;
      const time = $('#song-time');
      if (time) time.textContent = `${clock(now)} / ${clock(dur)}`;
      const bar = $('#song-bar i');
      if (bar) bar.style.transform = `scaleX(${Math.min(1, now / dur)})`;
      const notes = data.music.notes || [];
      let cur = -1;
      notes.forEach((n, i) => { if (now >= n.t) cur = i; });
      document.querySelectorAll('.song-notes li').forEach((li, i) => li.classList.toggle('now', on && i === cur));
    }
    return { unlock, play, pause, toggle, auto, duck, ui, has, canAutoplay, wanted: () => pref.get() !== 'off' };
  })();

  /* ---------- render: one page per part of the story ---------- */
  const sets = {};
  let pages = [];

  function render() {
    const media = data.media;
    const since = data.since ? parseDay(data.since) : null;
    const months = groupByMonth(media);
    const days = specialDays(since, data.days || []);
    const groups = placeGroups();
    const firsts = (data.firsts || []).filter((f) => f.title);
    const things = bucket.items();
    sets.all = media.map((m) => m.id);
    const favs = media.filter((m) => m.fav && m.type === 'photo');
    const fav = (k) => (favs.length ? favs[k % favs.length] : media[k % media.length]);
    pages = [
      { id: '', zh: '我们', en: 'Us', icon: ICON.us, build: (p) => homeHTML(p, { media, since, months, days, favs }) },
      {
        id: 'time', zh: '时光', en: 'Chapters', icon: ICON.time, has: months.length || firsts.length,
        build: (p) => timeHTML(p, { media, since, months, firsts, favs }),
        blurb: `${firsts.length ? `${firsts.length} 个第一次 · ` : ''}${months.length} 个月的照片`,
        cover: photoFor(firsts[1]) || fav(0),
      },
      {
        id: 'map', zh: '足迹', en: 'Places & moments', icon: ICON.map, has: media.length,
        build: (p) => mapHTML(p, groups, media),
        blurb: `${groups.length ? `${groups.length} 个地方 · ` : ''}${nf.format(media.length)} 个瞬间`,
        cover: groups.length ? tripCover(groups[groups.length - 1]) : fav(1),
      },
      {
        id: 'someday', zh: '以后', en: 'Someday', icon: ICON.someday,
        build: (p) => somedayHTML(p, things, favs),
        blurb: things.length ? `${things.length} 件事做了 ${bucket.count()} 件 · 时光胶囊` : '时光胶囊',
        cover: media[media.length - 1],
      },
    ].filter((p) => p.has === undefined || p.has);
    pages.forEach((p, i) => { p.no = i; });

    story.innerHTML = pages.map((p, i) => `<div class="page" data-page="${p.id}" hidden>
      ${p.build(p)}${i ? nextHTML(i) : ''}${footHTML(since)}
    </div>`).join('');
    chrome();

    if (since) tick(since);
    hero.prepare();
    atlas.setup();
    if (media.length) setupWall();
    setupCapsule();
    bucket.setup();
    story.querySelectorAll('.relock').forEach((b) => b.addEventListener('click', () => { store.clear(); location.reload(); }));
    $('.scroll-cue')?.addEventListener('click', () => $('#top').nextElementSibling?.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth' }));
    route();
  }

  function photoOn(date) {
    const day = date.slice(0, 10);
    const same = data.media.filter((m) => m.type === 'photo' && m.dq !== 'unknown' && m.date.slice(0, 10) === day);
    return same.find((m) => m.fav) || same[0] || null;
  }
  const photoFor = (item) => (item ? (item.photo && byId.get(item.photo)) || (item.date && photoOn(item.date)) || null : null);
  const tripCover = (g) => g.list.find((m) => m.fav && m.type === 'photo') || g.list.find((m) => m.type === 'photo') || g.list[0];
  const birthdayToday = (days) => days.find((d) => d.left === 0 && /生日/.test(d.label)) || null;

  // A page opens with its title, a few numbers, and a small fan of photos, so the first screen is never empty.
  function pageHead(p, lead, { facts = [], photos = [] } = {}) {
    const fan = photos.filter(Boolean).slice(0, 4);
    return `<header class="page-head${fan.length ? ' has-fan' : ''}"><div class="wrap">
      <div class="head-copy">
        <p class="page-no"><i>${pad2(p.no + 1)}</i><span>${esc(p.en)}</span></p>
        <h1 class="page-title">${[...p.zh].map((c, i) => `<span style="--i:${i}">${esc(c)}</span>`).join('')}</h1>
        ${lead ? `<p class="lead">${lead}</p>` : ''}
        ${facts.length ? `<dl class="facts">${facts.map(([n, l, id]) => `<div><dt${id ? ` id="${id}"` : ''}>${n}</dt><dd>${l}</dd></div>`).join('')}</dl>` : ''}
      </div>
      ${fan.length ? `<div class="fan" aria-hidden="true">${fan.map((m, k) => `<span class="fan-card lazy" data-id="${m.id}" style="--c:${m.c};--k:${k}"><img alt=""></span>`).join('')}</div>` : ''}
    </div></header>`;
  }

  function nextHTML(i) {
    const last = i === pages.length - 1;
    const n = last ? pages[0] : pages[i + 1];
    const m = n.id ? n.cover : (hero.first() || { list: [] }).list[0];
    return `<section class="next-sec"><div class="wrap"><a class="nextp reveal" href="#/${n.id}" style="--c:${m ? m.c : '#221a24'}">
      ${m ? `<span class="lazy next-bg" data-id="${m.id}"><img alt=""></span>` : ''}
      <span class="kicker">${last ? '回到开头' : '下一页'} · ${pad2(n.no + 1)}</span>
      <b>${n.zh}</b><small>${esc(n.en)}</small>
      <span class="next-arrow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></span>
    </a></div></section>`;
  }

  function footHTML(since) {
    const together = since ? Math.floor((Date.now() - since) / DAY) : 0;
    return `<footer class="foot">
      <h3 class="grad">To be continued</h3>
      <p>${since ? `今天是我们在一起的第 ${nf.format(together + 1)} 天，故事还在继续。` : '故事还在继续。'}</p>
      <div class="${hasSeal() ? 'foot-seal' : 'heart'}">${sealSVG('is-mini') || HEART}</div>
      <button class="relock" type="button">在这台设备上锁上</button>
    </footer>`;
  }

  /* 01 us: the cover, our seal and song, today and the days ahead, our favourites, and the doors to the other pages */
  function homeHTML(p, { media, since, months, days, favs }) {
    const [a, b] = data.names || [];
    const bd = birthdayToday(days);
    let html = `<section class="hero" id="top">
      <div class="hero-media" id="hero-media" aria-hidden="true"></div>
      <div class="hero-meta" id="hero-meta" aria-hidden="true"></div>
      <div class="hero-inner">
        ${bd ? '<p class="kicker bday-k reveal">Happy birthday</p>' : since ? `<p class="kicker reveal">Together since ${fmtDate(data.since)}</p>` : ''}
        <h1 class="names reveal" style="transition-delay:.12s">${a || b ? `<span>${esc(a)}</span><span class="amp">&amp;</span><span>${esc(b)}</span>` : '<span>Us</span>'}</h1>
        ${bd ? `<p class="bday-line reveal" style="transition-delay:.18s">今天是${esc(bd.label)}${bd.age ? `，${bd.age} 岁` : ''}。生日快乐！</p>` : ''}
        ${data.tagline ? `<p class="tagline reveal">${esc(data.tagline)}</p>` : ''}
        ${since ? `<div class="counter reveal" style="transition-delay:.24s" aria-live="off">
          <span class="lbl">我们已经在一起</span>
          <div class="big"><b id="c-days">0</b><span>天</span></div>
          <div class="hms"><span><b id="c-h">00</b>时</span><span><b id="c-m">00</b>分</span><span><b id="c-s">00</b>秒</span></div>
        </div>` : ''}
      </div>
      <button class="scroll-cue" type="button">SCROLL<i></i></button>
    </section>`;
    html += sealHTML();
    html += todayHTML(days);
    html += statsHTML(media, since, months);
    html += moonHTML(since);
    html += favsHTML(favs);
    html += doorsHTML();
    return html;
  }

  // Eight favourites in a mosaic, a different eight every day.
  function favsHTML(favs) {
    if (favs.length < 4) return '';
    const n = Math.min(8, favs.length);
    const start = (Math.round(todayDate() / DAY) * n) % favs.length;
    const list = Array.from({ length: n }, (_, k) => favs[(start + k) % favs.length]);
    sets.favs = list.map((m) => m.id);
    return `<section class="sec favs-sec"><div class="wrap">
      <header class="sec-head reveal"><p class="kicker">Favorites</p><h2>最喜欢的我们</h2><p class="lead">从 ${favs.length} 张最爱里挑的，每天换一组。</p></header>
      <div class="bento reveal">${list.map((m) => photoButton(m, { set: 'favs' })).join('')}</div>
    </div></section>`;
  }

  function statsHTML(media, since, months) {
    const together = since ? Math.floor((Date.now() - since) / DAY) : null;
    const next = since ? nextAnniversary(since) : null;
    const places = data.places || [];
    return `<section class="sec" id="stats"><div class="wrap"><div class="stats reveal">
      ${since ? `<div class="stat"><b>${nf.format(together)}</b><span>天在一起</span><small>DAYS</small></div>` : ''}
      <div class="stat"><b>${nf.format(media.length)}</b><span>张照片和视频</span><small>MOMENTS</small></div>
      ${places.length ? `<div class="stat"><b>${places.length}</b><span>个一起去过的地方</span><small>PLACES</small></div>` : `<div class="stat"><b>${months.length}</b><span>个留下回忆的月份</span><small>MONTHS</small></div>`}
      ${next ? `<div class="stat"><b>${next.days}</b><span>${next.days === 0 ? `今天就是 ${next.n} 周年` : `天后是 ${next.n} 周年`}</span><small>ANNIVERSARY</small></div>` : ''}
    </div></div></section>`;
  }

  /* ---------- the moon: how it looked the night we got together, and how it looks tonight ---------- */
  const moon = (() => {
    const rad = Math.PI / 180;
    const sin = (d) => Math.sin(d * rad);
    const cos = (d) => Math.cos(d * rad);
    const jd = (t) => t / DAY + 2440587.5;
    const fromJD = (j) => new Date((j - 2440587.5) * DAY);
    const BJ = 8 * 3600000; // the lunar calendar counts days in Beijing time

    // How much of the moon is lit, and whether it is growing (low precision, well within a percent).
    function at(t) {
      const d = jd(t) - 2451545;
      const M = 357.5291 + 0.98560028 * d;
      const sun = 280.459 + 0.98564736 * d + 1.915 * sin(M) + 0.02 * sin(2 * M);
      const Mm = 134.963 + 13.064993 * d;
      const D = 297.85 + 12.190749 * d;
      const lon = 218.316 + 13.176396 * d + 6.289 * sin(Mm) - 1.274 * sin(Mm - 2 * D) + 0.658 * sin(2 * D) + 0.214 * sin(2 * Mm) - 0.186 * sin(M) - 0.114 * sin(2 * (93.272 + 13.22935 * d));
      const e = (((lon - sun) % 360) + 360) % 360;
      return { lit: (1 - cos(e)) / 2, waxing: e < 180, e };
    }

    // New moon (full = false) or full moon number k counted from January 2000, after Meeus, Astronomical Algorithms ch. 49.
    function phase(k, full) {
      if (full) k += 0.5;
      const T = k / 1236.85;
      const E = 1 - 0.002516 * T - 0.0000074 * T * T;
      const M = 2.5534 + 29.1053567 * k - 0.0000014 * T * T;
      const Mm = 201.5643 + 385.81693528 * k + 0.0107582 * T * T + 0.00001238 * T ** 3;
      const F = 160.7108 + 390.67050284 * k - 0.0016118 * T * T;
      const O = 124.7746 - 1.56375588 * k + 0.0020672 * T * T;
      const c = full ? [-0.40614, 0.17302, 0.01614, 0.01043, 0.00734, -0.00515, 0.00209] : [-0.4072, 0.17241, 0.01608, 0.01039, 0.00739, -0.00514, 0.00208];
      const j = 2451550.09766 + 29.530588861 * k + 0.00015437 * T * T
        + c[0] * sin(Mm) + c[1] * E * sin(M) + c[2] * sin(2 * Mm) + c[3] * sin(2 * F) + c[4] * E * sin(Mm - M) + c[5] * E * sin(Mm + M) + c[6] * E * E * sin(2 * M)
        - 0.00111 * sin(Mm - 2 * F) - 0.00057 * sin(Mm + 2 * F) + 0.00056 * E * sin(2 * Mm + M) - 0.00042 * sin(3 * Mm)
        + 0.00042 * E * sin(M + 2 * F) + 0.00038 * E * sin(M - 2 * F) - 0.00024 * E * sin(2 * Mm - M) - 0.00017 * sin(O)
        - 0.0008; // TT to UT
      return fromJD(j);
    }
    const kNear = (t) => Math.floor((t - Date.UTC(2000, 0, 6, 18, 14)) / (29.530588861 * DAY));
    // The Beijing calendar day of an instant, as a local Date at midnight (what the rest of the site uses).
    const bjDay = (t) => { const b = new Date(t + BJ); return new Date(b.getUTCFullYear(), b.getUTCMonth(), b.getUTCDate()); };

    // Full moons whose Beijing day falls after day a and up to day b (both local midnights).
    function fulls(a, b) {
      const out = [];
      for (let k = kNear(a.getTime()) - 1; ; k += 1) {
        const t = phase(k, true);
        const d = bjDay(t.getTime());
        if (d > b) break;
        if (d > a) out.push(d);
      }
      return out;
    }

    const NUM = ['', '一', '二', '三', '四', '五', '六', '七', '八', '九', '十'];
    const dayName = (n) => (n <= 10 ? `初${NUM[n]}` : n < 20 ? `十${NUM[n - 10]}` : n === 20 ? '二十' : n < 30 ? `廿${NUM[n - 20]}` : '三十');
    let fmt = null;
    try { fmt = new Intl.DateTimeFormat('zh-CN-u-ca-chinese', { timeZone: 'Asia/Shanghai', month: 'long', day: 'numeric' }); } catch (e) { /* no Chinese calendar here */ }
    // "六月廿一": the month from the browser's Chinese calendar when it has one, the day from the new moons.
    function lunar(day) {
      const noon = Date.UTC(day.getFullYear(), day.getMonth(), day.getDate(), 4); // noon in Beijing
      let k = kNear(noon) + 1;
      while (bjDay(phase(k, false).getTime()) > day) k -= 1;
      const n = Math.round((day - bjDay(phase(k, false).getTime())) / DAY) + 1;
      let month = '';
      if (fmt) {
        const parts = fmt.formatToParts(new Date(noon));
        const m = parts.find((x) => x.type === 'month');
        const d = parts.find((x) => x.type === 'day');
        if (m && /月$/.test(m.value) && (!d || Number(d.value) === n)) month = m.value.replace(/^十一月$/, '冬月').replace(/^十二月$/, '腊月');
      }
      return `${month}${dayName(n)}`;
    }

    // Only the night of the full moon is called full; the night before it is still growing.
    function name(m, full) {
      if (full) return '满月';
      if (m.lit < 0.02) return '新月';
      if (Math.abs(m.lit - 0.5) < 0.06) return m.waxing ? '上弦月' : '下弦月';
      if (m.lit < 0.5) return m.waxing ? '蛾眉月' : '残月';
      return m.waxing ? '盈凸月' : '亏凸月';
    }

    // The evening of a day, 9 pm in Beijing.
    const evening = (day) => Date.UTC(day.getFullYear(), day.getMonth(), day.getDate(), 13);

    function svg(m, id) {
      const r = 46;
      const rx = (r * Math.abs(1 - 2 * m.lit)).toFixed(2);
      const lit = `M0 ${-r}A${r} ${r} 0 0 1 0 ${r}A${rx} ${r} 0 0 ${m.lit < 0.5 ? 0 : 1} 0 ${-r}Z`;
      const craters = [[-14, -18, 9], [16, -8, 6], [-4, 14, 11], [22, 20, 5], [-26, 6, 5], [6, -30, 4], [-16, 30, 4], [30, -4, 3.5]];
      return `<svg class="moon-svg" viewBox="-60 -60 120 120" aria-hidden="true">
        <defs>
          <radialGradient id="${id}-g" cx="-.25" cy="-.3" r="1.1"><stop offset="0" stop-color="#fff9f0"/><stop offset=".6" stop-color="#f6e7d4"/><stop offset="1" stop-color="#d8c2ad"/></radialGradient>
          <radialGradient id="${id}-h"><stop offset=".55" stop-color="rgba(255, 236, 214, .32)"/><stop offset="1" stop-color="rgba(255, 236, 214, 0)"/></radialGradient>
          <clipPath id="${id}-c"><path d="${lit}" transform="${m.waxing ? '' : 'scale(-1 1)'}"/></clipPath>
        </defs>
        <circle r="60" fill="url(#${id}-h)" opacity="${(0.25 + m.lit * 0.75).toFixed(2)}"/>
        <circle r="${r}" fill="#1d1820"/>
        <g clip-path="url(#${id}-c)"><circle r="${r}" fill="url(#${id}-g)"/>${craters.map(([x, y, s]) => `<circle cx="${x}" cy="${y}" r="${s}" fill="#c9b19c" opacity=".38"/>`).join('')}</g>
        <circle r="${r}" fill="none" stroke="rgba(255, 240, 225, .14)"/>
      </svg>`;
    }

    return { at, phase, fulls, lunar, name, evening, svg, bjDay };
  })();

  function moonHTML(since) {
    if (!since) return '';
    const today = todayDate();
    const day = (d, k) => new Date(d.getFullYear(), d.getMonth(), d.getDate() + k);
    const fullToday = moon.fulls(day(today, -1), today).length > 0;
    const count = moon.fulls(since, today).length;
    const next = moon.fulls(today, day(today, 40))[0];
    const left = next ? Math.round((next - today) / DAY) : 0;
    const fig = (d, m, id, when, full) => `<figure class="moon-fig${full ? ' full' : ''}">
      ${moon.svg(m, id)}
      <figcaption><small>${fmtDate(d)} · ${when}</small><b>农历${moon.lunar(d)}</b><span>${moon.name(m, full)} · 亮了 ${Math.round(m.lit * 100)}%</span></figcaption>
    </figure>`;
    const then = moon.at(moon.evening(since));
    const now = moon.at(moon.evening(today));
    const n = count + (fullToday ? 0 : 1);
    const line = fullToday ? `今晚就是满月，第 ${count} 次。`
      : left === 1 ? `明天晚上就是第 ${n} 次满月。`
        : next ? `下一次满月在 ${next.getMonth() + 1} 月 ${next.getDate()} 日，还有 ${left} 天。` : '';
    return `<section class="sec moon-sec" id="moon"><div class="wrap">
      <header class="sec-head reveal"><p class="kicker">The moon that night</p><h2>那天的月亮</h2><p class="lead">在一起的那天夜里，天上挂着的就是这样一个月亮。是照着天文算出来的，和那晚真的月亮一样。</p></header>
      <div class="moons reveal">
        ${fig(since, then, 'mn-a', '那天夜里', false)}
        <div class="moon-mid">
          <p><b>${count}</b><span>次月圆</span></p>
          <div class="beads" aria-hidden="true">${Array.from({ length: n }, (_, k) => `<i style="--i:${k}"${k >= count ? ' class="yet"' : ''}></i>`).join('')}</div>
        </div>
        ${fig(today, now, 'mn-b', '今晚', fullToday)}
      </div>
      <p class="moon-line reveal">在一起以后，月亮已经圆了 ${count} 次。${line}</p>
    </div></section>`;
  }

  // Photos from this day in earlier years; failing that, from these few days, or this month.
  function onThisDay() {
    const t = todayDate();
    const y = t.getFullYear();
    const md = `${pad2(t.getMonth() + 1)}-${pad2(t.getDate())}`;
    const past = data.media.filter((m) => m.dq !== 'unknown' && Number(m.date.slice(0, 4)) < y);
    const exact = past.filter((m) => m.dq !== 'approx' && m.date.slice(5, 10) === md);
    if (exact.length) return { title: '那年今天', list: exact };
    const near = past.filter((m) => {
      if (m.dq === 'approx') return false;
      const d = parseDay(m.date);
      return Math.abs(new Date(y, d.getMonth(), d.getDate()) - t) <= 3 * DAY;
    });
    if (near.length) return { title: '那年这几天', list: near };
    const month = past.filter((m) => m.date.slice(5, 7) === md.slice(0, 2));
    if (month.length) return { title: '往年的这个月', list: month };
    return null;
  }

  function todayHTML(days) {
    const t = todayDate();
    const otd = onThisDay();
    let left = '';
    if (otd) {
      sets.otd = otd.list.map((m) => m.id);
      const years = [...new Set(otd.list.map((m) => m.date.slice(0, 4)))].sort().reverse();
      left = `<div class="otd reveal">
        <p class="kicker">On this day · ${pad2(t.getMonth() + 1)}.${pad2(t.getDate())}</p>
        <h2>${otd.title}</h2>
        ${years.map((y) => {
          const list = otd.list.filter((m) => m.date.startsWith(y));
          const when = [...new Set(list.map((m) => (m.dq === 'approx' ? `${Number(m.date.slice(5, 7))} 月` : m.date.slice(5, 10).replace('-', '.'))))];
          return `<div class="otd-year">
            <div class="otd-y"><b>${y}</b><span>${t.getFullYear() - Number(y)} 年前${otd.title === '那年今天' ? '' : ` · ${when.slice(0, 3).join('、')}`}</span></div>
            <div class="otd-strip">${pick(list, 4).map((m) => photoButton(m, { set: 'otd' })).join('')}</div>
          </div>`;
        }).join('')}
      </div>`;
    }
    const right = days.length ? daysCard(days) : '';
    if (!left && !right) return '';
    return `<section class="sec today-sec"><div class="wrap today${left && right ? '' : ' one'}">${left}${right}</div></section>`;
  }

  // The next day that matters, big, and every other one under it.
  function daysCard(days) {
    const [next, ...rest] = days;
    const isBday = (d) => /生日/.test(d.label);
    const sub = (d) => [fmtDate(d.when), d.age ? `${d.age} 岁` : '', esc(d.note)].filter(Boolean).join(' · ');
    return `<div class="soon reveal${isBday(next) ? ' bday' : ''}" id="days">
      <p class="kicker">Days that matter</p>
      <div class="soon-top">
        <div class="soon-n">${next.left === 0 ? '<b>今天</b>' : `<b>${nf.format(next.left)}</b><span>天后</span>`}</div>
        <p class="soon-what">${esc(next.label)}</p>
        <small>${sub(next)}</small>
      </div>
      ${rest.length ? `<ul class="soon-list">${rest.map((d) => `<li class="${isBday(d) ? 'bday' : ''}">
        <span class="sl-l">${esc(d.label)}<small>${sub(d)}</small></span>
        <b>${d.left === 0 ? '今天' : nf.format(d.left)}</b><em>${d.left === 0 ? '' : '天后'}</em>
      </li>`).join('')}</ul>` : ''}
      ${days.some((d) => isBday(d) && d.left > 0) ? '<p class="soon-tease">生日那天打开网站，有个小惊喜。</p>' : ''}
    </div>`;
  }

  function doorsHTML() {
    const doors = pages.slice(1);
    if (!doors.length) return '';
    return `<section class="sec doors-sec"><div class="wrap">
      <header class="sec-head reveal"><p class="kicker">Chapters of us</p><h2>翻开我们的故事</h2></header>
      <div class="doors">${doors.map((p, k) => `<a class="door reveal" href="#/${p.id}" style="--c:${p.cover ? p.cover.c : '#221a24'};transition-delay:${(k % 3) * 0.07}s">
        ${p.cover ? `<span class="lazy door-bg" data-id="${p.cover.id}"><img alt=""></span>` : ''}
        <span class="door-no">${pad2(p.no + 1)}</span><span class="door-ic" aria-hidden="true">${p.icon}</span>
        <b>${p.zh}</b><small>${esc(p.en)}</small>${p.blurb ? `<em${p.id === 'someday' ? ' data-bk-blurb' : ''}>${esc(p.blurb)}</em>` : ''}
      </a>`).join('')}</div>
    </div></section>`;
  }

  /* 02 chapters: our firsts, then the timeline month by month */
  function timeHTML(p, { media, since, months, firsts, favs }) {
    const fan = firsts.map(photoFor).filter(Boolean);
    let html = pageHead(p, since ? `从 ${fmtDate(data.since)} 开始，一个月一个月攒下来的。` : '', {
      facts: [
        ...(since ? [[nf.format(Math.floor((Date.now() - since) / DAY)), '天在一起']] : []),
        [String(months.length), '个月有照片'],
        ...(firsts.length ? [[String(firsts.length), '个第一次']] : []),
      ],
      photos: (fan.length >= 3 ? fan : [...fan, ...favs]).slice(-4),
    });
    html += firstsHTML();
    html += yearlyHTML(since);
    const items = timelineItems(months, withAnniversaries(data.milestones || [], since, media), data.chapters || {});
    if (items.length) {
      let lastYear = null;
      let flip = false;
      html += `<section class="sec" id="timeline"><div class="wrap">
        <header class="sec-head reveal"><p class="kicker">Timeline</p><h2>时间线</h2></header>
        <div class="tl"><i class="tl-fill"></i>`;
      for (const it of items) {
        const y = it.date.slice(0, 4);
        if (y !== lastYear) { html += `<div class="tl-year reveal"><span>${y}</span></div>`; lastYear = y; }
        if (it.kind === 'milestone') {
          html += milestoneHTML(it, flip);
          if (it.ms.photo) flip = !flip;
        } else {
          html += chapterHTML(it, flip);
          flip = !flip;
        }
      }
      html += '</div></div></section>';
    }
    if (data.letter && data.letter.body) {
      const paras = data.letter.body.trim().split(/\n\s*\n/).map((x) => `<p>${esc(x).replace(/\n/g, '<br>')}</p>`).join('');
      html += `<section class="sec letter" id="letter"><div class="paper">
        <svg class="seal" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 21.2s-7.8-4.6-9.9-10C.7 7.6 2.9 3.6 6.8 3.6c2.2 0 3.9 1.2 5.2 3 1.3-1.8 3-3 5.2-3 3.9 0 6.1 4 4.7 7.6-2.1 5.4-9.9 10-9.9 10z"/></svg>
        <p class="kicker">To you</p>
        <h2>${esc(data.letter.title || '写给你')}</h2>
        <div class="letter-body">${paras}</div>
        ${data.letter.sign ? `<p class="sign">${esc(data.letter.sign)}</p>` : ''}
      </div></section>`;
    }
    return html;
  }

  function firstsHTML() {
    const list = (data.firsts || []).filter((f) => f.title);
    if (!list.length) return '';
    const tilt = [-2.4, 1.8, -1.2, 2.6, -1.8, 1.2];
    sets.firsts = [];
    return `<section class="sec firsts-sec"><div class="wrap">
      <header class="sec-head reveal"><p class="kicker">Firsts</p><h2>第一次</h2><p class="lead">那些第一次，一张一张贴在这里。日子按照片里能找到的最早一张来算；换手机丢掉的那些，就记在心里。</p></header>
      <div class="firsts">${list.map((f, i) => {
        const m = photoFor(f);
        if (m) sets.firsts.push(m.id);
        const pl = m && placeOf(m);
        return `<article class="first reveal" style="--r:${tilt[i % tilt.length]}deg;transition-delay:${(i % 3) * 0.08}s"><div class="polaroid">
          <i class="tape" aria-hidden="true"></i>
          ${m ? photoButton(m, { set: 'firsts' }) : `<div class="blank">${HEART}</div>`}
          <span class="d">${f.date ? fmtDate(f.date) : ''}${pl ? ` · ${esc(pl.name)}` : ''}</span>
          <h3>${esc(f.title)}</h3>
          ${f.text ? `<p>${esc(f.text)}</p>` : ''}
        </div></article>`;
      }).join('')}</div>
    </div></section>`;
  }

  // One photo a year, side by side: the favourite taken nearest our anniversary, unless story.json names one.
  function yearlyHTML(since) {
    if (!since) return '';
    const y0 = since.getFullYear();
    const y1 = todayDate().getFullYear();
    if (y1 === y0) return '';
    const pickYear = (y) => {
      const named = data.yearly && data.yearly[y] && byId.get(data.yearly[y]);
      if (named) return named;
      const ann = new Date(y, since.getMonth(), since.getDate());
      const list = data.media.filter((m) => m.type === 'photo' && m.dq !== 'unknown' && m.date.startsWith(String(y)));
      const favs = list.filter((m) => m.fav);
      let best = null;
      (favs.length ? favs : list).forEach((m) => { const d = Math.abs(parseDay(m.date) - ann); if (!best || d < best.d) best = { m, d }; });
      return best && best.m;
    };
    const years = [];
    for (let y = y0; y <= y1; y += 1) years.push([y, pickYear(y)]);
    sets.yearly = years.map(([, m]) => m && m.id).filter(Boolean);
    return `<section class="sec yearly-sec" id="yearly"><div class="wrap">
      <header class="sec-head reveal"><p class="kicker">One a year</p><h2>一年一张</h2><p class="lead">每年挑一张离纪念日最近的合照，并排放着，看看这几年的我们。</p></header>
      <div class="years" style="--n:${years.length}">${years.map(([y, m], k) => {
        const exact = m && m.dq !== 'approx';
        const sub = m ? `<small>${dateLabel(m)}</small>${exact ? `<span>在一起第 ${nf.format(Math.round((parseDay(m.date) - since) / DAY) + 1)} 天</span>` : ''}`
          : `<small>${y === y0 ? fmtDate(since) : ''}</small><span>${y === y0 ? '在一起了' : '这一年的照片还空着'}</span>`;
        return `<figure class="yr reveal" style="transition-delay:${k * 0.09}s">
          <div class="yr-ph">${m ? photoButton(m, { set: 'yearly' }) : `<div class="yr-blank">${HEART}<span>${y === y0 ? '故事从这一年开始' : '还没有照片'}</span></div>`}</div>
          <figcaption><b>${y}</b>${sub}</figcaption>
        </figure>`;
      }).join('')}</div>
    </div></section>`;
  }

  /* 03 places and moments: the map and its trips, then every photo */
  function mapHTML(p, groups, media) {
    const years = [...new Set(media.map((m) => m.date.slice(0, 4)))];
    const trip = journey();
    const km = trip.stops.length > 1 ? Math.round(trip.km) : 0;
    const earth = aroundEarth(km);
    const lead = groups.length
      ? `照片里还留着定位的，整理出 ${groups.length} 个一起去过的地方。${km ? `按时间把它们连起来，一共 ${nf.format(km)} 公里${earth ? `，${earth}` : ''}。` : ''}这只是不完全统计：换过几次手机，很多去过的地方没能留下位置和时间，只剩下照片。再往下，是全部 ${nf.format(media.length)} 个瞬间。`
      : `一共 ${nf.format(media.length)} 个瞬间。点开任意一张，可以左右翻看。`;
    return pageHead(p, lead, {
      facts: [
        ...(groups.length ? [[String(groups.length), '个一起去过的地方']] : []),
        ...(km ? [[nf.format(km), '公里的路']] : [[String(years.length), '个年头']]),
        [nf.format(media.length), '个瞬间'],
      ],
      photos: groups.length >= 4 ? groups.slice(-4).map(tripCover) : media.filter((m) => m.fav).slice(0, 4),
    }) + atlasHTML(groups) + galleryHTML(media, years);
  }

  function galleryHTML(media, years) {
    return `<section class="sec" id="gallery"><div class="wrap">
      <header class="sec-head reveal"><p class="kicker">Moments</p><h2>所有瞬间</h2><p class="lead">一共 ${nf.format(media.length)} 个。点开任意一张，可以左右翻看。</p></header>
      ${years.length > 1 ? `<div class="chips reveal" role="group" aria-label="按年份筛选"><button class="chip" aria-pressed="true" data-year="">全部</button>${years.map((y) => `<button class="chip" aria-pressed="false" data-year="${y}">${y}</button>`).join('')}</div>` : ''}
      <div class="wall" id="wall"></div>
      <div class="wall-more"><button class="btn" id="wall-more" hidden>再看更多</button></div>
    </div></section>`;
  }

  /* 04 someday: a hundred things to do together, and a time capsule */
  const CHECK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>';
  const CLOUD = ic('<path d="M7 18.5h10.5a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.6 9.2 4.7 4.7 0 0 0 7 18.5z"/>');
  const SHARE = ic('<path d="M12 15V4.5M8 8.5l4-4 4 4"/><path d="M5.5 12.5V18a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2v-5.5"/>');
  function somedayHTML(p, things, favs) {
    const facts = [];
    if (things.length) {
      const c = bucket.count();
      facts.push([String(c), '件做过了', 'fact-done'], [String(things.length - c), '件还没做', 'fact-todo']);
    }
    const openOn = capsuleOpenOn();
    if (openOn) {
      const now = new Date();
      now.setHours(0, 0, 0, 0);
      const left = Math.round((openOn - now) / DAY);
      if (left > 0) facts.push([nf.format(left), '天后打开胶囊']);
    }
    const n = things.length === 100 ? '一百' : String(things.length);
    return `${pageHead(p, things.length ? `${n}件想和对方一起做的事，做过的打个勾；还有一个封好的时光胶囊。` : '写给以后的我们。', { facts, photos: favs.slice(-4) })}
      ${bucketHTML(things)}
      ${capsuleHTML()}`;
  }

  function bucketHTML(things) {
    if (!things.length) return '';
    const groups = data.bucket.groups;
    return `<section class="sec bucket-sec" id="bucket"><div class="wrap">
      <header class="bk-head reveal">
        <div class="bk-copy">
          <p class="kicker">Our ${things.length} things</p>
          <h2>情侣要一起做的 ${things.length} 件事</h2>
          <p class="lead">做过的，点一下打个勾，它就会暗下去；还亮着的，是接下来要一起去做的。</p>
          <button class="bk-sync" id="bk-sync" type="button" data-s="off">${CLOUD}<span>开启自动同步</span></button>
        </div>
        <div class="bk-meter">
          <svg viewBox="0 0 120 120" aria-hidden="true">
            <defs><linearGradient id="bk-grad" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffd1dc"/><stop offset=".5" stop-color="#ff7d9c"/><stop offset="1" stop-color="#ffb68c"/></linearGradient></defs>
            <circle class="bk-track" cx="60" cy="60" r="52"/><circle class="bk-arc" id="bk-arc" cx="60" cy="60" r="52" pathLength="100"/>
          </svg>
          <div class="bk-num"><b id="bk-done">0</b><span>/ ${things.length}</span></div>
        </div>
      </header>
      <div class="bk-bar">
        <div class="bk-filter" role="group" aria-label="筛选">
          <button type="button" data-f="" aria-pressed="true">全部</button><button type="button" data-f="todo" aria-pressed="false">还没做</button><button type="button" data-f="done" aria-pressed="false">做过了</button>
        </div>
        <button class="bk-share" id="bk-share" type="button">${SHARE}<span>同步给 TA</span></button>
      </div>
      <div class="bk-groups" id="bk-groups" data-f="">${groups.map((g, gi) => `<section class="bk-group reveal" style="transition-delay:${(gi % 2) * 0.06}s">
        <header class="bk-gh"><span class="bk-gn">${pad2(gi + 1)}</span><h3>${esc(g.t)}</h3>${g.en ? `<small>${esc(g.en)}</small>` : ''}<em data-bk-g="${gi}" data-of="${g.items.length}">0/${g.items.length}</em></header>
        <ol class="bk-list">${things.filter((x) => x.gi === gi).map((x) => `<li><button class="bk-item" type="button" data-n="${x.n}" data-g="${gi}" aria-pressed="false">
          <span class="bk-no">${String(x.n).padStart(3, '0')}</span><span class="bk-t">${esc(x.t)}<small class="bk-d"></small></span><span class="bk-box">${CHECK}</span>
        </button></li>`).join('')}</ol>
      </section>`).join('')}</div>
      <p class="bk-note">开启自动同步后，打的勾会在每一台连上的手机和电脑之间自动同步。还没连上的设备，点「同步给 TA」把链接发过去，打开一次就连上了。</p>
      <dialog class="sync-dlg" id="sync-dlg" aria-labelledby="sync-h">
        <form method="dialog" class="sync-card">
          <h3 id="sync-h">自动同步</h3>
          <div class="sync-off">
            <p>打的勾会加密以后，存进你 GitHub 账号里的一个私密 Gist。连上的手机和电脑都会自动同步，别人看不懂内容。</p>
            <p>只要在一台设备上设置一次：</p>
            <ol>
              <li>点下面的按钮去 GitHub，Expiration 选 <b>No expiration</b>，拉到底点 <b>Generate token</b>。</li>
              <li>复制生成的口令（ghp_ 开头），粘贴到这里，点「连上」。</li>
              <li>再点「同步给 TA」，把链接发到其他手机和电脑，打开一次就都连上了。</li>
            </ol>
            <a class="sync-gh" href="https://github.com/settings/tokens/new?scopes=gist&amp;description=Our%20Story%20sync" target="_blank" rel="noopener">去 GitHub 生成口令</a>
            <label class="sr-only" for="sync-token">同步口令</label>
            <input id="sync-token" type="password" autocomplete="off" spellcheck="false" autocapitalize="off" placeholder="粘贴 ghp_ 开头的口令">
            <p class="sync-msg" id="sync-msg" role="alert"></p>
            <div class="sync-row"><button type="button" class="sync-go" id="sync-go">连上</button><button value="close" class="sync-x">取消</button></div>
          </div>
          <div class="sync-on">
            <p>这台设备已经连上自动同步。<span id="sync-when"></span></p>
            <p>还没连上的设备：点「同步给 TA」，把链接发过去，打开一次就连上了。</p>
            <div class="sync-row"><button type="button" class="sync-go" id="sync-now">现在同步</button><button type="button" class="sync-x" id="sync-off">断开这台设备</button><button value="close" class="sync-x">关闭</button></div>
          </div>
        </form>
      </dialog>
    </div></section>`;
  }

  // The capsule opens on its own date, or on our fifth anniversary.
  function capsuleOpenOn() {
    const cap = data.capsule;
    const since = data.since ? parseDay(data.since) : null;
    if (!cap) return null;
    return cap.open ? parseDay(cap.open) : since ? new Date(since.getFullYear() + 5, since.getMonth(), since.getDate()) : null;
  }

  function capsuleHTML() {
    const cap = data.capsule;
    const since = data.since ? parseDay(data.since) : null;
    const openOn = capsuleOpenOn();
    if (!openOn) return '';
    // The real date, never a preview date: the capsule opens when it opens.
    const now = new Date();
    now.setHours(0, 0, 0, 0);
    const left = Math.round((openOn - now) / DAY);
    const letters = (cap.letters || []).filter((l) => l.text);
    const n = since ? openOn.getFullYear() - since.getFullYear() : 0;
    const open = left <= 0 && letters.length > 0;
    return `<section class="sec capsule-sec"><div class="wrap">
      <header class="sec-head reveal"><p class="kicker">Time capsule</p><h2>时光胶囊</h2></header>
      <div class="capsule reveal${open ? ' can-open' : ''}" id="capsule">
        <button class="envelope" type="button"${open ? '' : ' disabled'} aria-label="${open ? '拆开胶囊' : '还没到打开的时候'}">
          <span class="env-back"></span><span class="env-paper"></span><span class="env-front"></span><span class="env-flap"></span>
          <span class="wax">${sealSVG('is-wax') || HEART}</span>
        </button>
        <div class="capsule-copy">
          <div class="capsule-n">${left > 0 ? `<b>${nf.format(left)}</b><span>天后开启</span>` : '<b>今天</b><span>可以打开了</span>'}</div>
          <p class="capsule-when">${fmtDate(openOn)}${n ? ` · 在一起 ${n} 周年那天` : ''}</p>
          <p class="capsule-note">${letters.length ? `里面封着 ${letters.length} 封信，${left > 0 ? '到那天才能拆开。' : '点信封拆开。'}` : '胶囊还空着。你们可以各写一段话放进来，到那天才能打开。'}</p>
        </div>
      </div>
      ${open ? `<div class="letters" id="letters" hidden>${letters.map((l) => `<article class="cap-letter">${l.from ? `<p class="kicker">${esc(l.from)}</p>` : ''}${l.text.trim().split(/\n\s*\n/).map((x) => `<p>${esc(x)}</p>`).join('')}</article>`).join('')}</div>` : ''}
    </div></section>`;
  }
  function setupCapsule() {
    const env = $('#capsule .envelope');
    if (!env || env.disabled) return;
    env.addEventListener('click', () => {
      $('#capsule').classList.add('opened');
      const l = $('#letters');
      if (l && l.hidden) { setTimeout(() => { l.hidden = false; l.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 900); confetti(90); }
    });
  }


  function toast(msg) {
    let t = $('#toast');
    if (!t) {
      document.body.insertAdjacentHTML('beforeend', '<div class="toast" id="toast" role="status" aria-live="polite"></div>');
      t = $('#toast');
    }
    t.textContent = msg;
    t.classList.add('on');
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => t.classList.remove('on'), 2800);
  }

  /* ---------- the 100 things: ticks stay on each device and travel between the two of us by link ---------- */
  const bucket = (() => {
    const LS = 'ourstory.bucket.v1';
    const EPOCH = Date.UTC(2023, 0, 1) / 60000; // ticks are stamped in minutes from here
    let state = null; // number -> [done 0/1, minute]
    let list = [];
    const load = () => {
      if (state) return;
      try { state = JSON.parse(localStorage.getItem(LS)) || {}; } catch (e) { state = {}; }
    };
    const save = () => { try { localStorage.setItem(LS, JSON.stringify(state)); } catch (e) { /* private mode */ } };
    const done = (n) => !!(state[n] && state[n][0]);
    const count = () => list.filter((x) => done(x.n)).length;
    const minute = () => Math.floor(Date.now() / 60000 - EPOCH);
    // In a link every tick is 8 base-36 characters: the number (2), done or not (1), and when (5).
    const b36 = (v, w) => Math.max(0, v).toString(36).padStart(w, '0').slice(-w);
    const encode = () => Object.keys(state).map((n) => b36(Number(n), 2) + (state[n][0] ? 1 : 0) + b36(state[n][1], 5)).join('');
    const decode = (code) => {
      const out = {};
      for (let i = 0; i + 8 <= code.length; i += 8) {
        const n = parseInt(code.slice(i, i + 2), 36);
        const t = parseInt(code.slice(i + 3, i + 8), 36);
        if (n > 0 && Number.isFinite(t)) out[n] = [code[i + 2] === '1' ? 1 : 0, t];
      }
      return out;
    };
    // Whoever ticked (or unticked) a thing last wins; in the same minute, ticked wins, so every device settles on the same answer.
    const newer = (a, b) => !b || a[1] > b[1] || (a[1] === b[1] && a[0] > b[0]);
    function merge(other) {
      let gained = 0;
      for (const [n, e] of Object.entries(other)) {
        if (!newer(e, state[n])) continue;
        if (e[0] && !done(n)) gained += 1;
        state[n] = e;
      }
      save();
      return gained;
    }

    function items() {
      load();
      list = [];
      ((data.bucket && data.bucket.groups) || []).forEach((g, gi) => g.items.forEach((t) => list.push({ n: list.length + 1, t, gi })));
      return list;
    }

    function paint() {
      const root = $('#bk-groups');
      if (!root) return;
      const per = {};
      root.querySelectorAll('.bk-item').forEach((el) => {
        const n = Number(el.dataset.n);
        const d = done(n);
        el.classList.toggle('done', d);
        el.parentElement.classList.toggle('done', d);
        el.setAttribute('aria-pressed', String(d));
        el.querySelector('.bk-d').textContent = d ? `${fmtDate(new Date((state[n][1] + EPOCH) * 60000))} 做到了` : '';
        if (d) per[el.dataset.g] = (per[el.dataset.g] || 0) + 1;
      });
      root.querySelectorAll('[data-bk-g]').forEach((e) => { e.textContent = `${per[e.dataset.bkG] || 0}/${e.dataset.of}`; });
      const c = count();
      const put = (sel, v) => { const e = $(sel); if (e) e.textContent = v; };
      put('#bk-done', c);
      put('#fact-done', c);
      put('#fact-todo', list.length - c);
      put('[data-bk-blurb]', `${list.length} 件事做了 ${c} 件 · 时光胶囊`);
      const arc = $('#bk-arc');
      if (arc) {
        arc.style.strokeDasharray = `${((c / list.length) * 100).toFixed(2)} 100`;
        arc.style.opacity = c ? 1 : 0; // a round cap would leave a dot at zero
      }
    }

    async function share() {
      const join = await cloud.invite();
      const url = `${location.origin}${location.pathname}#/someday?t=${encode()}${join ? `&k=${join}` : ''}`;
      try {
        if (navigator.share) { await navigator.share({ title: '我们的 100 件事', text: `我打了 ${count()} 个勾，点开同步一下`, url }); return; }
      } catch (e) {
        if (e.name === 'AbortError') return;
      }
      try {
        await navigator.clipboard.writeText(url);
        toast('链接复制好了，发给 TA 吧');
      } catch (e) {
        window.prompt('复制这个链接，发给 TA：', url);
      }
    }

    function setup() {
      const root = $('#bk-groups');
      if (!root) return;
      // Opened from a link the other one sent: fold their ticks into ours.
      const link = /[?&]t=([0-9a-z]+)/.exec(location.hash);
      const join = /[?&]k=([A-Za-z0-9_-]+)/.exec(location.hash);
      if (join) cloud.accept(join[1]);
      if (link) {
        const gained = merge(decode(link[1]));
        history.replaceState(null, '', `${location.pathname}${location.search}#/someday`);
        const say = () => (story.hidden ? setTimeout(say, 600) : toast(gained ? `和 TA 的勾合在一起了，多了 ${gained} 个勾` : '两边的勾已经一样了'));
        setTimeout(say, 1200);
      }
      paint();
      root.addEventListener('click', (e) => {
        const el = e.target.closest('.bk-item');
        if (!el) return;
        const n = Number(el.dataset.n);
        const v = done(n) ? 0 : 1;
        state[n] = [v, Math.max(minute(), state[n] ? state[n][1] + 1 : 0)]; // a change always outranks the one before it
        save();
        paint();
        cloud.soon();
        el.classList.remove('pop');
        void el.offsetWidth;
        el.classList.add('pop');
        if (!v) return;
        const r = el.querySelector('.bk-box').getBoundingClientRect();
        sprinkle(r.left + r.width / 2, r.top + r.height / 2, 6);
        const c = count();
        if (c === list.length) { confetti(260); toast(`${list.length} 件事，全都一起做到了！`); } else if (c % 10 === 0) { confetti(120); toast(`第 ${c} 件！`); }
      });
      document.querySelectorAll('.bk-filter button').forEach((b) => b.addEventListener('click', () => {
        document.querySelectorAll('.bk-filter button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
        root.dataset.f = b.dataset.f;
      }));
      $('#bk-share').addEventListener('click', share);
      cloud.setup();
      // Ticked in another tab on this device.
      addEventListener('storage', (e) => { if (e.key === LS) { state = null; load(); paint(); } });
    }

    // From the synced copy: fold its ticks in; and whether ours has anything it lacks.
    function absorb(other) { load(); const gained = merge(other); paint(); return gained; }
    const ahead = (other) => { load(); return Object.keys(state).some((n) => newer(state[n], other[n])); };
    const snapshot = () => { load(); return { ...state }; };

    return { items, count: () => { load(); return count(); }, setup, absorb, ahead, snapshot };
  })();

  /* ---------- the 100 things, synced: a sealed copy in a private gist that every connected device reads and writes ---------- */
  // The token is one the owner made for this (gist access only) and pasted in, or received sealed in a 同步给 TA link.
  // It stays in this device's storage and is only ever sent to api.github.com.
  const cloud = (() => {
    const LS = 'ourstory.sync.v1';
    const FILE = 'our-story-100.bin';
    const API = 'https://api.github.com';
    let cfg = null; // { t: token, g: gist id }
    let busy = null;
    let again = false;
    let timer = 0;
    let last = 0;
    let shown = 'off';
    const conf = () => {
      if (!cfg) { try { cfg = JSON.parse(localStorage.getItem(LS)) || {}; } catch (e) { cfg = {}; } }
      return cfg;
    };
    const keep = () => { try { localStorage.setItem(LS, JSON.stringify(cfg)); } catch (e) { /* private mode */ } };
    const on = () => !!conf().t;

    async function gh(path, opts = {}) {
      const r = await fetch(API + path, {
        ...opts,
        cache: 'no-store',
        headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${conf().t}`, ...(opts.body ? { 'Content-Type': 'application/json' } : {}) },
      });
      if (!r.ok) { const e = new Error(`GitHub ${r.status}`); e.code = r.status; throw e; }
      return r.json();
    }
    async function sealJSON(obj) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj))));
      const u = new Uint8Array(12 + ct.length);
      u.set(iv);
      u.set(ct, 12);
      return toB64(u);
    }
    const openJSON = async (b64) => JSON.parse(new TextDecoder().decode(await decrypt(key, fromB64(b64.trim()))));
    const url64 = (b64) => b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const from64 = (u) => u.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((u.length + 3) % 4);

    // Our gist: the one remembered, else the one holding our file, else a new one.
    async function gist() {
      const c = conf();
      if (c.g) {
        try { return await gh(`/gists/${c.g}`); } catch (e) { if (e.code !== 404) throw e; c.g = ''; }
      }
      for (let page = 1; page <= 5; page += 1) {
        const list = await gh(`/gists?per_page=100&page=${page}`);
        const hit = list.find((x) => x.files && x.files[FILE]);
        if (hit) { c.g = hit.id; keep(); return gh(`/gists/${hit.id}`); }
        if (list.length < 100) break;
      }
      const made = await gh('/gists', {
        method: 'POST',
        body: JSON.stringify({ description: 'Our Story · 100 件事的加密同步（请勿删除）', public: false, files: { [FILE]: { content: await sealJSON({ v: 1, s: {} }) } } }),
      });
      c.g = made.id;
      keep();
      return made;
    }

    async function round() {
      const g = await gist();
      const f = g.files && g.files[FILE];
      let theirs = {};
      if (f && f.content) { try { theirs = (await openJSON(f.content)).s || {}; } catch (e) { theirs = {}; } }
      const gained = bucket.absorb(theirs);
      if (bucket.ahead(theirs)) {
        await gh(`/gists/${g.id}`, { method: 'PATCH', body: JSON.stringify({ files: { [FILE]: { content: await sealJSON({ v: 1, s: bucket.snapshot() }) } } }) });
      }
      return gained;
    }

    function sync() {
      if (!on() || !key) return Promise.resolve();
      if (busy) { again = true; return busy; }
      show('busy');
      busy = (async () => {
        try {
          const gained = await round();
          last = Date.now();
          show('on');
          if (gained && $('#bk-groups')) toast(`从另一台设备同步来 ${gained} 个勾`);
        } catch (e) {
          show(e.code === 401 ? 'bad' : 'error');
        }
        busy = null;
        if (again) { again = false; sync(); }
      })();
      return busy;
    }
    const soon = () => { clearTimeout(timer); timer = setTimeout(sync, 1200); };

    const LABEL = { off: '开启自动同步', busy: '正在同步…', on: '已自动同步', error: '这会儿没连上，稍后自动重试', bad: '同步口令失效了，点这里重新设置' };
    function show(s) {
      shown = s;
      const b = $('#bk-sync');
      if (b) { b.dataset.s = s; b.querySelector('span').textContent = LABEL[s]; }
      const w = $('#sync-when');
      if (w) w.textContent = last ? `上次同步：${new Date(last).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })}` : '';
    }

    // For a 同步给 TA link: the token, sealed with our key, so the other device joins by opening it once.
    async function invite() {
      if (!on() || !key) return '';
      try { return url64(await sealJSON({ t: conf().t, g: conf().g || '' })); } catch (e) { return ''; }
    }
    async function accept(code) {
      try {
        const got = await openJSON(from64(code));
        if (!got.t) return;
        const fresh = got.t !== conf().t;
        cfg = { t: got.t, g: got.g || '' };
        keep();
        await sync();
        if (fresh && shown === 'on') setTimeout(() => toast('这台设备也连上自动同步了'), 2600);
      } catch (e) { /* not ours, or broken on the way */ }
    }

    function setup() {
      const b = $('#bk-sync');
      const dlg = $('#sync-dlg');
      if (!b || !dlg) return;
      show(on() ? (shown === 'off' ? 'on' : shown) : 'off');
      const msg = $('#sync-msg');
      b.addEventListener('click', () => {
        dlg.classList.toggle('is-on', on() && shown !== 'bad');
        msg.textContent = '';
        show(shown);
        if (dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', '');
      });
      $('#sync-go').addEventListener('click', async () => {
        const t = $('#sync-token').value.trim();
        if (!/^(ghp_|github_pat_)\w{20,}$/.test(t)) { msg.textContent = '这不像 GitHub 口令，应该是 ghp_ 开头的一长串。'; return; }
        cfg = { t, g: '' };
        keep();
        msg.textContent = '正在连接…';
        await sync();
        if (shown === 'on') {
          $('#sync-token').value = '';
          dlg.close();
          toast('连上了！再点「同步给 TA」，把其他设备也连上');
        } else {
          msg.textContent = shown === 'bad' ? '口令不对或已失效，再检查一下。' : '暂时连不上 GitHub，稍后再试。';
          if (shown === 'bad') { cfg = {}; keep(); show('off'); }
        }
      });
      $('#sync-now').addEventListener('click', () => { sync(); });
      $('#sync-off').addEventListener('click', () => {
        cfg = {};
        keep();
        show('off');
        dlg.close();
        toast('这台设备不再自动同步，勾还留在这里');
      });
    }

    // Catch up when the site opens, when it comes back to the front, and every minute while it is open.
    document.addEventListener('visibilitychange', () => { if (!document.hidden) sync(); });
    setInterval(() => { if (!document.hidden) sync(); }, 60000);
    addEventListener('storage', (e) => { if (e.key === LS) { cfg = null; show(on() ? 'on' : 'off'); } });

    return { sync, soon, invite, accept, setup };
  })();


  /* ---------- page routing: #/time, #/map, #/someday ---------- */
  let current = null;
  let tapAt = null;
  addEventListener('pointerdown', (e) => { tapAt = [e.clientX, e.clientY]; }, { passive: true, capture: true });
  // Pages that were folded into others still open where their content now lives.
  const MOVED = { moments: ['map', 'gallery'], days: ['', 'days'] };
  function route() {
    const m = /^#\/([\w-]*)/.exec(location.hash);
    const moved = MOVED[m ? m[1] : ''];
    const id = moved ? moved[0] : m ? m[1] : '';
    const page = pages.find((p) => p.id === id) || pages[0];
    const jump = () => { if (moved) setTimeout(() => document.getElementById(moved[1])?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 150); };
    if (!page) return;
    if (page.id === current) { jump(); return; }
    const prev = current == null ? null : story.querySelector(`.page[data-page="${current}"]`);
    const next = story.querySelector(`.page[data-page="${page.id}"]`);
    current = page.id;
    document.querySelectorAll('#nav a').forEach((a) => {
      if (a.dataset.page === page.id) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    document.title = page.id ? `${page.zh} · ${baseTitle}` : baseTitle;
    const show = () => {
      if (prev) { prev.hidden = true; prev.classList.remove('leaving'); }
      next.hidden = false;
      scrollTo(0, 0);
      jump();
      if (!prev || reduceMotion) return;
      next.classList.add('entering');
      void next.offsetWidth;
      next.classList.remove('entering');
    };
    if (prev && !reduceMotion && !story.hidden) {
      prev.classList.add('leaving');
      veil();
      setTimeout(show, 360);
    } else show();
  }
  addEventListener('hashchange', route);
  // A soft rose light blooms from where you tapped while the page turns.
  function veil() {
    const v = $('#veil');
    if (!v) return;
    const [x, y] = tapAt || [innerWidth / 2, innerHeight / 2];
    v.style.setProperty('--x', `${x}px`);
    v.style.setProperty('--y', `${y}px`);
    v.classList.remove('on');
    void v.offsetWidth;
    v.classList.add('on');
  }

  function sealHTML() {
    if (!hasSeal()) return '';
    const sl = data.seal;
    const [c1, c2] = sl.chars || [];
    const [f1, f2] = sl.from || [];
    return `<section class="sec" id="seal"><div class="wrap seal-sec">
      <div class="seal-stage reveal">
        <button class="seal-big" type="button" aria-label="再盖一次">${sealSVG('is-big')}</button>
        <p class="seal-hint">点一下，再盖一次</p>
      </div>
      <div class="seal-copy">
        <header class="sec-head reveal"><p class="kicker">Our seal</p><h2>${esc(sl.word || '')}</h2></header>
        ${c1 && c2 ? `<div class="eq reveal">
          <span class="g"><b>${esc(c1)}</b><small>${esc(f1 || '')}</small></span><i>+</i>
          <span class="g"><b>${esc(c2)}</b><small>${esc(f2 || '')}</small></span><i>=</i>
          <span class="g word"><b>${esc(sl.word || '')}</b><small>${esc(sl.say || '')}</small></span>
        </div>` : ''}
        ${sl.text ? `<p class="seal-text reveal">${esc(sl.text)}</p>` : ''}
        ${music.has() ? songHTML(data.music) : ''}
      </div>
    </div></section>`;
  }

  function songHTML(mu) {
    const notes = mu.notes || [];
    return `<div class="song reveal" id="song">
      <div class="song-head">
        <button class="song-play" id="song-play" type="button" aria-label="播放《${esc(mu.title)}》">${PLAY}${PAUSE}</button>
        <div class="song-meta"><p class="kicker">Our song</p><b>《${esc(mu.title)}》</b><span>${esc(mu.sub || '')}</span></div>
      </div>
      <div class="song-track">
        <div class="song-bar" id="song-bar"><i></i>${notes.map((n) => `<b style="left:${((n.t / mu.dur) * 100).toFixed(2)}%"></b>`).join('')}</div>
        <span class="song-time" id="song-time">0:00 / ${clock(mu.dur)}</span>
      </div>
      ${mu.about ? `<p class="song-about">${esc(mu.about)}</p>` : ''}
      <ol class="song-notes">${notes.map((n) => `<li><button type="button" data-t="${n.t}">
        <span class="at">${clock(n.t)}</span><span class="tt">${esc(n.title)}</span><span class="tx">${esc(n.text)}</span>
      </button></li>`).join('')}</ol>
      ${mu.credit ? `<p class="song-credit">${esc(mu.credit)}</p>` : ''}
    </div>`;
  }

  /* The seal in the corner and the music button stay put while the page scrolls. */
  function chrome() {
    if (hasSeal() && !$('#brand')) {
      document.body.insertAdjacentHTML('afterbegin', SEAL_DEFS);
      document.body.insertAdjacentHTML('beforeend', `<a class="brand" id="brand" href="#/" aria-label="${esc(data.seal.word || '回到开头')}">${sealSVG('is-corner')}</a>`);
      const b = $('#brand');
      if (finePointer) b.addEventListener('mouseenter', () => playSeal(b.querySelector('svg'), 0.45));
    }
    if (pages.length > 1 && !$('#nav')) {
      document.body.insertAdjacentHTML('beforeend', `<nav class="nav" id="nav" aria-label="页面" style="--n:${pages.length}">${pages.map((p) => `<a href="#/${p.id}" data-page="${p.id}">
        <span class="ic" aria-hidden="true">${p.icon}</span><span class="nl">${p.zh}</span></a>`).join('')}</nav><div class="veil" id="veil" aria-hidden="true"></div>`);
      // Tapping the page you are on takes you back to its top.
      document.querySelectorAll('#nav a, #brand').forEach((a) => a.addEventListener('click', () => {
        if ((a.dataset.page ?? '') === current) scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' });
      }));
    }
    if (!$('#miss-btn')) {
      document.body.insertAdjacentHTML('beforeend', `<button class="miss-btn" id="miss-btn" type="button" aria-label="想你了，点一下">${HEART}<span>想你</span></button>`);
      $('#miss-btn').addEventListener('click', () => missYou.open());
    }
    if (music.has() && !$('#music-btn')) {
      document.body.insertAdjacentHTML('beforeend', `<button class="music-btn" id="music-btn" type="button" aria-pressed="false" aria-label="播放音乐">
        <span class="bars" aria-hidden="true"><i></i><i></i><i></i><i></i></span><span class="music-tip">点一下，听《${esc(data.music.title)}》</span></button>`);
      $('#music-btn').addEventListener('click', () => music.toggle());
    }
    const big = $('.seal-big');
    if (big) big.addEventListener('click', () => playSeal(big.querySelector('svg')));
    const sp = $('#song-play');
    if (sp) sp.addEventListener('click', () => music.toggle());
    const bar = $('#song-bar');
    if (bar) {
      bar.addEventListener('click', (e) => {
        const r = bar.getBoundingClientRect();
        music.unlock();
        music.play(Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)) * data.music.dur);
      });
    }
    document.querySelectorAll('.song-notes button').forEach((b) => b.addEventListener('click', () => {
      music.unlock();
      music.play(Number(b.dataset.t));
    }));
  }

  function groupByMonth(media) {
    const map = new Map();
    for (const m of media) {
      if (m.dq === 'unknown') continue; // no real shooting date: photo wall only
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
    const where = [...new Set(it.list.map((m) => m.p).filter((p) => p != null))].map((p) => data.places[p].name);
    return `<article class="tl-item chapter reveal${flip ? ' flip' : ''}">
      <div class="tl-text">
        <div class="tl-date">${y} · ${String(mo).padStart(2, '0')}</div>
        <h3 class="tl-title">${esc(title)}</h3>
        ${where.length ? `<div class="tl-places">${where.map((n) => `<span>${esc(n)}</span>`).join('')}</div>` : ''}
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
    return `<article class="tl-item milestone reveal${m ? (flip ? ' flip' : '') : ' solo'}">
      <div class="tl-text">
        <div class="tl-date">${fmtDate(ms.date)}</div>
        <h3 class="tl-title">${esc(ms.title || '')}</h3>
        ${ms.text ? `<p class="tl-body">${esc(ms.text)}</p>` : ''}
      </div>
      ${m ? `<div class="tl-media"><div class="collage n1">${photoButton(m, { set: 'all' })}</div></div>` : ''}
    </article>`;
  }

  function nextAnniversary(since) {
    const today = todayDate();
    let n = today.getFullYear() - since.getFullYear();
    let when = new Date(since.getFullYear() + n, since.getMonth(), since.getDate());
    if (when < today) { n += 1; when = new Date(since.getFullYear() + n, since.getMonth(), since.getDate()); }
    if (n < 1) { n = 1; when = new Date(since.getFullYear() + 1, since.getMonth(), since.getDate()); }
    return { n, when, days: Math.round((when - today) / DAY) };
  }

  function specialDays(since, extra) {
    const today = todayDate();
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
      let when = null;
      let age = null;
      if (d.dates) {
        // Lunar dates arrive already converted, one per year.
        const next = d.dates.find((x) => parseDay(x.d) >= today);
        if (next) { when = parseDay(next.d); age = next.age ?? null; }
      } else if (d.date) {
        const parts = d.date.split('-').map(Number);
        if (parts.length === 2) {
          when = new Date(today.getFullYear(), parts[0] - 1, parts[1]);
          if (when < today) when = new Date(today.getFullYear() + 1, parts[0] - 1, parts[1]);
          if (d.born) age = when.getFullYear() - d.born;
        } else {
          when = new Date(parts[0], parts[1] - 1, parts[2]);
          if (when < today) when = null;
        }
      }
      if (!when) continue;
      out.push({ label: d.label, when, left: Math.round((when - today) / DAY), age, note: d.note || '' });
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
  const observeImages = (root) => root.querySelectorAll('.ph:not([data-seen]), .lazy:not([data-seen])').forEach((el) => { el.dataset.seen = '1'; imgObserver.observe(el); });

  /* ---------- reveal + timeline progress ---------- */
  function startReveal() {
    const ro = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) { e.target.classList.add('in'); ro.unobserve(e.target); }
    }, { rootMargin: '0px 0px -8% 0px' });
    story.querySelectorAll('.reveal, .paper').forEach((el) => ro.observe(el));
    const stamp = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        stamp.unobserve(e.target);
        e.target.classList.add('drawn');
        playSeal(e.target.querySelector('.seal-mark'), e.target.classList.contains('foot-seal') ? 0.55 : 1);
      }
    }, { threshold: 0.45 });
    story.querySelectorAll('.seal-stage, .foot-seal').forEach((el) => stamp.observe(el));
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
    music.duck(false);
    if (lastFocus) lastFocus.focus({ preventScroll: true });
  }
  function show(i) {
    lbIndex = (i + lbSet.length) % lbSet.length;
    const m = byId.get(lbSet[lbIndex]);
    $('#lb-n').textContent = `${lbIndex + 1} / ${lbSet.length}`;
    $('#lb-date').textContent = [dateLabel(m), placeOf(m) && placeOf(m).name].filter(Boolean).join(' · ');
    $('#lb-text').textContent = m.cap || '';
    stage.innerHTML = '<img alt="" class="ghost">';
    const ghost = stage.querySelector('img');
    blobURL(m.id, 'image/webp', true).then((u) => { if (lbSet[lbIndex] === m.id) ghost.src = u; }).catch(() => {});
    const full = m.type === 'video' ? blobURL(m.v, 'video/mp4', true) : blobURL(m.l, 'image/webp', true);
    full.then((u) => {
      if (lbSet[lbIndex] !== m.id) return;
      if (m.type === 'video') {
        stage.innerHTML = `<video src="${u}" controls playsinline autoplay></video>`;
        stage.querySelector('video').addEventListener('play', () => music.duck(true));
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

  /* ---------- anniversaries on the timeline ---------- */
  function withAnniversaries(milestones, since, media) {
    if (!since) return milestones;
    const out = milestones.slice();
    const have = new Set(out.map((ms) => ms.date));
    const today = todayDate();
    for (let n = 1; ; n += 1) {
      const d = new Date(since.getFullYear() + n, since.getMonth(), since.getDate());
      if (d > today) break;
      const key = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
      if (have.has(key)) continue;
      const that = media.filter((m) => m.dq === 'exif' && m.date.startsWith(key));
      const photo = (that.find((m) => m.fav) || that[0] || {}).id || null;
      out.push({ date: key, title: `在一起 ${n} 周年`, text: '', photo });
    }
    return out;
  }

  /* ---------- hero: a slow slideshow of the photos picked in story.json ---------- */
  // A photo that suits the screen fills it alone. The others share a slide: portraits side by side
  // on a wide screen, landscapes stacked above the names on a phone, so each one is seen whole.
  // One left without a partner stands beside the names on a wide screen, or above them on a phone.
  const hero = (() => {
    let picks = [];
    let slides = [];
    let wide = true;
    let idx = 0;
    let layers = [];
    let timer = 0;
    let started = false;
    let visible = true;
    const HOLD = 6500;
    const ar = (m) => m.w / m.h;
    // Side by side, a group is as wide as its photos' widths added up; stacked, as tall as their heights.
    const shapeOf = (list, stack) => (stack ? 1 / list.reduce((n, m) => n + 1 / ar(m), 0) : list.reduce((n, m) => n + ar(m), 0));

    function plan() {
      const ids = data.hero && data.hero.length ? data.hero : data.cover ? [data.cover] : [];
      picks = ids.map((id) => byId.get(id)).filter(Boolean);
      if (!picks.length && data.media.length) picks = [data.media[0]];
      wide = innerWidth >= innerHeight;
      const stack = !wide;
      const target = wide ? innerWidth / innerHeight : innerWidth / (innerHeight * 0.7);
      const alone = (m) => (wide ? ar(m) >= 1.15 : ar(m) <= 0.9);
      const used = new Set();
      slides = [];
      picks.forEach((m, i) => {
        if (used.has(i)) return;
        used.add(i);
        const list = [m];
        if (!alone(m)) {
          // Pull in the next photos that would not fit alone either.
          for (let j = i + 1; j < picks.length && list.length < 3; j += 1) {
            const n = picks[j];
            if (alone(n) || used.has(j)) continue;
            if (Math.abs(shapeOf([...list, n], stack) - target) >= Math.abs(shapeOf(list, stack) - target)) break;
            list.push(n);
            used.add(j);
          }
        }
        slides.push({ list, stack: stack && !alone(m), side: !stack && !alone(m) && list.length === 1 });
      });
    }
    const urls = (s) => Promise.all(s.list.map((m) => blobURL(m.l, 'image/webp', true)));
    function fill(el, s, us) {
      const h = s.stack ? Math.min(innerHeight * 0.7, innerWidth / shapeOf(s.list, true)) : 0;
      const w = s.side ? Math.min(innerWidth * 0.62, innerHeight * ar(s.list[0])) : 0;
      // Each photo gets room in proportion to its shape, so it is barely cropped, if at all.
      const room = s.list.map((m) => (s.stack ? 1 / ar(m) : ar(m)));
      const sum = room.reduce((x, y) => x + y, 0);
      const size = h ? ` style="height:${Math.round(h)}px"` : w ? ` style="width:${Math.round(w)}px"` : '';
      el.innerHTML = `<div class="frames${s.stack ? ' stack' : s.side ? ' side' : ''}"${size}>${s.list.map((m, k) => `<div class="cell" style="flex:${((room[k] / sum) * 100).toFixed(2)} 1 0">
        <img alt="" src="${us[k]}" style="object-position:${m.h > m.w ? '50% 30%' : '50% 50%'}"></div>`).join('')}</div>`;
      return Promise.all([...el.querySelectorAll('img')].map((img) => img.decode().catch(() => {})));
    }
    function prepare() {
      const box = $('#hero-media');
      if (!box) return;
      layers = [0, 1].map(() => {
        const el = document.createElement('div');
        el.className = 'slide';
        box.appendChild(el);
        return el;
      });
      if (!slides.length) plan();
      new IntersectionObserver((es) => { visible = es[0].isIntersecting; }).observe($('#top'));
      // Turning a phone sideways needs the other kind of layout.
      addEventListener('resize', () => {
        if ((innerWidth >= innerHeight) === wide || !started) return;
        plan();
        idx = 0;
        showSlide(0);
      });
    }
    const first = () => { if (!slides.length) plan(); return slides[0] || null; };
    function meta(m) {
      const el = $('#hero-meta');
      if (!el) return;
      const p = placeOf(m);
      el.classList.remove('on');
      setTimeout(() => {
        el.textContent = [p && (p.en || p.name), dateLabel(m)].filter(Boolean).join(' · ');
        el.classList.toggle('on', !!el.textContent);
      }, 500);
    }
    function showSlide(i) {
      const s = slides[i];
      if (!s) return Promise.resolve();
      return urls(s).then((us) => {
        const el = layers[i % 2];
        const other = layers[(i + 1) % 2];
        return fill(el, s, us).then(() => {
          el.className = `slide on kb${i % 4}`;
          other.classList.remove('on');
          meta(s.list[0]);
        });
      }).catch(() => {});
    }
    function loop() {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        if (visible && !document.hidden && slides.length > 1) {
          idx = (idx + 1) % slides.length;
          await showSlide(idx);
          const next = slides[(idx + 1) % slides.length];
          if (next) urls(next).catch(() => {});
        }
        loop();
      }, HOLD);
    }
    function start() {
      if (started || !layers.length) return;
      started = true;
      showSlide(0).then(() => {
        if (slides[1]) urls(slides[1]).catch(() => {});
        if (!reduceMotion) loop();
      });
    }
    return { prepare, start, first, urls, fill };
  })();

  /* ---------- opening: the photos gather into a heart, which opens into the cover ---------- */
  const HEART_COLS = 11;
  const HEART_TOP = 12.5;
  const HEART_UNIT = 34 / HEART_COLS;
  const heartPoint = (t) => [16 * Math.sin(t) ** 3, 13 * Math.cos(t) - 5 * Math.cos(2 * t) - 2 * Math.cos(3 * t) - Math.cos(4 * t)];
  const HEART_POLY = Array.from({ length: 160 }, (_, i) => heartPoint((i / 160) * Math.PI * 2));
  function inHeart(x, y) {
    let c = false;
    for (let i = 0, j = HEART_POLY.length - 1; i < HEART_POLY.length; j = i, i += 1) {
      const [x1, y1] = HEART_POLY[i];
      const [x2, y2] = HEART_POLY[j];
      if ((y1 > y) !== (y2 > y) && x < ((x2 - x1) * (y - y1)) / (y2 - y1) + x1) c = !c;
    }
    return c;
  }
  function heartCells() {
    const cells = [];
    for (let r = 0; ; r += 1) {
      const y = HEART_TOP - (r + 0.5) * HEART_UNIT;
      if (y < -17.5) break;
      for (let c = 0; c < HEART_COLS; c += 1) if (inHeart(-17 + (c + 0.5) * HEART_UNIT, y)) cells.push([c, r]);
    }
    return cells;
  }
  function heartMask(rows) {
    const h = rows * HEART_UNIT;
    const d = HEART_POLY.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(2)} ${(-y).toFixed(2)}`).join('') + 'Z';
    return `url("data:image/svg+xml,${encodeURIComponent(`<svg xmlns='http://www.w3.org/2000/svg' viewBox='-17 ${-HEART_TOP} 34 ${h.toFixed(3)}' preserveAspectRatio='none'><path d='${d}'/></svg>`)}")`;
  }

  function prepareIntro() {
    const cover = hero.first();
    const coverURL = cover ? hero.urls(cover) : Promise.reject(new Error('no cover'));
    const spriteURL = data.mosaic ? blobURL(data.mosaic.id, 'image/webp', true) : Promise.reject(new Error('no mosaic'));
    coverURL.catch(() => {});
    spriteURL.catch(() => {});
    return { play: () => playIntro(spriteURL, coverURL, cover) };
  }

  async function playIntro(spriteURL, coverURL, cover) {
    const sprite = await Promise.race([spriteURL, sleep(2600).then(() => null)]).catch(() => null);
    const vw = innerWidth;
    const vh = innerHeight;
    const cells = heartCells();
    const rows = cells.reduce((n, [, r]) => Math.max(n, r + 1), 0);
    const W = Math.min(vw * 0.8, vh * 0.56, 460);
    const step = W / HEART_COLS;
    const H = rows * step;
    const left = (vw - W) / 2;
    const top = Math.max(16, vh * 0.45 - H / 2);

    const el = document.createElement('div');
    el.className = 'intro';
    el.innerHTML = `<div class="intro-heart" style="left:${left}px;top:${top}px;width:${W}px;height:${H}px"></div>
      <div class="intro-cover"></div>
      <div class="intro-cap" style="top:${top + H + 26}px"></div>
      ${hasSeal() ? `<div class="intro-seal" style="left:${(vw - W * 0.46) / 2}px;top:${top + H * 0.44 - W * 0.23}px;width:${W * 0.46}px;height:${W * 0.46}px">${sealSVG('is-intro')}</div>` : ''}
      <button class="intro-skip" type="button">跳过</button>`;
    document.body.appendChild(el);
    const heartEl = el.querySelector('.intro-heart');
    const coverEl = el.querySelector('.intro-cover');
    const cap = el.querySelector('.intro-cap');
    lock.classList.add('is-leaving');

    let skipped = false;
    const skip = new Promise((resolve) => {
      el.addEventListener('click', () => { skipped = true; resolve(); }, { once: true });
    });
    const wait = (ms) => Promise.race([sleep(ms), skip]);

    const since = data.since ? parseDay(data.since) : null;
    const days = since ? Math.floor((Date.now() - since) / DAY) + 1 : 0;
    cap.innerHTML = `${since ? `<span class="k">${fmtDate(data.since)} — ${fmtDate(new Date())}</span>` : ''}
      <b>${since ? `第 ${nf.format(days)} 天 · ` : ''}${nf.format(data.media.length)} 个瞬间</b>`;

    // On a birthday the heart folds into a cake, and a tap blows the candles out.
    async function cake(bd) {
      const tiers = [[4, 6], [2, 8], [1, 9], [0, 10]]; // the columns of each tier, two rows each, top down
      const base = rows - tiers.length * 2;
      const spots = [];
      tiers.forEach(([c0, c1], k) => {
        for (let r = 0; r < 2; r += 1) for (let c = c0; c <= c1; c += 1) spots.push([c, base + k * 2 + r]);
      });
      const from = cells.map((c, i) => ({ c, t: tiles[i] })).sort((x, y) => x.c[1] - y.c[1] || x.c[0] - y.c[0]);
      const moves = from.map(({ c, t }, i) => {
        const to = spots[i];
        const tr = to ? `translate(${(to[0] - c[0]) * step}px, ${(to[1] - c[1]) * step}px)` : `translate(0, ${-2 * step}px) scale(.3)`;
        t.animate([{ transform: 'none', opacity: 1 }, { transform: tr, opacity: to ? 1 : 0 }],
          { duration: 1000, delay: Math.random() * 240, easing: 'cubic-bezier(.65,0,.25,1)', fill: 'forwards' });
        return { t, tr, to };
      });
      const sealWrap = el.querySelector('.intro-seal');
      if (sealWrap) { sealWrap.style.transition = 'opacity .5s'; sealWrap.style.opacity = '0'; }
      cap.classList.remove('on');
      const ch = step * 1.3;
      const candles = document.createElement('div');
      candles.className = 'cake-candles';
      candles.style.cssText = `left:${left + 4 * step}px;top:${top + base * step - ch}px;width:${3 * step}px;height:${ch}px;--cw:${Math.max(5, step * 0.2)}px`;
      candles.innerHTML = '<i class="candle"><b class="flame"></b></i>'.repeat(3);
      el.appendChild(candles);
      await wait(1100);
      if (skipped) return;
      candles.classList.add('lit');
      cap.innerHTML = `<span class="k">Happy birthday</span><b>今天是${esc(bd.label)}</b><span class="tap">点一下，吹蜡烛</span>`;
      cap.classList.add('on');
      let blow;
      const blown = new Promise((r) => { blow = r; });
      const onTap = (e) => {
        if (e.target.closest('.intro-skip')) return;
        e.stopImmediatePropagation();
        blow();
      };
      el.addEventListener('click', onTap, true);
      await Promise.race([blown, skip, sleep(15000)]);
      el.removeEventListener('click', onTap, true);
      if (skipped) return;
      candles.classList.add('out');
      confetti(200);
      cap.classList.remove('on');
      await sleep(350);
      cap.innerHTML = `<span class="k">Happy birthday</span><b>生日快乐${bd.age ? ` · ${bd.age} 岁` : ''}</b>`;
      cap.classList.add('on');
      await wait(2300);
      candles.style.opacity = '0';
      moves.forEach(({ t, tr, to }) => t.animate([{ transform: tr, opacity: to ? 1 : 0 }, { transform: 'none', opacity: 1 }],
        { duration: 900, delay: Math.random() * 200, easing: 'cubic-bezier(.65,0,.25,1)', fill: 'forwards' }));
      if (sealWrap) sealWrap.style.opacity = '';
      await wait(1100);
    }

    let tiles = [];
    if (sprite && data.mosaic) {
      const mos = data.mosaic;
      const srows = Math.ceil(mos.n / mos.cols);
      const order = cells.map((_, i) => i % mos.n).sort(() => Math.random() - 0.5);
      const g = step * 0.06;
      tiles = cells.map(([c, r], i) => {
        const t = document.createElement('i');
        const k = order[i];
        t.className = 'intro-tile';
        t.style.cssText = `left:${c * step + g}px;top:${r * step + g}px;width:${step - 2 * g}px;height:${step - 2 * g}px;`
          + `background-image:url(${sprite});background-size:${mos.cols * 100}% ${srows * 100}%;`
          + `background-position:${((k % mos.cols) / (mos.cols - 1)) * 100}% ${(Math.floor(k / mos.cols) / Math.max(1, srows - 1)) * 100}%`;
        heartEl.appendChild(t);
        return t;
      });
      tiles.forEach((t) => {
        const a = Math.random() * Math.PI * 2;
        const d = Math.max(vw, vh) * (0.5 + Math.random() * 0.5);
        t.animate([
          { transform: `translate(${Math.cos(a) * d}px, ${Math.sin(a) * d}px) scale(.3) rotate(${(Math.random() - 0.5) * 120}deg)`, opacity: 0 },
          { opacity: 1, offset: 0.3 },
          { transform: 'none', opacity: 1 },
        ], { duration: 1300, delay: 100 + Math.random() * 700, easing: 'cubic-bezier(.16,.84,.24,1)', fill: 'both' });
      });
      await wait(900);
      const sealWrap = el.querySelector('.intro-seal');
      let stampAt = 1100;
      if (sealWrap && !skipped) {
        sealWrap.classList.add('on');
        stampAt = Math.max(1100, playSeal(sealWrap.querySelector('svg'), 0.62) - 520);
      }
      await wait(stampAt);
      if (!skipped) {
        cap.classList.add('on');
        heartEl.animate([
          { transform: 'scale(1)' }, { transform: 'scale(1.07)', offset: 0.16 }, { transform: 'scale(1)', offset: 0.34 },
          { transform: 'scale(1.045)', offset: 0.52 }, { transform: 'scale(1)' },
        ], { duration: 1000, easing: 'ease-in-out' });
        await wait(1200);
        const bd = birthdayToday(specialDays(since, data.days || []));
        if (bd && !skipped) await cake(bd);
      }
    }

    const urls = skipped ? null : await Promise.race([coverURL, sleep(1800).then(() => null)]).catch(() => null);
    if (urls && !skipped) {
      await hero.fill(coverEl, cover, urls);
      const mask = heartMask(rows);
      const setMask = (w, h, x, y) => {
        coverEl.style.webkitMaskImage = mask; coverEl.style.maskImage = mask;
        coverEl.style.webkitMaskSize = `${w}px ${h}px`; coverEl.style.maskSize = `${w}px ${h}px`;
        coverEl.style.webkitMaskPosition = `${x}px ${y}px`; coverEl.style.maskPosition = `${x}px ${y}px`;
      };
      setMask(W, H, left, top);
      coverEl.classList.add('on');
      cap.classList.remove('on');
      await wait(450);
      if (!skipped) {
        // Grow around a point inside the heart until it covers the screen.
        const ax = vw / 2;
        const ay = top + H * 0.42;
        const k = Math.max(vw / (W * 0.42), vh / (H * 0.36)) * 1.25;
        coverEl.classList.add('grow');
        void coverEl.offsetWidth;
        const sealWrap = el.querySelector('.intro-seal');
        const brand = $('#brand');
        if (sealWrap && brand) {
          const from = sealWrap.getBoundingClientRect();
          const to = brand.getBoundingClientRect();
          sealWrap.animate([{ transform: 'none' }, { transform: `translate(${to.left - from.left}px, ${to.top - from.top}px) scale(${to.width / from.width})` }],
            { duration: 1250, delay: 120, easing: 'cubic-bezier(.65,0,.2,1)', fill: 'forwards' });
        }
        setMask(W * k, H * k, ax - (ax - left) * k, ay - (ay - top) * k);
        tiles.forEach((t) => {
          const r = t.getBoundingClientRect();
          const dx = r.left + r.width / 2 - ax;
          const dy = r.top + r.height / 2 - ay;
          const f = 1.6 + Math.random();
          t.animate([{ transform: 'none', opacity: 1 }, { transform: `translate(${dx * f}px, ${dy * f}px) scale(.6) rotate(${(Math.random() - 0.5) * 90}deg)`, opacity: 0 }],
            { duration: 1100, delay: Math.random() * 150, easing: 'cubic-bezier(.5,0,.75,0)', fill: 'forwards' });
        });
        await wait(1500);
      }
      coverEl.style.webkitMaskImage = 'none';
      coverEl.style.maskImage = 'none';
    }

    showStory();
    await sleep(80);
    el.classList.add('out');
    setTimeout(() => el.remove(), 1000);
  }

  /* ---------- travel map ---------- */
  function placeGroups() {
    const groups = (data.places || []).map((pl, i) => ({ i, pl, list: [] }));
    data.media.forEach((m) => { if (m.p != null && groups[m.p]) groups[m.p].list.push(m); });
    groups.forEach((g) => {
      const dated = g.list.filter((m) => m.dq !== 'unknown');
      g.first = dated.length ? dated[0].date : '9999';
      g.last = dated.length ? dated[dated.length - 1].date : '';
      // Visits more than a week apart count separately.
      g.visits = 0;
      let prev = null;
      dated.forEach((m) => { const t = parseDay(m.date); if (!prev || t - prev > 7 * DAY) g.visits += 1; prev = t; });
    });
    return groups.filter((g) => g.list.length).sort((x, y) => (x.first < y.first ? -1 : 1));
  }

  // Every place we went, in the order we went there, and how far that is in straight lines.
  function journey() {
    const rad = Math.PI / 180;
    const far = (a, b) => {
      const h = Math.sin(((b.lat - a.lat) * rad) / 2) ** 2 + Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(((b.lon - a.lon) * rad) / 2) ** 2;
      return 2 * 6371 * Math.asin(Math.sqrt(h));
    };
    const stops = [];
    let km = 0;
    data.media.forEach((m) => {
      const pl = placeOf(m);
      const last = stops[stops.length - 1];
      if (!pl || m.dq === 'unknown' || (last && last.i === m.p)) return;
      if (last) km += far(last.pl, pl);
      stops.push({ i: m.p, pl, m, km });
    });
    return { stops, km };
  }
  const aroundEarth = (km) => {
    const r = km / 40075;
    return r >= 1 ? `够绕地球 ${r.toFixed(1)} 圈了` : r >= 0.2 ? `差不多绕了地球${r < 0.45 ? '小半' : r < 0.55 ? '半' : '大半'}圈` : '';
  };

  function atlasHTML(groups) {
    if (!groups.length) return '';
    const range = (g) => {
      if (!g.last) return '';
      const a = g.first.slice(0, 10);
      const b = g.last.slice(0, 10);
      if (g.visits > 1) return `${g.visits} 次 · ${a.slice(0, 7).replace('-', '.')} – ${b.slice(0, 7).replace('-', '.')}`;
      if (a === b) return fmtDate(a);
      return `${fmtDate(a)} – ${a.slice(0, 4) === b.slice(0, 4) ? b.slice(5).replace('-', '.') : fmtDate(b)}`;
    };
    const cards = groups.map((g, n) => {
      sets[`p${g.i}`] = g.list.map((m) => m.id);
      const c = tripCover(g);
      return `<li class="trip" data-p="${g.i}">
        <button class="ph trip-ph" type="button" data-id="${c.id}" data-set="p${g.i}" style="--c:${c.c}" aria-label="${esc(g.pl.name)}的照片"><img alt="" decoding="async"></button>
        <div class="trip-meta">
          <span class="trip-no">${pad2(n + 1)}</span>
          <h3>${esc(g.pl.name)}</h3>
          ${g.pl.en ? `<small>${esc(g.pl.en)}</small>` : ''}
          <p>${range(g)}${range(g) ? ' · ' : ''}${g.list.length} 张</p>
        </div>
      </li>`;
    }).join('');
    return `<section class="sec atlas" id="map"><div class="wrap">
      <div class="atlas-map reveal"><div class="atlas-stage">
        <canvas id="atlas" aria-label="旅行地图"></canvas>
        <div class="atlas-ctl" role="group" aria-label="地图范围">
          <button type="button" data-view="fit" aria-pressed="true">我们的足迹</button>
          <button type="button" data-view="world" aria-pressed="false">全世界</button>
        </div>
        <div class="atlas-now" id="atlas-now" aria-live="polite"></div>
        ${journey().stops.length > 1 ? `<div class="atlas-km">
          <small>我们走过的路 · 不完全统计</small>
          <p><b id="km-n">0</b><span>公里</span></p>
          <button class="km-play" id="km-play" type="button" aria-pressed="false">${PLAY}${PAUSE}<em>沿着时间重走一遍</em></button>
        </div>` : ''}
        </div>
        <p class="atlas-note"><b>不完全统计</b><span>换过几次手机，很多照片的拍摄地点和时间都没能留下来，只剩下照片本身。地图上的地方和公里数，只是照片还记得的那一部分；我们一起走过的路，比这里画出来的多得多。</span></p>
      </div>
      <div class="trips-wrap reveal">
        <button class="trips-nav prev" type="button" aria-label="上一站"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 6l-6 6 6 6"/></svg></button>
        <ol class="trips" id="trips">${cards}</ol>
        <button class="trips-nav next" type="button" aria-label="下一站"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg></button>
      </div>
    </div></section>`;
  }

  const atlas = (() => {
    const K = Math.cos((25 * Math.PI) / 180); // horizontal scale of the map projection
    let canvas; let ctx; let W = 0; let H = 0; let dpr = 1;
    let land = null; let bits = null;
    let groups = []; let pins = []; let route = [];
    let view = null; let flight = null; let mode = 'fit'; let active = -1;
    let routeP = 0; let routeStart = 0; let visible = false; let raf = 0; let following = false;
    let trip = null; let tour = null; let done = false; let shownKm = -1;

    const P = (lon, lat, v = view) => [W / 2 + (lon - v.lon) * K * v.s, H / 2 - (lat - v.lat) * v.s];

    // top: extra room kept free at the top for the view buttons.
    function fitView(list, pad, top = 0) {
      const lons = list.map((p) => p.lon);
      const lats = list.map((p) => p.lat);
      const lo0 = Math.min(...lons); const lo1 = Math.max(...lons);
      const la0 = Math.min(...lats); const la1 = Math.max(...lats);
      const s = Math.min((W - pad * 2) / Math.max(1, (lo1 - lo0) * K), (H - pad * 2 - top) / Math.max(1, la1 - la0), 40);
      return { lon: (lo0 + lo1) / 2, lat: (la0 + la1) / 2 + top / 2 / s, s };
    }
    const worldView = () => ({ lon: 100, lat: 18, s: Math.max(W / (360 * K), H / 150) });
    const placeView = (pl) => ({ lon: pl.lon, lat: pl.lat, s: Math.max(16, Math.min(64, Math.min(W, H * 1.3) / 8)) });
    const targetFor = () => (mode === 'world' ? worldView() : mode === 'place' && active >= 0 ? placeView(data.places[active]) : fitView(pins, Math.min(W, H) * 0.14, 40));

    function setup() {
      canvas = $('#atlas');
      if (!canvas) return;
      ctx = canvas.getContext('2d');
      groups = placeGroups();
      pins = groups.map((g) => ({ ...g.pl, i: g.i, n: g.list.length }));
      // Route: each hop between two places, in the order we first made it. A hop made again
      // (going home and back) is drawn once, always bending the same way.
      const seq = [];
      data.media.filter((m) => m.p != null && m.dq !== 'unknown').forEach((m) => { if (seq[seq.length - 1] !== m.p) seq.push(m.p); });
      const seen = new Set();
      route = [];
      for (let i = 1; i < seq.length; i += 1) {
        const [a, b] = [data.places[seq[i - 1]], data.places[seq[i]]].sort((x, y) => x.lon - y.lon);
        const k = `${a.name}|${b.name}`;
        if (!seen.has(k)) { seen.add(k); route.push([a, b]); }
      }
      // The page is still hidden while this runs, so size the canvas once it is laid out.
      new ResizeObserver(() => { resize(); if (W && !flight && !tour) view = targetFor(); kick(); }).observe(canvas);
      new IntersectionObserver((es) => {
        visible = es[0].isIntersecting;
        if (visible) {
          if (!land) loadLand();
          if (!routeStart) routeStart = performance.now() + 400;
          kick();
        }
      }, { rootMargin: '100px 0px' }).observe(canvas);
      canvas.addEventListener('click', onClick);
      document.querySelectorAll('.atlas-ctl button').forEach((b) => b.addEventListener('click', () => setMode(b.dataset.view)));
      setupTrips();
      trip = journey();
      $('#km-play')?.addEventListener('click', () => (tour ? stopTour() : startTour()));
    }

    function loadLand() {
      land = { loading: true };
      fetch('assets/land.json').then((r) => r.json()).then((j) => {
        land = j;
        bits = Uint8Array.from(atob(j.bits), (c) => c.charCodeAt(0));
        kick();
      }).catch(() => { land = null; });
    }

    function resize() {
      dpr = Math.min(2, devicePixelRatio || 1);
      const r = canvas.getBoundingClientRect();
      W = r.width;
      H = r.height;
      canvas.width = Math.round(W * dpr);
      canvas.height = Math.round(H * dpr);
    }

    const pressCtl = (m) => document.querySelectorAll('.atlas-ctl button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.view === m)));
    function setMode(m, placeIndex) {
      if (tour) stopTour();
      mode = m;
      if (m === 'place') active = placeIndex; else if (m !== 'place') active = -1;
      pressCtl(m);
      document.querySelectorAll('.trip').forEach((t) => t.classList.toggle('on', Number(t.dataset.p) === active));
      const now = $('#atlas-now');
      if (now) {
        const g = groups.find((x) => x.i === active);
        now.innerHTML = g ? `<b>${esc(g.pl.name)}</b><span>${g.list.length} 张照片</span>` : '';
        now.classList.toggle('on', !!g);
      }
      flyTo(targetFor());
    }

    function flyTo(to, quick = 1) {
      if (!view || !W) { view = to; return; }
      const from = { ...view };
      const dist = Math.hypot((to.lon - from.lon) * K, to.lat - from.lat);
      flight = { from, to, t0: performance.now(), dur: reduceMotion ? 1 : (900 + Math.min(900, dist * 18)) * quick, dip: Math.min(1.1, dist / 30) };
      kick();
    }

    /* ---------- walking the whole way again, stop by stop ---------- */
    function odometer(km) {
      const n = Math.round(km);
      if (n === shownKm) return;
      shownKm = n;
      const e = $('#km-n');
      if (e) e.textContent = nf.format(n);
    }
    function playButton(on) {
      const b = $('#km-play');
      if (!b) return;
      b.setAttribute('aria-pressed', String(on));
      b.querySelector('em').textContent = on ? '停下' : done ? '再走一遍' : '沿着时间重走一遍';
    }
    function caption(html) {
      const now = $('#atlas-now');
      if (!now) return;
      now.innerHTML = html;
      now.classList.toggle('on', !!html);
    }
    const legView = (k) => fitView([trip.stops[k].pl, trip.stops[k + 1].pl], Math.min(W, H) * 0.2);
    function arrive(k) {
      const st = trip.stops[k];
      active = st.i;
      caption(`<b>${esc(st.pl.name)}</b><span>第 ${k + 1} 站 · ${dateLabel(st.m)}</span>`);
    }
    function startTour() {
      if (!trip || trip.stops.length < 2 || !W) return;
      mode = 'fit';
      pressCtl('');
      document.querySelectorAll('.trip').forEach((t) => t.classList.remove('on'));
      following = false;
      done = false;
      routeP = 1;
      tour = { leg: 0, ph: 'fly', t0: 0, e: 0 };
      odometer(0);
      arrive(0);
      playButton(true);
      flyTo(legView(0), 0.8);
    }
    function stopTour() {
      tour = null;
      active = -1;
      odometer(trip.km);
      caption('');
      playButton(false);
    }
    function finishTour() {
      const s = trip.stops;
      tour = null;
      done = true;
      active = -1;
      mode = 'fit';
      pressCtl('fit');
      flyTo(targetFor());
      odometer(trip.km);
      caption(`<b>${s.length} 站</b><span>${s[0].m.date.slice(0, 7).replace('-', '.')} – ${s[s.length - 1].m.date.slice(0, 7).replace('-', '.')}</span>`);
      playButton(false);
      const r = $('#km-n')?.getBoundingClientRect();
      if (r && r.top < innerHeight && r.bottom > 0) sprinkle(r.left + r.width / 2, r.top, 6);
    }
    function tourStep(now) {
      const s = trip.stops;
      const t = tour;
      if (t.ph === 'fly') {
        if (flight) return;
        t.ph = 'move';
        t.t0 = now;
        t.dur = reduceMotion ? 1 : 650 + Math.min(1100, (s[t.leg + 1].km - s[t.leg].km) * 0.24);
        return;
      }
      if (t.ph === 'move') {
        const f = Math.min(1, (now - t.t0) / t.dur);
        t.e = f < 0.5 ? 2 * f * f : 1 - (-2 * f + 2) ** 2 / 2;
        odometer(s[t.leg].km + (s[t.leg + 1].km - s[t.leg].km) * t.e);
        if (f >= 1) { t.ph = 'rest'; t.t0 = now; arrive(t.leg + 1); }
        return;
      }
      if (now - t.t0 < (reduceMotion ? 1000 : 520)) return;
      t.leg += 1;
      if (t.leg >= s.length - 1) { finishTour(); return; }
      t.ph = 'fly';
      t.e = 0;
      flyTo(legView(t.leg), 0.75);
    }

    const ease = (t) => (t < 0.5 ? 4 * t * t * t : 1 - (-2 * t + 2) ** 3 / 2);
    function step(now) {
      if (flight) {
        const t = Math.min(1, (now - flight.t0) / flight.dur);
        const e = ease(t);
        const { from, to } = flight;
        const ls = Math.log(from.s) + (Math.log(to.s) - Math.log(from.s)) * e - flight.dip * Math.sin(Math.PI * e);
        view = { lon: from.lon + (to.lon - from.lon) * e, lat: from.lat + (to.lat - from.lat) * e, s: Math.exp(ls) };
        if (t >= 1) { view = to; flight = null; }
      }
      if (tour) tourStep(now);
      else if (routeStart && now > routeStart && routeP < 1) {
        routeP = reduceMotion ? 1 : Math.min(1, (now - routeStart) / 3200);
        if (trip && !done) odometer(trip.km * (1 - (1 - routeP) ** 3)); // the kilometres count up as the route draws itself
      }
    }

    function kick() {
      if (raf || !visible) return;
      raf = requestAnimationFrame(frame);
    }
    function frame(now) {
      raf = 0;
      step(now);
      draw(now);
      if (visible && !document.hidden) raf = requestAnimationFrame(frame);
    }

    function drawLand() {
      if (!bits) return;
      const st = land.step;
      const cell = st * view.s; // px between dots vertically
      const stride = Math.max(1, Math.ceil(4.6 / cell));
      const gap = cell * stride;
      const r = Math.max(0.55, Math.min(1.7, gap * 0.2));
      const lonL = view.lon - W / 2 / (K * view.s);
      const lonR = view.lon + W / 2 / (K * view.s);
      const latT = view.lat + H / 2 / view.s;
      const latB = view.lat - H / 2 / view.s;
      const r0 = Math.max(0, Math.floor((land.lat0 - latT) / st / stride) * stride);
      const r1 = Math.min(land.rows - 1, Math.ceil((land.lat0 - latB) / st));
      const c0 = Math.floor((lonL - land.lon0) / st / stride) * stride;
      const c1 = Math.ceil((lonR - land.lon0) / st);
      ctx.beginPath();
      for (let row = r0; row <= r1; row += stride) {
        const lat = land.lat0 - (row + 0.5) * st;
        const y = H / 2 - (lat - view.lat) * view.s;
        const base = row * land.cols;
        for (let c = c0; c <= c1; c += stride) {
          const col = ((c % land.cols) + land.cols) % land.cols;
          const i = base + col;
          if (!(bits[i >> 3] & (1 << (i & 7)))) continue;
          const x = W / 2 + (land.lon0 + (c + 0.5) * st - view.lon) * K * view.s;
          ctx.moveTo(x + r, y);
          ctx.arc(x, y, r, 0, Math.PI * 2);
        }
      }
      ctx.fillStyle = 'rgba(255, 232, 240, .2)';
      ctx.fill();
      // Warm the land around the places we have been.
      ctx.globalCompositeOperation = 'source-atop';
      for (const p of pins) {
        const [x, y] = P(p.lon, p.lat);
        const R = Math.max(26, view.s * 2.2);
        const g = ctx.createRadialGradient(x, y, 0, x, y, R);
        g.addColorStop(0, 'rgba(255, 125, 156, .95)');
        g.addColorStop(1, 'rgba(255, 125, 156, 0)');
        ctx.fillStyle = g;
        ctx.fillRect(x - R, y - R, R * 2, R * 2);
      }
      ctx.globalCompositeOperation = 'source-over';
    }

    function seg(a, b) {
      const [x0, y0] = P(a.lon, a.lat);
      const [x2, y2] = P(b.lon, b.lat);
      const mx = (x0 + x2) / 2; const my = (y0 + y2) / 2;
      const dx = x2 - x0; const dy = y2 - y0;
      return [x0, y0, mx - dy * 0.22, my + dx * 0.22, x2, y2];
    }
    function drawRoute(now) {
      if (!route.length) return;
      const n = route.length;
      const k = routeP * n;
      const walked = tour || done;
      ctx.save();
      if (walked) ctx.globalAlpha = 0.3;
      ctx.lineWidth = 1.3;
      ctx.strokeStyle = 'rgba(255, 160, 180, .75)';
      ctx.shadowColor = 'rgba(255, 125, 156, .8)';
      ctx.shadowBlur = 6;
      ctx.setLineDash([3, 4]);
      ctx.beginPath();
      for (let i = 0; i < n && i < k; i += 1) {
        let [x0, y0, cx, cy, x2, y2] = seg(route[i][0], route[i][1]);
        const f = Math.min(1, k - i);
        if (f < 1) { // cut the curve where the drawing has got to
          const ax = x0 + (cx - x0) * f; const ay = y0 + (cy - y0) * f;
          const bx = cx + (x2 - cx) * f; const by = cy + (y2 - cy) * f;
          x2 = ax + (bx - ax) * f; y2 = ay + (by - ay) * f; cx = ax; cy = ay;
        }
        ctx.moveTo(x0, y0);
        ctx.quadraticCurveTo(cx, cy, x2, y2);
      }
      ctx.stroke();
      ctx.restore();
      if (walked) { drawWalk(now); return; }
      if (routeP >= 1 && !reduceMotion) { // a small light keeps travelling the route
        const T = (now / 1000 / 2.2) % n;
        const i = Math.floor(T);
        const t = T - i;
        const [x0, y0, cx, cy, x2, y2] = seg(route[i][0], route[i][1]);
        const x = (1 - t) * (1 - t) * x0 + 2 * (1 - t) * t * cx + t * t * x2;
        const y = (1 - t) * (1 - t) * y0 + 2 * (1 - t) * t * cy + t * t * y2;
        const g = ctx.createRadialGradient(x, y, 0, x, y, 9);
        g.addColorStop(0, 'rgba(255, 240, 245, .95)');
        g.addColorStop(1, 'rgba(255, 125, 156, 0)');
        ctx.fillStyle = g;
        ctx.fillRect(x - 9, y - 9, 18, 18);
      }
    }

    // One leg of the journey, as points along the same curve the dashed route uses, up to a fraction of the way.
    function legPts(k, upto = 1) {
      const a = trip.stops[k].pl;
      const b = trip.stops[k + 1].pl;
      const back = a.lon > b.lon; // the route always bends as if drawn from west to east
      const [x0, y0, cx, cy, x2, y2] = back ? seg(b, a) : seg(a, b);
      const n = Math.max(1, Math.ceil(40 * upto));
      const pts = [];
      for (let j = 0; j <= n; j += 1) {
        const u = (upto * j) / n;
        const t = back ? 1 - u : u;
        pts.push([(1 - t) * (1 - t) * x0 + 2 * (1 - t) * t * cx + t * t * x2, (1 - t) * (1 - t) * y0 + 2 * (1 - t) * t * cy + t * t * y2]);
      }
      return pts;
    }
    function glowAt(x, y, r, a = 1) {
      const g = ctx.createRadialGradient(x, y, 0, x, y, r);
      g.addColorStop(0, `rgba(255, 255, 255, ${a})`);
      g.addColorStop(0.28, `rgba(255, 205, 220, ${a * 0.85})`);
      g.addColorStop(1, 'rgba(255, 125, 156, 0)');
      ctx.fillStyle = g;
      ctx.fillRect(x - r, y - r, r * 2, r * 2);
    }
    function drawWalk(now) {
      const legs = trip.stops.length - 1;
      const full = done ? legs : tour.leg;
      const line = (pts) => pts.forEach(([x, y], j) => (j ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
      let head = null;
      ctx.save();
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      ctx.lineWidth = 2.2;
      ctx.strokeStyle = 'rgba(255, 186, 204, .95)';
      ctx.shadowColor = 'rgba(255, 105, 145, 1)';
      ctx.shadowBlur = 14;
      ctx.beginPath();
      for (let k = 0; k < full; k += 1) line(legPts(k));
      if (tour && tour.ph !== 'fly') {
        const pts = legPts(tour.leg, tour.ph === 'move' ? tour.e : 1);
        line(pts);
        if (tour.ph === 'move') head = pts;
      }
      ctx.stroke();
      ctx.restore();
      if (head) {
        // a comet: a bright head and a tail that thins out behind it
        for (let j = Math.max(1, head.length - 12); j < head.length; j += 1) {
          const k = (j - head.length + 12) / 12;
          ctx.beginPath();
          ctx.moveTo(head[j - 1][0], head[j - 1][1]);
          ctx.lineTo(head[j][0], head[j][1]);
          ctx.strokeStyle = `rgba(255, 245, 248, ${k * 0.9})`;
          ctx.lineWidth = 1 + k * 3;
          ctx.stroke();
        }
        const [x, y] = head[head.length - 1];
        glowAt(x, y, 18);
      } else if (done && !reduceMotion) {
        // a light keeps walking the way, in the order we went
        const T = (now / 1000 / 1.6) % legs;
        const k = Math.floor(T);
        const pts = legPts(k, T - k);
        const [x, y] = pts[pts.length - 1];
        glowAt(x, y, 10, 0.9);
      }
    }

    function drawPins(now) {
      const boxes = [];
      const order = pins.slice().sort((a, b) => (a.i === active ? -1 : b.i === active ? 1 : b.n - a.n));
      for (const p of pins) {
        const [x, y] = P(p.lon, p.lat);
        if (x < -30 || y < -30 || x > W + 30 || y > H + 30) continue;
        const on = p.i === active;
        const ph = ((now / 2400) + p.i * 0.37) % 1;
        ctx.beginPath();
        ctx.arc(x, y, (on ? 7 : 4) + ph * (on ? 22 : 14), 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(255, 125, 156, ${(on ? 0.7 : 0.45) * (1 - ph)})`;
        ctx.lineWidth = 1;
        ctx.stroke();
        const g = ctx.createRadialGradient(x, y, 0, x, y, on ? 18 : 11);
        g.addColorStop(0, 'rgba(255, 125, 156, .75)');
        g.addColorStop(1, 'rgba(255, 125, 156, 0)');
        ctx.fillStyle = g;
        ctx.fillRect(x - 18, y - 18, 36, 36);
        ctx.beginPath();
        ctx.arc(x, y, on ? 4.6 : 3, 0, Math.PI * 2);
        ctx.fillStyle = on ? '#fff' : '#ffe3ea';
        ctx.fill();
      }
      ctx.textBaseline = 'middle';
      // A name may not sit on top of another place's dot either.
      const dots = pins.map((p) => { const [x, y] = P(p.lon, p.lat); return [x - 5, y - 5, 10, 10, p.i]; });
      for (const p of order) {
        const [x, y] = P(p.lon, p.lat);
        const on = p.i === active;
        ctx.font = `${on ? 600 : 400} ${on ? 16 : 13}px "Story Kai", "UI Kai", "Songti SC", serif`;
        const w = ctx.measureText(p.name).width;
        const h = on ? 20 : 16;
        let bx = x + 9;
        let box = [bx, y - h / 2, w, h];
        const over = (b, o) => b[0] < o[0] + o[2] + 4 && b[0] + b[2] + 4 > o[0] && b[1] < o[1] + o[3] && b[1] + b[3] > o[1];
        const hit = (b) => boxes.some((o) => over(b, o)) || dots.some((o) => o[4] !== p.i && over(b, o));
        if (hit(box) || bx + w > W - 4) { bx = x - 9 - w; box = [bx, y - h / 2, w, h]; }
        if ((hit(box) || bx < 4) && !on) continue;
        boxes.push(box);
        ctx.lineWidth = 3;
        ctx.strokeStyle = 'rgba(11, 9, 16, .85)';
        ctx.strokeText(p.name, bx, y + 1);
        ctx.fillStyle = on ? '#fff' : 'rgba(255, 238, 244, .86)';
        ctx.fillText(p.name, bx, y + 1);
      }
    }

    function draw(now) {
      if (!view || !W) return;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      drawLand();
      drawRoute(now);
      drawPins(now);
    }

    function onClick(e) {
      const r = canvas.getBoundingClientRect();
      const x = e.clientX - r.left;
      const y = e.clientY - r.top;
      let best = null; let bd = 22;
      for (const p of pins) {
        const [px, py] = P(p.lon, p.lat);
        const d = Math.hypot(px - x, py - y);
        if (d < bd) { bd = d; best = p; }
      }
      if (best) { following = true; select(best.i, true); }
    }

    function select(i, scrollCard) {
      if (i === active && mode === 'place') return;
      setMode('place', i);
      if (scrollCard) {
        const card = document.querySelector(`.trip[data-p="${i}"]`);
        const list = $('#trips');
        if (card && list) list.scrollTo({ left: card.offsetLeft - (list.clientWidth - card.offsetWidth) / 2, behavior: reduceMotion ? 'auto' : 'smooth' });
      }
    }

    function setupTrips() {
      const list = $('#trips');
      if (!list) return;
      let tm = 0;
      const pick = () => {
        const mid = list.scrollLeft + list.clientWidth / 2;
        let best = null; let bd = Infinity;
        list.querySelectorAll('.trip').forEach((c) => {
          const d = Math.abs(c.offsetLeft + c.offsetWidth / 2 - mid);
          if (d < bd) { bd = d; best = c; }
        });
        if (best) select(Number(best.dataset.p), false);
      };
      list.addEventListener('scroll', () => {
        if (!following) return;
        clearTimeout(tm);
        tm = setTimeout(pick, 90);
      }, { passive: true });
      ['pointerdown', 'wheel', 'touchstart', 'keydown'].forEach((ev) => list.addEventListener(ev, () => { following = true; }, { passive: true }));
      const go = (dir) => {
        following = true;
        const cards = [...list.querySelectorAll('.trip')];
        let i = cards.findIndex((c) => Number(c.dataset.p) === active);
        i = i < 0 ? 0 : Math.max(0, Math.min(cards.length - 1, i + dir));
        select(Number(cards[i].dataset.p), true);
      };
      document.querySelector('.trips-nav.prev').addEventListener('click', () => go(-1));
      document.querySelector('.trips-nav.next').addEventListener('click', () => go(1));
      list.addEventListener('mouseover', (e) => {
        const c = e.target.closest('.trip');
        if (c && finePointer) { following = true; select(Number(c.dataset.p), false); }
      });
    }

    return { setup };
  })();

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
      sprinkle(e.clientX, e.clientY, 2 + Math.floor(Math.random() * 2));
    });
  }

  function sprinkle(x, y, n) {
    for (let i = 0; i < n; i += 1) {
      const h = document.createElement('div');
      h.className = 'float-heart';
      h.innerHTML = HEART;
      h.style.left = `${x}px`;
      h.style.top = `${y}px`;
      h.style.setProperty('--dx', `${(Math.random() - 0.5) * 80}px`);
      h.style.setProperty('--rot', `${(Math.random() - 0.5) * 50}deg`);
      h.style.animationDelay = `${i * 90}ms`;
      h.style.width = h.style.height = `${12 + Math.random() * 12}px`;
      document.body.appendChild(h);
      setTimeout(() => h.remove(), 1700);
    }
  }

  /* Double-tap (or double-click) anywhere and a heart pops up there. */
  function tapHearts() {
    const ok = (e) => !document.body.classList.contains('is-locked') && !e.target.closest('button, a, input, label, .lb, .intro, #atlas, .trips');
    let popped = 0;
    const pop = (x, y) => {
      if (performance.now() - popped < 400) return; // a double tap can also fire dblclick
      popped = performance.now();
      const h = document.createElement('div');
      h.className = 'big-heart';
      h.innerHTML = HEART;
      h.style.left = `${x}px`;
      h.style.top = `${y}px`;
      document.body.appendChild(h);
      setTimeout(() => h.remove(), 1100);
      sprinkle(x, y, 4);
    };
    addEventListener('dblclick', (e) => {
      if (!ok(e)) return;
      getSelection()?.removeAllRanges();
      pop(e.clientX, e.clientY);
    });
    let last = null;
    addEventListener('pointerup', (e) => {
      if (e.pointerType === 'mouse' || !ok(e)) return;
      const now = performance.now();
      if (last && now - last.t < 330 && Math.hypot(e.clientX - last.x, e.clientY - last.y) < 36) { pop(e.clientX, e.clientY); last = null; }
      else last = { t: now, x: e.clientX, y: e.clientY };
    }, { passive: true });
  }

  /* ---------- "missing you": hearts all over the screen, then an old photo of us ---------- */
  function heartRain() {
    if (reduceMotion) return null;
    const c = document.createElement('canvas');
    c.className = 'confetti';
    c.setAttribute('aria-hidden', 'true');
    document.body.appendChild(c);
    const dpr = Math.min(2, devicePixelRatio || 1);
    const w = innerWidth;
    const h = innerHeight;
    c.width = w * dpr;
    c.height = h * dpr;
    const g = c.getContext('2d');
    const heart = new Path2D(HEART_PATH);
    const colors = ['#ff7d9c', '#ffb3c6', '#ffd1dc', '#ff5f87', '#ffb68c', '#fff0f4'];
    const bits = Array.from({ length: Math.round(Math.min(72, 34 + w / 28)) }, (_, i) => ({
      x: Math.random() * w, y: h + 20 + Math.random() * h * 0.7, s: 0.7 + Math.random() * 1.7, v: 0.22 + Math.random() * 0.3,
      sway: 10 + Math.random() * 28, ph: Math.random() * 6, c: colors[i % colors.length], r: (Math.random() - 0.5) * 0.6,
    }));
    const t0 = performance.now();
    let last = t0;
    const frame = (t) => {
      const dt = Math.min(48, t - last);
      last = t;
      g.setTransform(dpr, 0, 0, dpr, 0, 0);
      g.clearRect(0, 0, w, h);
      let alive = 0;
      for (const b of bits) {
        b.y -= b.v * dt * (h / 800);
        if (b.y < -40) continue;
        alive += 1;
        const x = b.x + Math.sin((t - t0) / 520 + b.ph) * b.sway;
        g.globalAlpha = Math.min(1, Math.max(0, b.y / (h * 0.3)));
        g.setTransform(dpr * b.s, 0, 0, dpr * b.s, x * dpr, b.y * dpr);
        g.rotate(b.r + Math.sin((t - t0) / 400 + b.ph) * 0.18);
        g.translate(-12, -12);
        g.fillStyle = b.c;
        g.fill(heart);
      }
      if (alive && t - t0 < 7000) requestAnimationFrame(frame); else c.remove();
    };
    requestAnimationFrame(frame);
    return c;
  }

  const missYou = (() => {
    const LS = 'ourstory.miss.v1';
    let box = null;
    let recent = [];
    let current = null;

    // How many times today; it starts again from one every day.
    function times() {
      const today = fmtDate(new Date());
      let s = null;
      try { s = JSON.parse(localStorage.getItem(LS)); } catch (e) { /* nothing yet */ }
      const n = s && s.d === today ? s.n + 1 : 1;
      try { localStorage.setItem(LS, JSON.stringify({ d: today, n })); } catch (e) { /* private mode */ }
      return n;
    }

    function build() {
      document.body.insertAdjacentHTML('beforeend', `<div class="memory" id="memory" hidden>
        <div class="mem-card" role="dialog" aria-modal="true" aria-labelledby="mem-k">
          <p class="kicker" id="mem-k"></p>
          <button class="mem-ph" id="mem-ph" type="button" aria-label="放大看"><img alt=""></button>
          <p class="mem-when"><b id="mem-d"></b><span id="mem-s"></span></p>
          <div class="mem-act"><button type="button" id="mem-again">${HEART}<span>再翻一张</span></button><button type="button" id="mem-close">收起</button></div>
        </div>
      </div>`);
      box = $('#memory');
      box.addEventListener('click', (e) => { if (e.target === box) close(); });
      $('#mem-close').addEventListener('click', close);
      $('#mem-again').addEventListener('click', () => { const r = $('#mem-again').getBoundingClientRect(); sprinkle(r.left + 24, r.top + r.height / 2, 3); show(); });
      $('#mem-ph').addEventListener('click', () => {
        if (!current) return;
        close();
        openLightbox([current.id], 0);
      });
      addEventListener('keydown', (e) => { if (e.key === 'Escape' && !box.hidden) close(); });
    }

    function pickOne() {
      const pool = data.media.filter((m) => m.type === 'photo' && m.dq !== 'unknown');
      const fresh = pool.filter((m) => !recent.includes(m.id));
      const m = (fresh.length ? fresh : pool)[Math.floor(Math.random() * (fresh.length || pool.length))];
      recent = [m.id, ...recent].slice(0, 30);
      return m;
    }

    function show() {
      const m = pickOne();
      current = m;
      const ph = $('#mem-ph');
      ph.style.setProperty('--ar', (m.w / m.h).toFixed(4));
      ph.style.setProperty('--c', m.c);
      const img = ph.querySelector('img');
      img.classList.remove('ready');
      img.removeAttribute('src');
      blobURL(m.id, 'image/webp', true).then((u) => {
        if (current !== m) return;
        img.onload = () => img.classList.add('ready');
        img.src = u;
        return blobURL(m.l, 'image/webp', true);
      }).then((u) => { if (u && current === m) img.src = u; }).catch(() => {});
      const pl = placeOf(m);
      const ago = Math.round((todayDate() - parseDay(m.date)) / DAY);
      $('#mem-d').textContent = dateLabel(m);
      const when = m.dq === 'approx' ? `大约 ${Math.max(1, Math.round(ago / 30.4))} 个月前` : ago > 0 ? `${nf.format(ago)} 天前` : '就是今天';
      $('#mem-s').textContent = [pl && pl.name, when].filter(Boolean).join(' · ');
      const card = box.querySelector('.mem-card');
      card.classList.remove('flip');
      void card.offsetWidth;
      card.classList.add('flip');
    }

    function open() {
      if (!data) return;
      if (!box) build();
      const n = times();
      const b = $('#miss-btn').getBoundingClientRect();
      sprinkle(b.left + b.width / 2, b.top, 5);
      const rain = heartRain();
      $('#mem-k').textContent = n === 1 ? '今天第一次想你' : `今天第 ${n} 次想你`;
      show();
      setTimeout(() => {
        box.hidden = false;
        rain?.classList.add('behind'); // the hearts go on rising behind the photo, softly blurred
        document.body.style.overflow = 'hidden';
        requestAnimationFrame(() => box.classList.add('on'));
        $('#mem-again').focus({ preventScroll: true });
      }, reduceMotion ? 0 : 750);
    }

    function close() {
      box.classList.remove('on');
      document.body.style.overflow = '';
      setTimeout(() => { if (!box.classList.contains('on')) box.hidden = true; }, 400);
    }

    return { open };
  })();

  /* Confetti from both sides of the screen: birthdays and opening the capsule. */
  function confetti(n = 160) {
    if (reduceMotion) return;
    const c = document.createElement('canvas');
    c.className = 'confetti';
    c.setAttribute('aria-hidden', 'true');
    document.body.appendChild(c);
    const dpr = Math.min(2, devicePixelRatio || 1);
    const w = innerWidth;
    const h = innerHeight;
    c.width = w * dpr;
    c.height = h * dpr;
    const g = c.getContext('2d');
    g.scale(dpr, dpr);
    const colors = ['#ff7d9c', '#ffd1dc', '#ffb68c', '#fff4f7', '#c9a7ff', '#ffe08a', '#9ee6d0'];
    const lift = Math.sqrt(h / 850);
    const bits = Array.from({ length: n }, (_, i) => {
      const left = i % 2 === 0;
      const a = -Math.PI / 2 + (left ? 0.42 : -0.42) + (Math.random() - 0.5) * 0.6;
      const v = (13 + Math.random() * 11) * lift;
      const ribbon = Math.random() < 0.18;
      return {
        x: left ? -8 : w + 8, y: h * 0.9, vx: Math.cos(a) * v, vy: Math.sin(a) * v, r: Math.random() * 6, vr: (Math.random() - 0.5) * 0.3,
        w: ribbon ? 3 : 6 + Math.random() * 5, l: ribbon ? 18 + Math.random() * 12 : 4 + Math.random() * 4, c: colors[i % colors.length], ph: Math.random() * 6,
      };
    });
    const t0 = performance.now();
    const frame = (t) => {
      g.clearRect(0, 0, w, h);
      let alive = 0;
      for (const b of bits) {
        b.vx *= 0.986;
        b.vy = b.vy * 0.986 + 0.26;
        if (b.vy > 2.4) b.vy = 2.4; // flutter down slowly once they turn
        b.x += b.vx + Math.sin((t - t0) / 320 + b.ph) * 0.7;
        b.y += b.vy;
        b.r += b.vr;
        if (b.y > h + 30) continue;
        alive += 1;
        g.save();
        g.translate(b.x, b.y);
        g.rotate(b.r);
        g.scale(1, Math.cos((t - t0) / 170 + b.ph));
        g.fillStyle = b.c;
        g.fillRect(-b.w / 2, -b.l / 2, b.w, b.l);
        g.restore();
      }
      if (alive && t - t0 < 9000) requestAnimationFrame(frame); else c.remove();
    };
    requestAnimationFrame(frame);
  }

  /* ---------- weather: petals in spring, fireflies in summer, leaves in autumn, snow in winter ---------- */
  function weather(kind) {
    if (reduceMotion || $('#weather')) return;
    const canvas = document.createElement('canvas');
    canvas.id = 'weather';
    canvas.setAttribute('aria-hidden', 'true');
    document.body.appendChild(canvas);
    const g = canvas.getContext('2d');
    const heart = new Path2D(HEART_PATH);
    const PALETTE = {
      petals: ['#ffc4d2', '#ffd9e2', '#ffb3c6'], leaves: ['#e8894f', '#d9653b', '#f0a95b', '#c4513a'],
      confetti: ['#ff7d9c', '#ffd1dc', '#ffb68c', '#c9a7ff', '#ffe08a', '#9ee6d0'], hearts: ['#ff7d9c', '#ffb3c6', '#ffd1dc'],
    };
    const FALL = { snow: 0.4, petals: 0.55, leaves: 0.7, confetti: 0.9, hearts: 0.45 };
    let w = 0; let h = 0; let parts = [];
    const dpr = Math.min(2, devicePixelRatio || 1);
    const make = (anywhere) => {
      const pal = PALETTE[kind] || ['#fff'];
      const p = {
        x: Math.random() * w, y: anywhere ? Math.random() * h : -16, s: 0.6 + Math.random() * 0.8,
        a: Math.random() * Math.PI * 2, spin: (Math.random() - 0.5) * 0.04, ph: Math.random() * Math.PI * 2,
        c: pal[Math.floor(Math.random() * pal.length)], vx: (Math.random() - 0.5) * 0.3, vy: (FALL[kind] || 0.5) * (0.6 + Math.random() * 0.8),
      };
      if (kind === 'fireflies') { p.y = h * (0.3 + Math.random() * 0.7); p.vy = (Math.random() - 0.5) * 0.2; }
      return p;
    };
    const resize = () => {
      w = innerWidth;
      h = innerHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      g.setTransform(dpr, 0, 0, dpr, 0, 0);
      const n = Math.min(34, Math.max(14, (w * h) / 42000)) * (kind === 'snow' ? 1.6 : kind === 'fireflies' ? 0.8 : 1);
      parts = Array.from({ length: Math.round(n) }, () => make(true));
    };
    const draw = (t) => {
      g.clearRect(0, 0, w, h);
      for (const p of parts) {
        if (kind === 'fireflies') {
          p.x += p.vx + Math.sin(t / 1600 + p.ph) * 0.25;
          p.y += p.vy + Math.cos(t / 1900 + p.ph) * 0.2;
          if (p.x < -10) p.x = w + 10; else if (p.x > w + 10) p.x = -10;
          if (p.y < h * 0.2 || p.y > h + 10) p.vy = -p.vy;
          const a = 0.2 + 0.8 * Math.max(0, Math.sin(t / 760 + p.ph));
          const r = 11 * p.s;
          const gr = g.createRadialGradient(p.x, p.y, 0, p.x, p.y, r);
          gr.addColorStop(0, `rgba(255, 246, 180, ${0.85 * a})`);
          gr.addColorStop(0.25, `rgba(255, 226, 120, ${0.35 * a})`);
          gr.addColorStop(1, 'rgba(255, 220, 110, 0)');
          g.fillStyle = gr;
          g.fillRect(p.x - r, p.y - r, r * 2, r * 2);
          continue;
        }
        p.y += p.vy;
        p.x += p.vx + Math.sin(t / 1300 + p.ph) * (kind === 'snow' ? 0.2 : 0.4);
        p.a += p.spin;
        if (p.y > h + 20 || p.x < -30 || p.x > w + 30) Object.assign(p, make(false));
        g.save();
        g.translate(p.x, p.y);
        g.rotate(p.a);
        g.fillStyle = p.c;
        if (kind === 'snow') {
          g.globalAlpha = 0.35 + 0.4 * (p.s - 0.6);
          g.beginPath(); g.arc(0, 0, 1.2 * p.s + 0.5, 0, Math.PI * 2); g.fill();
        } else if (kind === 'petals') {
          g.globalAlpha = 0.7;
          g.beginPath(); g.ellipse(0, 0, 5 * p.s, 2.6 * p.s * Math.abs(Math.cos(t / 900 + p.ph)) + 0.8, 0, 0, Math.PI * 2); g.fill();
        } else if (kind === 'leaves') {
          const k = 6 * p.s;
          g.globalAlpha = 0.65;
          g.scale(1, Math.cos(t / 1100 + p.ph));
          g.beginPath(); g.moveTo(0, -k); g.quadraticCurveTo(k * 0.95, 0, 0, k); g.quadraticCurveTo(-k * 0.95, 0, 0, -k); g.fill();
        } else if (kind === 'confetti') {
          g.globalAlpha = 0.8;
          g.scale(1, Math.cos(t / 420 + p.ph));
          g.fillRect(-3 * p.s, -4.5 * p.s, 6 * p.s, 9 * p.s);
        } else {
          g.globalAlpha = 0.5;
          g.scale(0.5 * p.s, 0.5 * p.s);
          g.translate(-12, -12);
          g.fill(heart);
        }
        g.restore();
      }
    };
    let raf = 0;
    const loop = (t) => { draw(t); raf = requestAnimationFrame(loop); };
    resize();
    addEventListener('resize', resize);
    raf = requestAnimationFrame(loop);
    document.addEventListener('visibilitychange', () => {
      cancelAnimationFrame(raf);
      if (!document.hidden) raf = requestAnimationFrame(loop);
    });
  }

  sky();
  pointerFX();
  tapHearts();
  boot();
})();
