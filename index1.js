/* ins, repCL: App/US 의존 — index.js에 유지 */
function ins(ed, s, e, text) { ed.value = ed.value.substring(0, s) + text + ed.value.substring(e); const p = s + text.length; ed.setSelectionRange(p, p); ed.focus(); App.render(); US.snap() }
function repCL(ed, t) { const { ls, le } = getCL(ed); ed.value = ed.value.substring(0, ls) + t + ed.value.substring(le); const p = ls + t.length; ed.setSelectionRange(p, p); ed.focus(); App.render(); US.snap() }

/* ═══════════════════════════════════════════════════════════════════
   AppLock — 앱 잠금 & GitHub 토큰 AES-256-GCM 암호화
   PBKDF2(SHA-256, 200_000회, 랜덤 16B salt) + AES-GCM(랜덤 12B IV)
═══════════════════════════════════════════════════════════════════ */
const AppLock = (() => {
  const LOCK_KEY   = 'mdpro_lock_v1';      // { hash_b64, salt_b64 }  비밀번호 검증용
  const ENC_GH_KEY = 'mdpro_gh_enc_v1';    // { salt, iv, data } 암호화된 GH cfg
  const ENC_PV_KEY = 'mdpro_pv_enc_v1';    // { salt, iv, data } 암호화된 PV cfg
  const RAW_GH_KEY = 'mdpro_gh_cfg';       // 기존 평문 키 (마이그레이션 후 삭제)
  const RAW_PV_KEY = 'pvshare_cfg';
  const AUTO_LOCK_KEY = 'mdpro_autolock_min'; // 자동 잠금 분 (0=끄기)

  let _unlocked = false;
  let _sessionKey = null;  // 잠금 해제 후 메모리에만 보관 (CryptoKey)
  let _autoLockTimer = null;

  /* ── Base64 유틸 ── */
  function b64enc(u8) { return btoa(String.fromCharCode(...u8)); }
  function b64dec(s)  { return new Uint8Array(atob(s).split('').map(c=>c.charCodeAt(0))); }

  /* ── PBKDF2 키 유도 ── */
  async function _deriveKey(password, salt) {
    const enc = new TextEncoder();
    const km  = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
      km,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /* ── 데이터 암호화 ── */
  async function _encrypt(plaintext, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const key  = await _deriveKey(password, salt);
    const ct   = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(plaintext)
    );
    return { salt: b64enc(salt), iv: b64enc(iv), data: b64enc(new Uint8Array(ct)) };
  }

  /* ── 데이터 복호화 ── */
  async function _decrypt(payload, password) {
    const salt = b64dec(payload.salt);
    const iv   = b64dec(payload.iv);
    const data = b64dec(payload.data);
    const key  = await _deriveKey(password, salt);
    const pt   = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(pt);
  }

  /* ── 비밀번호 해시 저장 (검증용) ── */
  async function _saveHash(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key  = await _deriveKey(password, salt);
    // 빈 문자열을 암호화해서 검증 데이터로 사용
    const dummy = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(12) },
      key,
      new TextEncoder().encode('mdpro_ok')
    );
    const rec = { salt: b64enc(salt), iv: b64enc(new Uint8Array(12)), data: b64enc(new Uint8Array(dummy)) };
    localStorage.setItem(LOCK_KEY, JSON.stringify(rec));
  }

  /* ── 비밀번호 검증 ── */
  async function _verifyPw(password) {
    const raw = localStorage.getItem(LOCK_KEY);
    if (!raw) return false;
    try {
      const rec  = JSON.parse(raw);
      const salt = b64dec(rec.salt);
      const iv   = b64dec(rec.iv);
      const data = b64dec(rec.data);
      const key  = await _deriveKey(password, salt);
      const pt   = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
      return new TextDecoder().decode(pt) === 'mdpro_ok';
    } catch(e) { return false; }
  }

  /* ── 평문 설정 → 암호화 저장 (마이그레이션) ── */
  async function _migrateIfNeeded(password) {
    const rawGh = localStorage.getItem(RAW_GH_KEY);
    if (rawGh) {
      try {
        const enc = await _encrypt(rawGh, password);
        localStorage.setItem(ENC_GH_KEY, JSON.stringify(enc));
        localStorage.removeItem(RAW_GH_KEY);
      } catch(e) {}
    }
    const rawPv = localStorage.getItem(RAW_PV_KEY);
    if (rawPv) {
      try {
        const enc = await _encrypt(rawPv, password);
        localStorage.setItem(ENC_PV_KEY, JSON.stringify(enc));
        localStorage.removeItem(RAW_PV_KEY);
      } catch(e) {}
    }
  }

  /* ── 잠금 해제 후 GH cfg 복호화 → localStorage(평문 임시) 복원 ── */
  async function _restoreConfigs(password) {
    const encGh = localStorage.getItem(ENC_GH_KEY);
    if (encGh) {
      try {
        const plain = await _decrypt(JSON.parse(encGh), password);
        localStorage.setItem(RAW_GH_KEY, plain);
      } catch(e) {}
    }
    const encPv = localStorage.getItem(ENC_PV_KEY);
    if (encPv) {
      try {
        const plain = await _decrypt(JSON.parse(encPv), password);
        localStorage.setItem(RAW_PV_KEY, plain);
      } catch(e) {}
    }
  }

  /* ── 앱 잠금 시 평문 cfg 제거 & 재암호화 저장 ── */
  async function _secureOnLock(password) {
    const rawGh = localStorage.getItem(RAW_GH_KEY);
    if (rawGh) {
      const enc = await _encrypt(rawGh, password);
      localStorage.setItem(ENC_GH_KEY, JSON.stringify(enc));
      localStorage.removeItem(RAW_GH_KEY);
    }
    const rawPv = localStorage.getItem(RAW_PV_KEY);
    if (rawPv) {
      const enc = await _encrypt(rawPv, password);
      localStorage.setItem(ENC_PV_KEY, JSON.stringify(enc));
      localStorage.removeItem(RAW_PV_KEY);
    }
  }

  /* ── 잠금 화면 표시 ── */
  function _showLockScreen(mode) {
    // mode: 'unlock' | 'set' | 'change'
    const ov = document.getElementById('app-lock-overlay');
    if (!ov) return;
    const isSet = (mode === 'set');
    const isChange = (mode === 'change');
    document.getElementById('lock-title').textContent =
      isSet ? '🔒 앱 비밀번호 설정' : isChange ? '🔑 비밀번호 변경' : '🔒 MD Pro Locked';
    document.getElementById('lock-sub').textContent =
      isSet ? '처음 사용 시 비밀번호를 설정하세요' :
      isChange ? '새 비밀번호를 입력하세요' :
      '비밀번호를 입력하여 잠금 해제';
    document.getElementById('lock-pw2-row').style.display = (isSet || isChange) ? '' : 'none';
    document.getElementById('lock-btn').textContent = isSet ? '비밀번호 설정' : isChange ? '변경 완료' : '잠금 해제';
    document.getElementById('lock-pw-input').value = '';
    document.getElementById('lock-pw2-input').value = '';
    document.getElementById('lock-error').textContent = '';
    ov.dataset.mode = mode;
    ov.style.display = 'flex';
    setTimeout(() => document.getElementById('lock-pw-input').focus(), 80);
  }

  function _hideLockScreen() {
    const ov = document.getElementById('app-lock-overlay');
    if (ov) ov.style.display = 'none';
    _updateSidebarLockBtn();
  }

  /* ── 버튼 핸들러 ── */
  async function handleLockBtn() {
    const ov   = document.getElementById('app-lock-overlay');
    const mode = ov.dataset.mode || 'unlock';
    const pw   = document.getElementById('lock-pw-input').value;
    const pw2  = document.getElementById('lock-pw2-input').value;
    const err  = document.getElementById('lock-error');
    const btn  = document.getElementById('lock-btn');

    if (!pw) { err.textContent = '비밀번호를 입력하세요'; return; }

    btn.disabled = true;
    btn.textContent = '처리 중…';

    try {
      if (mode === 'set' || mode === 'change') {
        if (pw.length < 4) { err.textContent = '4자 이상 입력하세요'; return; }
        if (pw !== pw2)    { err.textContent = '비밀번호가 일치하지 않습니다'; return; }
        if (mode === 'change') {
          // 기존 비번으로 재암호화
          await _secureOnLock(pw);
        }
        await _saveHash(pw);
        await _migrateIfNeeded(pw);
        await _restoreConfigs(pw);
        _unlocked = true;
        _hideLockScreen();
        startAutoLockTimer();
        AppLock._toast('🔒 비밀번호가 설정되었습니다');
      } else {
        // unlock
        const ok = await _verifyPw(pw);
        if (!ok) {
          err.textContent = '비밀번호가 틀렸습니다';
          document.getElementById('lock-pw-input').value = '';
          document.getElementById('lock-pw-input').focus();
          return;
        }
        await _restoreConfigs(pw);
        _unlocked = true;
        _hideLockScreen();
        startAutoLockTimer();
        // GH 모듈 재로드
        if (typeof GH !== 'undefined' && GH.reloadCfg) GH.reloadCfg();
      }
    } catch(e) {
      err.textContent = '오류: ' + e.message;
    } finally {
      btn.disabled = false;
      btn.textContent = mode === 'unlock' ? '잠금 해제' : mode === 'set' ? '비밀번호 설정' : '변경 완료';
    }
  }

  function _toast(msg) {
    if (typeof App !== 'undefined' && App._toast) { App._toast(msg); return; }
    const t = document.createElement('div');
    t.textContent = msg;
    Object.assign(t.style, {
      position:'fixed', bottom:'24px', left:'50%', transform:'translateX(-50%)',
      background:'rgba(30,30,40,.95)', color:'#eee', padding:'8px 18px',
      borderRadius:'8px', fontSize:'13px', zIndex:'99999', pointerEvents:'none'
    });
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2200);
  }

  /* ── 공개 API ── */
  function init() {
    const hasLock   = !!localStorage.getItem(LOCK_KEY);
    const hasEncGh  = !!localStorage.getItem(ENC_GH_KEY);
    const hasRawGh  = !!localStorage.getItem(RAW_GH_KEY);
    const hasRawPv  = !!localStorage.getItem(RAW_PV_KEY);

    if (!hasLock) {
      // 처음 사용: 비밀번호 설정 화면
      // 기존 평문 토큰이 있으면 설정 후 암호화, 없으면 그냥 진입
      if (hasRawGh || hasRawPv) {
        _showLockScreen('set');
      } else {
        // 토큰도 없으면 잠금 없이 진입
        _unlocked = true;
        _hideLockScreen();
      }
    } else {
      _showLockScreen('unlock');
    }

    _updateSidebarLockBtn();

    /* 자동 잠금: 사용자 활동 시 타이머 리셋 */
    const onActivity = () => resetAutoLockTimer();
    document.addEventListener('keydown', onActivity);
    document.addEventListener('mousedown', onActivity);
    document.addEventListener('click', onActivity);
    document.addEventListener('touchstart', onActivity);
  }

  function showChangePw() { _showLockScreen('change'); }
  function showSetPw()    { _showLockScreen('set'); }
  function isUnlocked()   { return _unlocked; }
  function hasLock()     { return !!localStorage.getItem(LOCK_KEY); }

  function _updateSidebarLockBtn() {
    const btn = document.getElementById('app-lock-btn');
    if (btn) btn.style.display = hasLock() ? '' : 'none';
  }

  function getAutoLockMinutes() {
    const v = parseInt(localStorage.getItem(AUTO_LOCK_KEY), 10);
    return (v >= 0 && v <= 120) ? v : 0;
  }
  function setAutoLockMinutes(min) {
    const m = Math.max(0, Math.min(120, parseInt(min, 10) || 0));
    try { localStorage.setItem(AUTO_LOCK_KEY, String(m)); } catch (e) {}
    if (_unlocked) { clearAutoLockTimer(); if (m > 0) startAutoLockTimer(); }
    return m;
  }
  function clearAutoLockTimer() {
    if (_autoLockTimer) { clearTimeout(_autoLockTimer); _autoLockTimer = null; }
  }
  function startAutoLockTimer() {
    clearAutoLockTimer();
    const min = getAutoLockMinutes();
    if (min <= 0 || !_unlocked) return;
    _autoLockTimer = setTimeout(() => { _autoLockTimer = null; lockNow(); }, min * 60 * 1000);
  }
  function resetAutoLockTimer() {
    if (!_unlocked) return;
    const min = getAutoLockMinutes();
    if (min <= 0) return;
    startAutoLockTimer();
  }

  function lockNow() {
    clearAutoLockTimer();
    _unlocked = false;
    _showLockScreen('unlock');
  }

  /* ── 비밀번호 분실 재설정 ─────────────────────────────────── */
  function showReset() {
    document.getElementById('lock-reset-panel').style.display = '';
    document.getElementById('lock-forgot-row').style.display  = 'none';
    document.getElementById('lock-reset-error').textContent   = '';
    document.getElementById('lock-reset-token').value = '';
    document.getElementById('lock-reset-pw').value    = '';
    document.getElementById('lock-reset-pw2').value   = '';
    setTimeout(() => document.getElementById('lock-reset-token').focus(), 60);
  }

  function hideReset() {
    document.getElementById('lock-reset-panel').style.display = 'none';
    document.getElementById('lock-forgot-row').style.display  = '';
  }

  async function doReset() {
    const token = document.getElementById('lock-reset-token').value.trim();
    const pw    = document.getElementById('lock-reset-pw').value;
    const pw2   = document.getElementById('lock-reset-pw2').value;
    const err   = document.getElementById('lock-reset-error');

    err.textContent = '';
    if (!token)           { err.textContent = 'GitHub 토큰을 입력하세요';   return; }
    if (!token.startsWith('gh')) {
      err.textContent = '올바른 GitHub 토큰 형식이 아닙니다 (ghp_... 또는 github_pat_...)';
      return;
    }
    if (pw.length < 4)    { err.textContent = '새 비밀번호는 4자 이상';    return; }
    if (pw !== pw2)       { err.textContent = '비밀번호가 일치하지 않습니다'; return; }

    const btn = document.querySelector('#lock-reset-panel button');
    if (btn) { btn.disabled = true; btn.textContent = '처리 중…'; }

    try {
      /* 1) 기존 암호화 데이터 시도 복호화 (토큰을 이전 비번으로 사용했을 가능성) */
      const ENC_GH_KEY = 'mdpro_gh_enc_v1';
      const ENC_PV_KEY = 'mdpro_pv_enc_v1';
      const RAW_GH_KEY = 'mdpro_gh_cfg';
      const RAW_PV_KEY = 'pvshare_cfg';

      /* 기존 데이터 삭제 (복호화 불가 = 토큰으로 원래 암호화된 경우) */
      const encGh = localStorage.getItem(ENC_GH_KEY);
      let restoredGh = null;
      if (encGh) {
        try {
          restoredGh = await _decrypt(JSON.parse(encGh), token);
          localStorage.setItem(RAW_GH_KEY, restoredGh);
        } catch(e) {
          /* 복호화 실패 → 기존 암호화 삭제 후 새 토큰으로 재등록 */
          localStorage.removeItem(ENC_GH_KEY);
          /* 사용자가 입력한 토큰을 새 cfg로 등록 */
          const newCfg = JSON.parse(localStorage.getItem(RAW_GH_KEY) || 'null') || {};
          newCfg.token = token;
          localStorage.setItem(RAW_GH_KEY, JSON.stringify(newCfg));
        }
      } else {
        /* 암호화 데이터 없음 → 토큰으로 새 cfg 등록 */
        const newCfg = JSON.parse(localStorage.getItem(RAW_GH_KEY) || 'null') || {};
        newCfg.token = token;
        localStorage.setItem(RAW_GH_KEY, JSON.stringify(newCfg));
      }

      /* PVShare cfg 도 같이 처리 */
      const encPv = localStorage.getItem(ENC_PV_KEY);
      if (encPv) {
        try {
          const plain = await _decrypt(JSON.parse(encPv), token);
          localStorage.setItem(RAW_PV_KEY, plain);
        } catch(e) { localStorage.removeItem(ENC_PV_KEY); }
      }

      /* 2) 새 비밀번호로 해시 저장 */
      await _saveHash(pw);

      /* 3) 현재 평문 데이터를 새 비번으로 암호화 */
      await _migrateIfNeeded(pw);

      /* 4) 잠금 해제 */
      _unlocked = true;
      document.getElementById('app-lock-overlay').style.display = 'none';
      startAutoLockTimer();
      _updateSidebarLockBtn();
      if (typeof GH !== 'undefined' && GH.reloadCfg) GH.reloadCfg();
      _toast('✅ 비밀번호가 재설정되었습니다');

    } catch(e) {
      err.textContent = '오류: ' + e.message;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '재설정'; }
    }
  }

  return { init, handleLockBtn, showChangePw, showSetPw, isUnlocked, hasLock, lockNow, getAutoLockMinutes, setAutoLockMinutes, resetAutoLockTimer, _toast, showReset, hideReset, doReset };
})();

/* ═══════════════════════════════════════════════════════════
   AiApiKey — Google AI Studio API 키 암호화 저장
   PBKDF2 + AES-256-GCM (앱 고정 시크릿)
═══════════════════════════════════════════════════════════ */
const AiApiKey = (() => {
  const STORAGE_KEY = 'mdpro_ai_apikey_enc';
  const APP_SECRET = 'mdpro_ai_enc_v1_fixed_secret';

  function b64enc(u8) { return btoa(String.fromCharCode(...u8)); }
  function b64dec(s)  { return new Uint8Array(atob(s).split('').map(c=>c.charCodeAt(0))); }

  async function _deriveKey() {
    const enc = new TextEncoder();
    const km = await crypto.subtle.importKey('raw', enc.encode(APP_SECRET), 'PBKDF2', false, ['deriveKey']);
    const salt = enc.encode('mdpro_ai_salt_v1');
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      km,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function _encrypt(plaintext) {
    const key = await _deriveKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(plaintext)
    );
    return { iv: b64enc(iv), data: b64enc(new Uint8Array(ct)) };
  }

  async function _decrypt(payload) {
    const key = await _deriveKey();
    const iv = b64dec(payload.iv);
    const data = b64dec(payload.data);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(pt);
  }

  async function save() {
    const inp = document.getElementById('ai_apikey');
    if (!inp) return;
    const val = (inp.value || '').trim();
    if (!val) {
      try { localStorage.removeItem(STORAGE_KEY); } catch(e) {}
      inp.value = '';
      inp.classList.remove('apikey-saved');
      return;
    }
    try {
      const enc = await _encrypt(val);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(enc));
      inp.classList.add('apikey-saved');
    } catch(e) { console.warn('AiApiKey save failed:', e); }
  }

  async function load() {
    const inp = document.getElementById('ai_apikey');
    if (!inp) return;
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    try {
      const payload = JSON.parse(raw);
      const plain = await _decrypt(payload);
      inp.value = plain;
      inp.classList.add('apikey-saved');
    } catch(e) { console.warn('AiApiKey load failed:', e); }
  }

  function get() {
    const inp = document.getElementById('ai_apikey');
    return inp ? (inp.value || '').trim() : '';
  }

  function toggleShow() {
    const inp = document.getElementById('ai_apikey');
    const btn = document.getElementById('ai-apikey-btn-show');
    if (!inp || !btn) return;
    const isPass = inp.type === 'password';
    inp.type = isPass ? 'text' : 'password';
    btn.textContent = isPass ? '🙈 숨기기' : '👁 키보기';
  }

  return { save, load, get, toggleShow };
})();

/* Scholar API Key (SerpAPI) — Google Scholar 검색용, 암호화 저장 */
const ScholarApiKey = (() => {
  const STORAGE_KEY = 'mdpro_scholar_apikey_enc';
  const LEGACY_KEY = 'mdpro_scholar_apikey';
  const APP_SECRET = 'mdpro_scholar_enc_v1_fixed_secret';
  const API_KEY_RE = /api_key\s*:\s*["']([^"']+)["']/;

  function b64enc(u8) { return btoa(String.fromCharCode(...u8)); }
  function b64dec(s) { return new Uint8Array(atob(s).split('').map(c => c.charCodeAt(0))); }

  async function _deriveKey() {
    const enc = new TextEncoder();
    const km = await crypto.subtle.importKey('raw', enc.encode(APP_SECRET), 'PBKDF2', false, ['deriveKey']);
    const salt = enc.encode('mdpro_scholar_salt_v1');
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      km,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function _encrypt(plaintext) {
    const key = await _deriveKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(plaintext)
    );
    return { iv: b64enc(iv), data: b64enc(new Uint8Array(ct)) };
  }

  async function _decrypt(payload) {
    if (!payload || !payload.iv || !payload.data) return '';
    const key = await _deriveKey();
    const iv = b64dec(payload.iv);
    const data = b64dec(payload.data);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(pt);
  }

  async function save() {
    const inp = document.getElementById('scholar_apikey');
    if (!inp) return;
    const val = (inp.value || '').trim();
    try {
      if (val) {
        const enc = await _encrypt(val);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(enc));
        try { localStorage.removeItem(LEGACY_KEY); } catch (e) {}
        inp.classList.add('apikey-saved');
      } else {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(LEGACY_KEY);
        inp.classList.remove('apikey-saved');
      }
    } catch (e) { console.warn('ScholarApiKey save failed:', e); }
  }

  async function load() {
    const inp = document.getElementById('scholar_apikey');
    if (!inp) return;
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        try {
          const payload = JSON.parse(raw);
          const plain = await _decrypt(payload);
          inp.value = plain;
          inp.classList.add('apikey-saved');
          return;
        } catch (e) { /* not encrypted */ }
      }
      const legacy = localStorage.getItem(LEGACY_KEY);
      if (legacy) {
        inp.value = legacy;
        inp.classList.add('apikey-saved');
        localStorage.removeItem(LEGACY_KEY);
        const enc = await _encrypt(legacy);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(enc));
      }
    } catch (e) { console.warn('ScholarApiKey load failed:', e); }
  }

  function get() {
    const inp = document.getElementById('scholar_apikey');
    return inp ? (inp.value || '').trim() : '';
  }

  function toggleShow() {
    const inp = document.getElementById('scholar_apikey');
    const btn = document.getElementById('scholar-apikey-btn-show');
    if (!inp || !btn) return;
    const isPass = inp.type === 'password';
    inp.type = isPass ? 'text' : 'password';
    btn.textContent = isPass ? '🙈 숨기기' : '👁 키보기';
  }
  /** 붙여넣은 코드에서 api_key 추출 (getJson({ api_key: "..." }) 등) */
  function extractFromPaste(text) {
    if (!text || typeof text !== 'string') return null;
    const m = text.match(API_KEY_RE);
    return m ? m[1].trim() : null;
  }
  /** #scholar_code_paste 텍스트에서 키 추출 후 위 Scholar API Key 입력란에 넣기 */
  function extractFromPasteBox() {
    const box = document.getElementById('scholar_code_paste');
    const inp = document.getElementById('scholar_apikey');
    const feedback = document.getElementById('scholar-extract-feedback');
    if (!box || !inp) return false;
    const key = extractFromPaste(box.value);
    if (key) {
      inp.value = key;
      inp.classList.add('apikey-saved');
      if (feedback) {
        feedback.style.display = 'inline';
        feedback.textContent = '✓ api_key 추출됨';
        feedback.style.color = 'var(--ok)';
        clearTimeout(feedback._hide);
        feedback._hide = setTimeout(() => { feedback.style.display = 'none'; }, 2500);
      }
      return true;
    }
    if (feedback) {
      feedback.style.display = 'inline';
      feedback.textContent = 'api_key를 찾을 수 없음';
      feedback.style.color = 'var(--er)';
      clearTimeout(feedback._hide);
      feedback._hide = setTimeout(() => { feedback.style.display = 'none'; }, 2500);
    }
    return false;
  }
  function initPasteExtract() {
    const inp = document.getElementById('scholar_apikey');
    if (!inp) return;
    inp.addEventListener('paste', (e) => {
      const pasted = (e.clipboardData && e.clipboardData.getData('text')) || '';
      const key = extractFromPaste(pasted);
      if (key) {
        e.preventDefault();
        inp.value = key;
        inp.classList.add('apikey-saved');
      }
    });
    const pasteBox = document.getElementById('scholar_code_paste');
    if (pasteBox) {
      pasteBox.addEventListener('paste', () => {
        setTimeout(() => extractFromPasteBox(), 10);
      });
    }
  }
  return { save, load, get, toggleShow, extractFromPaste, extractFromPasteBox, initPasteExtract };
})();

function mdRender(md, showFootnotes) {
    try {
        /* ── ~ 이스케이프 전처리 ──────────────────────────────────
           ~~취소선~~, ~취소선~ (공백 경계) 는 유지하고,
           범위 표기용 ~ (면(1~2), 1~2배, A~B 등) 는 \~ 이스케이프.
           marked 9.x GFM 에서 ~ 앞뒤 문자 무관하게 strikethrough 처리하므로
           의도치 않은 취소선을 방지한다.                          */
        const _strikePH = [];
        // 1) ~~...~~ 보호
        md = md.replace(/~~[\s\S]*?~~/g, m => {
            const idx = _strikePH.length; _strikePH.push(m);
            return `\x00STR${idx}\x00`;
        });
        // 2) (공백/줄경계) ~취소선~ → <del>취소선</del> 직접 변환
        //    ※ step4에서 ~text~ 그대로 복원하면 marked가 재처리하므로 HTML 선변환
        md = md.replace(/(^|\s)~([^~\n]+?)~(\s|$)/gm, (m, pre, inner, post) => {
            const idx = _strikePH.length;
            _strikePH.push(`<del>${inner}</del>`);
            return `${pre}\x00STR${idx}\x00${post}`;
        });
        // 3) 나머지 ~ 이스케이프 (범위 표기 등)
        md = md.replace(/~/g, '\\~');
        // 4) 플레이스홀더 복원
        md = md.replace(/\x00STR(\d+)\x00/g, (m, i) => _strikePH[parseInt(i)]);
        /* ── 각주 처리 ── */
        // Process footnotes: highlight [^n] references and collect definitions
        let fnDefs = {}; let fnCounter = 0;
        // Collect footnote definitions [^n]: text
        md = md.replace(/^\[\^([^\]]+)\]:\s*(.+)$/gm, (m, key, text) => { fnDefs[key] = text; return '__FN_DEF_' + key + '__' });
        // Replace inline [^n] with highlighted spans
        md = md.replace(/\[\^([^\]]+)\]/g, (m, key) => {
            fnCounter++;
            return `<sup class="footnote-highlight" title="${fnDefs[key] || ''}">[${fnCounter}]</sup>`;
        });
        // Remove def placeholders (they'll be added to footnotes section)
        md = md.replace(/__FN_DEF_[^_]+__\n?/g, '');
        // ** 사이에 (), [], 등 특수문자가 있으면 marked가 파싱 못하므로 <b>로 선변환
        md = md.replace(/\*\*([^*\n]*[()[\]{}][^*\n]*)\*\*/g, (m, inner) => `<b>${inner}</b>`);
        let html = marked.parse(md || '');
        // Append footnotes section if there are definitions and showFootnotes is not false
        if (Object.keys(fnDefs).length > 0 && showFootnotes !== false) {
            let fnHtml = '<div class="footnotes-section">';
            let i = 1;
            Object.entries(fnDefs).forEach(([k, v]) => { fnHtml += `<div class="footnote-def"><sup>[${i}]</sup> ${v}</div>`; i++ });
            fnHtml += '</div>';
            html += fnHtml;
        }
        return html;
    } catch (e) { return `<p style="color:red">${e.message}</p>`; }
}
/* PAGE SPLIT */
function splitPages(md) { const p = md.replace(/\r\n/g, '\n').split(/\n?<div class="page-break"><\/div>\n?/); return p.length ? p : [md] }

function parseSlideContent(slideMd) {
    const raw = (slideMd || '').trim();
    const lines = raw.split('\n');
    let title = '';
    const bullets = [];
    let notes = '';
    let inNotes = false;
    for (const line of lines) {
        if (/^notes:\s*$/i.test(line)) { inNotes = true; continue; }
        if (inNotes) { notes += (notes ? '\n' : '') + line; continue; }
        const h1 = line.match(/^#\s+(.+)$/);
        if (h1) { title = h1[1].trim(); continue; }
        if (/^-\s+/.test(line)) bullets.push(line.replace(/^-\s+/, '').trim());
    }
    return { title, bullets, notes: notes.trim() };
}
function parseMarkdownToSlides(md) {
    const pages = splitPages(md || '');
    return { slides: pages.map(p => parseSlideContent(p)) };
}

/* ═══════════════════════════════════════════════════════════
   PREVIEW RENDERER
═══════════════════════════════════════════════════════════ */
const PR = {
    rm: false,
    slideMode: false,
    getSlideMode() { try { return localStorage.getItem('mdpro_slide_mode') === '1'; } catch(e) { return false; } },
    setSlideMode(v) { try { localStorage.setItem('mdpro_slide_mode', v ? '1' : '0'); } catch(e) {} this.slideMode = !!v; },
    /* 단락(p)에만 연속 번호 삽입 — 제목·표·코드·인용 제외 */
    _applyRM(container) {
        /* 기존 번호 제거 */
        container.querySelectorAll('.rm-ln').forEach(n => n.remove());
        if (!this.rm) return;
        let n = 1;
        container.querySelectorAll('.preview-page').forEach(page => {
            /* 직계 p만 대상 (blockquote>p, li>p 등 중첩 제외) */
            page.querySelectorAll(':scope>p, :scope>section>p').forEach(p => {
                const span = document.createElement('span');
                span.className = 'rm-ln';
                span.textContent = n++;
                span.setAttribute('aria-hidden', 'true');
                p.insertBefore(span, p.firstChild);
            });
        });
    },
    render(md, showFootnotes) {
        if (showFootnotes === undefined) showFootnotes = true;
        this.slideMode = this.getSlideMode();
        const c = el('preview-container');
        c.classList.toggle('slide-mode', !!this.slideMode);
        const savedScrollTop = (typeof SS !== 'undefined' && !SS.isEnabled()) ? c.scrollTop : -1;
        const pages = splitPages(md); c.innerHTML = '';
        if (this.slideMode) {
            pages.forEach((p, i) => {
                const parsed = parseSlideContent(p);
                const slideDiv = document.createElement('div');
                slideDiv.className = 'ppt-slide' + (parsed.bullets.length > 6 ? ' slide-bullet-warn' : '');
                slideDiv.dataset.slideIndex = i + 1;
                const inner = document.createElement('div');
                inner.className = 'slide-inner';
                inner.innerHTML = mdRender(p, showFootnotes);
                slideDiv.appendChild(inner);
                const numSpan = document.createElement('span');
                numSpan.className = 'slide-num';
                numSpan.textContent = String(i + 1);
                slideDiv.appendChild(numSpan);
                if (parsed.bullets.length > 6) {
                    const warn = document.createElement('span');
                    warn.className = 'slide-bullet-warn-msg';
                    warn.textContent = '⚠ bullet 6개 초과';
                    slideDiv.appendChild(warn);
                }
                slideDiv.querySelectorAll('a').forEach(a => { a.target = '_blank'; a.rel = 'noopener noreferrer'; });
                c.appendChild(slideDiv);
            });
            requestAnimationFrame(() => {
                c.querySelectorAll('.ppt-slide .slide-inner').forEach(el => {
                    if (el.scrollHeight > el.clientHeight) el.parentElement.classList.add('slide-overflow');
                });
            });
            const pgEl = el('pg-cnt'); if (pgEl) pgEl.textContent = pages.length ? `1 / ${pages.length}` : '0 / 0';
        } else {
            pages.forEach((p, i) => {
                const div = document.createElement('div');
                div.className = 'preview-page' + (this.rm ? ' rm' : ''); div.dataset.page = i + 1;
                div.innerHTML = mdRender(p, showFootnotes);
                div.querySelectorAll('a').forEach(a => { a.target = '_blank'; a.rel = 'noopener noreferrer' });
                c.appendChild(div);
            });
            this._applyRM(c);
            const pgEl = el('pg-cnt'); if (pgEl) pgEl.textContent = `1 / ${pages.length}`;
        }
        if (window.MathJax && typeof MathJax.typesetPromise === 'function') { try { MathJax.typesetPromise([c]).catch(() => {}); } catch(e) {} }
        /* 스크롤 시 현재 페이지 번호 실시간 업데이트 */
        const _pcEl = el('preview-container');
        if (_pcEl && !_pcEl._pgScrollBound) {
            _pcEl._pgScrollBound = true;
            _pcEl.addEventListener('scroll', () => {
                const sel = _pcEl.classList.contains('slide-mode') ? '.ppt-slide' : '.preview-page';
                const scrollPages = [..._pcEl.querySelectorAll(sel)];
                if (!scrollPages.length) return;
                const mid = _pcEl.scrollTop + _pcEl.clientHeight * 0.3;
                let cur = 0;
                for (let i = 0; i < scrollPages.length; i++) {
                    if (scrollPages[i].offsetTop <= mid) cur = i;
                }
                const pgEl = el('pg-cnt'); if (pgEl) pgEl.textContent = `${cur + 1} / ${scrollPages.length}`;
            }, { passive: true });
        }
        if (typeof A4Ruler !== 'undefined') A4Ruler.refresh();
        if (typeof PV !== 'undefined') PV.refresh();
        const slideBtn = document.getElementById('slide-mode-btn');
        if (slideBtn) slideBtn.classList.toggle('active', !!this.slideMode);
        /* sync OFF일 때 저장했던 scrollTop 복원 */
        if (savedScrollTop >= 0) {
            requestAnimationFrame(() => { c.scrollTop = savedScrollTop; });
        }
    }
};

/* Slide Mode 토글 + ScholarSlide 연동 */
const SlideMode = {
    toggle() {
        const next = !PR.getSlideMode();
        PR.setSlideMode(next);
        App.render();
        const btn = document.getElementById('slide-mode-btn');
        if (btn) btn.classList.toggle('active', next);
    },
    openInScholarSlide() {
        const md = el('editor').value;
        const encoded = encodeURIComponent(md);
        window.open(`scholarslide.html?data=${encoded}`, '_blank', 'noopener');
    }
};

/* ═══════════════════════════════════════════════════════════
   PV — 미리보기 확대/축소 + PPT 모드
   PPT 모드: 245% 확대 + scroll-snap으로 페이지 단위 이동
   ↑↓ 키, ◀▶ 버튼으로 페이지 이동
═══════════════════════════════════════════════════════════ */
const PV = (() => {
    let scale = 1.0;
    const STEP = 0.15, MIN = 0.4, MAX = 3.0;
    let pptOn = false;
    let pptIdx = 0;
    let _keyBound = false;

    let _pvFontPt = 11; /* 내부 PV 폰트 크기(pt) */
    let _transOn = false; /* 가로/세로 전환 상태 */

    function setScale(s) {
        scale = Math.min(MAX, Math.max(MIN, Math.round(s * 100) / 100));
        const pc = el('preview-container');
        pc.style.setProperty('--pv-scale', scale);
        el('pv-zoom-lbl').textContent = Math.round(scale * 100) + '%';
        const fontPx = Math.round(_pvFontPt * (96 / 72));
        /* 슬라이드 모드: .ppt-slide 영역에 폰트 크기만 적용 (확대/축소는 폰트로) */
        if (pc.classList.contains('slide-mode')) {
            pc.style.fontSize = fontPx + 'px';
            pc.querySelectorAll('.ppt-slide').forEach(slide => {
                if (scale === 1) {
                    slide.style.transform = '';
                    slide.style.transformOrigin = '';
                    slide.style.marginBottom = '';
                } else {
                    slide.style.transformOrigin = 'top center';
                    slide.style.transform = `scale(${scale})`;
                    const baseH = slide.offsetHeight;
                    slide.style.marginBottom = (16 + baseH * (scale - 1)) + 'px';
                }
            });
            _updateFontLbl();
            return;
        }
        pc.querySelectorAll('.preview-page').forEach(p => {
            if (scale === 1) {
                p.style.transform = ''; p.style.transformOrigin = ''; p.style.marginBottom = '';
            } else {
                p.style.transformOrigin = 'top center';
                p.style.transform = `scale(${scale})`;
                const baseH = p.offsetHeight;
                p.style.marginBottom = (16 + baseH * (scale - 1)) + 'px';
            }
            p.style.fontSize = fontPx + 'px';
            p.style.lineHeight = '1.8'; /* 폰트 변경 시 줄간격 유지 */
        });
        _updateFontLbl();
    }

    function _updateFontLbl() {
        const lbl = el('pv-font-lbl');
        if (lbl) lbl.textContent = _pvFontPt + 'pt';
    }

    function fontUp() {
        _pvFontPt = Math.min(24, _pvFontPt + 1);
        if (pptOn) {
            const pane = el('preview-pane');
            const vw = pane.clientWidth;
            const ratio = vw / Math.round(210 * (96 / 25.4));
            const fontPx = Math.round(_pvFontPt * (96 / 72) * ratio);
            const pc = el('preview-container');
            const sel = pc.classList.contains('slide-mode') ? '.ppt-slide' : '.preview-page';
            pc.querySelectorAll(sel).forEach(p => {
                p.style.fontSize = fontPx + 'px'; p.style.lineHeight = '1.8';
            });
        } else { setScale(scale); }
        _updateFontLbl();
    }
    function fontDown() {
        _pvFontPt = Math.max(6, _pvFontPt - 1);
        if (pptOn) {
            const pane = el('preview-pane');
            const vw = pane.clientWidth;
            const ratio = vw / Math.round(210 * (96 / 25.4));
            const fontPx = Math.round(_pvFontPt * (96 / 72) * ratio);
            const pc = el('preview-container');
            const sel = pc.classList.contains('slide-mode') ? '.ppt-slide' : '.preview-page';
            pc.querySelectorAll(sel).forEach(p => {
                p.style.fontSize = fontPx + 'px'; p.style.lineHeight = '1.8';
            });
        } else { setScale(scale); }
        _updateFontLbl();
    }

    /* 미리보기 패널 너비에 맞게 자동 fit */
    function fitToPane() {
        const pc = el('preview-container');
        const pages = [...pc.querySelectorAll('.preview-page')];
        if (!pages.length) return;
        const origW = pages[0].offsetWidth / scale; /* 현재 scale 제거한 원본 너비 */
        const avail = pc.clientWidth - 32;          /* 좌우 패딩 감안 */
        if (avail <= 0) return;
        const fit = Math.floor((avail / origW) * 100) / 100;
        setScale(Math.max(MIN, Math.min(MAX, fit)));
    }

    /* PPT 모드 전용 zoom: 페이지 width/padding/minHeight 비례 조정 */
    function _pptZoom(delta) {
        const pane = el('preview-pane');
        const pc = el('preview-container');
        const pages = getPages();
        if (!pages.length) return;
        const MM = 96 / 25.4;
        const baseWmm = _transOn ? 297 : 210;
        const baseHmm = _transOn ? 210 : 297;
        const origPx = Math.round(baseWmm * MM);
        /* 현재 pane 너비를 기준으로 ratio 산출 후 delta 적용 */
        const curW = parseFloat(pages[0].style.width) || pane.clientWidth;
        const newW = Math.round(Math.max(pane.clientWidth * 0.5,
            Math.min(pane.clientWidth * 2.0, curW + delta * origPx)));
        const ratio = newW / origPx;
        const fontPx = Math.round(_pvFontPt * (96 / 72) * ratio);
        pages.forEach(p => {
            p.style.width = newW + 'px';
            p.style.padding = Math.round(22 * MM * ratio) + 'px ' + Math.round(18 * MM * ratio) + 'px';
            p.style.minHeight = Math.round(baseHmm * MM * ratio) + 'px';
            p.style.fontSize = fontPx + 'px';
            p.style.lineHeight = '1.8';
        });
        el('pv-zoom-lbl').textContent = Math.round(ratio * 100) + '%';
    }

    function zoomIn() { if (pptOn) { _pptZoom(+STEP); } else { setScale(scale + STEP); } }
    function zoomOut() { if (pptOn) { _pptZoom(-STEP); } else { setScale(scale - STEP); } }

    /* PPT 모드 */
    function getPages() {
        const pc = el('preview-container');
        const sel = pc.classList.contains('slide-mode') ? '.ppt-slide' : '.preview-page';
        return [...pc.querySelectorAll(sel)];
    }

    function pptGo(idx) {
        const pages = getPages();
        if (!pages.length) return;
        pptIdx = Math.max(0, Math.min(pages.length - 1, idx));
        /* PPT 모드: preview-container 스크롤 (scrollIntoView는 부모가 overflow:auto일 때 정확히 작동) */
        const pc = el('preview-container');
        const target = pages[pptIdx];
        pc.scrollTo({ top: target.offsetTop, behavior: 'smooth' });
        el('ppt-pg').textContent = `${pptIdx + 1} / ${pages.length}`;
    }

    /* PPT 뷰포트 단위 이동 (내부 패널용) */
    function pptStep(dir) {
        const pc = el('preview-container');
        const vh = pc.clientHeight;
        let next = pc.scrollTop + dir * vh;
        next = Math.max(0, next);
        /* 페이지 상단 snap */
        getPages().forEach(p => {
            if (Math.abs(next - p.offsetTop) < vh * 0.18) next = p.offsetTop;
        });
        next = Math.min(next, pc.scrollHeight - pc.clientHeight);
        pc.scrollTo({ top: next, behavior: 'smooth' });
        /* 페이지 번호 갱신 */
        setTimeout(() => {
            const mid = pc.scrollTop + vh / 2;
            let best = 0, bestD = Infinity;
            getPages().forEach((p, i) => {
                const d = Math.abs(p.offsetTop + p.offsetHeight / 2 - mid);
                if (d < bestD) { bestD = d; best = i; }
            });
            pptIdx = best;
            el('ppt-pg').textContent = `${best + 1} / ${getPages().length}`;
        }, 350);
    }

    function pptPrev() { pptOn ? pptStep(-1) : pptGo(pptIdx - 1); }
    function pptNext() { pptOn ? pptStep(1) : pptGo(pptIdx + 1); }

    function togglePPT() {
        pptOn = !pptOn;
        const pane = el('preview-pane');
        const btn = el('ppt-btn');
        const nav = el('ppt-nav');

        if (pptOn) {
            /* PPT 진입:
               1. View 모드로 자동 전환 (미리보기 패널 최대화)
               2. transform 대신 width를 패널 너비에 맞게 직접 확대
               3. pv-hdr 항상 위에 유지 */
            App.setView('preview');

            pane.classList.add('ppt-mode');
            btn.textContent = '🎬 종료';
            btn.style.background = 'rgba(240,192,96,.28)';
            btn.style.color = '#ffe090';
            btn.style.borderColor = '#f0c060';
            nav.classList.add('vis');

            /* 패널이 렌더 완료된 뒤 fit 적용 */
            setTimeout(() => {
                const pages = getPages();
                if (!pages.length) return;
                /* 패널 내용 영역 너비 (pv-hdr 너비 = pane 너비) */
                const vw = pane.clientWidth;
                const MM = 96 / 25.4;
                const baseWmm = _transOn ? 297 : 210;
                const baseHmm = _transOn ? 210 : 297;
                const origPx = Math.round(baseWmm * MM); /* A4 가로(mm) 기준 px */
                const ratio = vw / origPx;
                const pc = el('preview-container');

                pages.forEach(p => {
                    p.style.transform = 'none';
                    p.style.transformOrigin = '';
                    p.style.width = vw + 'px';
                    p.style.padding = Math.round(22 * MM * ratio) + 'px ' + Math.round(18 * MM * ratio) + 'px';
                    p.style.minHeight = Math.round(baseHmm * MM * ratio) + 'px';
                    p.style.marginBottom = '0';
                    p.style.boxSizing = 'border-box';
                });
                /* preview-container 폰트 비례 확대 (_pvFontPt 반영) */
                const fontPx = Math.round(_pvFontPt * (96 / 72) * ratio);
                pages.forEach(p => { p.style.fontSize = fontPx + 'px'; p.style.lineHeight = '1.8'; });
                el('pv-zoom-lbl').textContent = Math.round(ratio * 100) + '%';

                pptIdx = 0;
                pc.scrollTop = 0;
                setTimeout(() => pptGo(0), 60);
            }, 80);

            if (!_keyBound) {
                _keyBound = true;
                document.addEventListener('keydown', _pptKey, true);
            }
        } else {
            /* PPT 종료: 스타일 복구 */
            const drawExt = document.getElementById('pv-draw-ext');
            if (drawExt) drawExt.style.display = 'none';
            pane.classList.remove('ppt-mode');
            btn.textContent = '🎬 PPT';
            btn.style.background = '';
            btn.style.color = '';
            btn.style.borderColor = '';
            nav.classList.remove('vis');

            const pc = el('preview-container');
            getPages().forEach(p => {
                p.style.transform = ''; p.style.transformOrigin = '';
                p.style.width = ''; p.style.padding = '';
                p.style.minHeight = ''; p.style.marginBottom = '';
                p.style.boxSizing = ''; p.style.fontSize = ''; p.style.lineHeight = '';
            });
            pc.style.fontSize = '';
            setScale(1.0);
        }
    }

    /* capture 단계에서 잡아야 에디터/다른 요소 포커스에 무관하게 작동 */
    function _pptKey(e) {
        if (!pptOn) return;
        if (e.key === 'ArrowDown' || e.key === 'PageDown') { e.preventDefault(); e.stopPropagation(); pptNext(); }
        else if (e.key === 'ArrowUp' || e.key === 'PageUp') { e.preventDefault(); e.stopPropagation(); pptPrev(); }
        else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); togglePPT(); }
        else if (e.key >= '1' && e.key <= '6') { e.preventDefault(); IPPT.handleKey(e.key); }
    }

    /* ── Trans (가로/세로 전환) ── */
    function toggleTrans() {
        _transOn = !_transOn;
        const btn = el('pv-trans-btn');
        document.body.classList.toggle('trans-mode', _transOn);
        if (btn) {
            btn.textContent = _transOn ? '↕ Portrait' : '↔ Trans';
        }
        /* 레이아웃이 바뀌므로 약간의 지연 후 다시 맞춤 */
        setTimeout(() => {
            const pc = el('preview-container');
            if (pptOn) {
                refresh();
            } else if (pc.classList.contains('slide-mode')) {
                /* 슬라이드 모드: 폰트/스케일만 재적용 */
                pc.style.fontSize = Math.round(_pvFontPt * (96 / 72)) + 'px';
                _updateFontLbl();
                if (scale !== 1.0) setScale(scale);
            } else {
                if (scale !== 1.0) setScale(scale);
                else fitToPane();
            }
        }, 80);
    }

    /* ── Dark 테마 ── */
    const PV_DARK_KEY = 'mdpro_pv_dark';
    let _darkOn = false;

    function setDark(on) {
        _darkOn = !!on;
        const pc = el('preview-container');
        const btn = el('pv-dark-btn');
        if (pc) pc.classList.toggle('pv-dark', _darkOn);
        if (btn) {
            btn.textContent = _darkOn ? '☀ Light' : '◑ Dark';
            btn.style.background = _darkOn ? 'rgba(100,160,255,.2)' : '';
            btn.style.color = _darkOn ? '#7ab8ff' : '';
            btn.style.borderColor = _darkOn ? '#5090ff' : 'rgba(100,160,255,.3)';
        }
        try { localStorage.setItem(PV_DARK_KEY, _darkOn ? '1' : '0'); } catch (e) {}
    }

    function toggleDark() {
        setDark(!_darkOn);
    }

    function initTheme() {
        try { setDark(localStorage.getItem(PV_DARK_KEY) === '1'); } catch (e) {}
    }

    /* 렌더 후 scale 유지. 첫 렌더 시에는 창에 맞게 자동 fit */
    let _firstRender = true;
    function refresh() {
        const pc = el('preview-container');
        if (_firstRender) {
            _firstRender = false;
            if (pc.classList.contains('slide-mode')) {
                pc.style.fontSize = Math.round(_pvFontPt * (96 / 72)) + 'px';
                _updateFontLbl();
            } else {
                requestAnimationFrame(() => fitToPane());
            }
            return;
        }
        if (pptOn) {
            /* PPT 모드 중 재렌더: 스타일 재적용 */
            setTimeout(() => {
                const pane = el('preview-pane');
                const vw = pane.clientWidth;
                const MM = 96 / 25.4;
                const origPx = Math.round(210 * MM);
                const ratio = vw / origPx;
                const fontPx = Math.round(_pvFontPt * (96 / 72) * ratio);
                const sel = pc.classList.contains('slide-mode') ? '.ppt-slide' : '.preview-page';
                pc.querySelectorAll(sel).forEach(p => {
                    p.style.width = vw + 'px';
                    p.style.padding = Math.round(22 * MM * ratio) + 'px ' + Math.round(18 * MM * ratio) + 'px';
                    p.style.minHeight = Math.round(297 * MM * ratio) + 'px';
                    p.style.marginBottom = '0';
                    p.style.boxSizing = 'border-box';
                    p.style.fontSize = fontPx + 'px';
                    p.style.lineHeight = '1.8';
                });
                const pages = getPages();
                el('ppt-pg').textContent = pages.length ? `${pptIdx + 1} / ${pages.length}` : '0 / 0';
            }, 50);
            return;
        }
        if (pc.classList.contains('slide-mode')) {
            pc.style.fontSize = Math.round(_pvFontPt * (96 / 72)) + 'px';
            _updateFontLbl();
        }
        if (scale !== 1.0) setScale(scale);
    }

    return { zoomIn, zoomOut, fitToPane, fontUp, fontDown, togglePPT, pptPrev, pptNext, refresh, toggleDark, setDark, initTheme, toggleTrans };
})();

/* ═══════════════════════════════════════════════════════════
   IPPT — 내부 PV PPT 드로잉 팔레트
   (ppt-nav 내 버튼으로 제어)
═══════════════════════════════════════════════════════════ */
const IPPT = (() => {
    let tool = 'laser', penColor = '#e63030', penSize = 4;
    let hlColor = '#ffe040', hlSize = 18, hlAlpha = 0.40;
    let drawing = false;
    let canvas, ctx, laserDot, container;
    let _init = false;

    function init() {
        if (!_init) {
            _init = true;
            canvas = document.getElementById('ippt-canvas');
            laserDot = document.getElementById('ippt-laser');
            container = document.getElementById('preview-container');
            if (!canvas || !container) return;

            /* 이벤트: 컨테이너 기준 좌표 사용 */
            document.addEventListener('mousemove', onMove);
            canvas.addEventListener('mousedown', onDown);
            document.addEventListener('mouseup', onUp);
        }
        /* 캔버스 크기는 매번 show() 시 갱신 (PPT 모드에서 크기가 바뀌므로) */
        _resizeCanvas();
    }

    function _resizeCanvas() {
        if (!canvas || !container) return;
        const w = container.scrollWidth || container.clientWidth;
        const h = container.scrollHeight || container.clientHeight;
        if (canvas.width === w && canvas.height === h) return; /* 변화 없으면 스킵 */
        const tmp = document.createElement('canvas');
        tmp.width = canvas.width; tmp.height = canvas.height;
        if (ctx) tmp.getContext('2d').drawImage(canvas, 0, 0);
        canvas.width = w; canvas.height = h;
        canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
        ctx = canvas.getContext('2d');
        if (tmp.width > 0) ctx.drawImage(tmp, 0, 0);
        /* ResizeObserver는 최초 1회만 등록 */
        if (!_resizeObserver) {
            _resizeObserver = new ResizeObserver(() => _resizeCanvas());
            _resizeObserver.observe(container);
        }
    }
    let _resizeObserver = null;

    function _updHlUI() {
        const sl = document.getElementById('ippt-hl-size-lbl');
        const al = document.getElementById('ippt-hl-alpha-lbl');
        if (sl) sl.textContent = hlSize;
        if (al) al.textContent = Math.round(hlAlpha * 100) + '%';
    }
    function setTool(t) {
        tool = t;
        /* ppt-nav 색상 피커·hl 컨트롤 표시 */
        const colorNav = document.getElementById('ippt-pen-color-nav');
        if (colorNav) colorNav.style.display = (t === 'pen' || t === 'hl') ? 'block' : 'none';
        const hlCtrl = document.getElementById('ippt-hl-ctrl');
        if (hlCtrl) { hlCtrl.style.display = (t === 'hl') ? 'flex' : 'none'; if (t === 'hl') _updHlUI(); }
        if (!canvas) return;
        if (t === 'laser') {
            canvas.style.pointerEvents = 'none';
            if (laserDot) laserDot.style.display = 'block';
        } else {
            canvas.style.pointerEvents = 'all';
            if (laserDot) laserDot.style.display = 'none';
        }
        canvas.style.cursor = (t === 'eraser') ? 'cell' : (t === 'pen' || t === 'hl') ? 'crosshair' : 'default';
    }

    function _canvasXY(e) {
        /* container 기준 좌표 (스크롤 포함) */
        const r = container.getBoundingClientRect();
        return {
            x: e.clientX - r.left + container.scrollLeft,
            y: e.clientY - r.top + container.scrollTop
        };
    }

    /* 형광펜 전용: 오프스크린 캔버스에 획 전체를 그린 뒤 한 번에 합성
       → 한 획 안에서 alpha가 누적되지 않아 농도가 일정하게 유지됨 */
    let _hlOffscreen = null, _hlOffCtx = null, _hlPoints = [];

    function _ensureHlOffscreen() {
        if (_hlOffscreen && _hlOffscreen.width === canvas.width && _hlOffscreen.height === canvas.height) return;
        _hlOffscreen = document.createElement('canvas');
        _hlOffscreen.width = canvas.width; _hlOffscreen.height = canvas.height;
        _hlOffCtx = _hlOffscreen.getContext('2d');
    }

    function _drawHlStroke() {
        if (!_hlOffCtx || _hlPoints.length < 2) return;
        _hlOffCtx.clearRect(0, 0, _hlOffscreen.width, _hlOffscreen.height);
        _hlOffCtx.beginPath();
        _hlOffCtx.moveTo(_hlPoints[0].x, _hlPoints[0].y);
        for (let i = 1; i < _hlPoints.length; i++) _hlOffCtx.lineTo(_hlPoints[i].x, _hlPoints[i].y);
        _hlOffCtx.strokeStyle = hlColor; _hlOffCtx.lineWidth = hlSize;
        _hlOffCtx.lineCap = 'round'; _hlOffCtx.lineJoin = 'round';
        _hlOffCtx.globalAlpha = 1; _hlOffCtx.globalCompositeOperation = 'source-over';
        _hlOffCtx.stroke();
        /* 오프스크린을 메인 캔버스에 globalAlpha로 한 번만 합성 */
        ctx.save();
        ctx.globalAlpha = hlAlpha;
        ctx.globalCompositeOperation = 'source-over';
        ctx.drawImage(_hlOffscreen, 0, 0);
        ctx.restore();
    }

    function onDown(e) {
        drawing = true;
        if (tool === 'pen' || tool === 'eraser') {
            const { x, y } = _canvasXY(e);
            ctx.beginPath();
            ctx.moveTo(x, y);
            _setCtxStyle();
        } else if (tool === 'hl') {
            _ensureHlOffscreen();
            _hlPoints = [_canvasXY(e)];
        }
    }

    function _setCtxStyle() {
        if (tool === 'eraser') {
            ctx.globalCompositeOperation = 'destination-out';
            ctx.globalAlpha = 1; ctx.lineWidth = 24; ctx.strokeStyle = 'rgba(0,0,0,1)';
        } else if (tool === 'pen') {
            ctx.globalCompositeOperation = 'source-over';
            ctx.globalAlpha = 1; ctx.strokeStyle = penColor; ctx.lineWidth = penSize;
        }
        ctx.lineCap = 'round'; ctx.lineJoin = 'round';
    }

    function onMove(e) {
        if (tool === 'laser' && laserDot) {
            const r = container.getBoundingClientRect();
            const x = e.clientX - r.left, y = e.clientY - r.top;
            const inBounds = x >= 0 && y >= 0 && x <= r.width && y <= r.height;
            laserDot.style.display = inBounds ? 'block' : 'none';
            /* 레이저 닷: viewport 기준 (fixed처럼 보여야 함) */
            laserDot.style.left = x + 'px';
            laserDot.style.top = (y + container.scrollTop) + 'px';
            return;
        }
        if (!drawing || !ctx) return;
        if (tool === 'pen' || tool === 'eraser') {
            const { x, y } = _canvasXY(e);
            ctx.lineTo(x, y); ctx.stroke(); ctx.beginPath(); ctx.moveTo(x, y);
        } else if (tool === 'hl') {
            _hlPoints.push(_canvasXY(e));
        }
    }

    function onUp() {
        if (drawing && tool === 'hl') {
            /* 획 완료: 오프스크린을 globalAlpha로 메인 캔버스에 한 번 합성 */
            _drawHlStroke();
            _hlPoints = [];
            if (_hlOffCtx) _hlOffCtx.clearRect(0, 0, _hlOffscreen.width, _hlOffscreen.height);
        }
        drawing = false;
        if (ctx) { ctx.globalAlpha = 1; ctx.globalCompositeOperation = 'source-over'; }
    }

    function clearAll() {
        if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height);
    }

    function show() {
        init(); /* 이벤트 등록 + 최초 크기 */
        if (canvas) canvas.style.display = 'block';
        setTool('laser');
        /* PPT 레이아웃 적용 후 캔버스 크기 재조정 */
        setTimeout(() => _resizeCanvas(), 120);
    }
    function hide() {
        if (canvas) canvas.style.display = 'none';
        if (laserDot) laserDot.style.display = 'none';
        clearAll(); tool = 'laser';
    }

    /* 단축키 (내부 PPT 모드 전용) */
    function handleKey(k) {
        if (k === '1') setTool('laser');
        else if (k === '2') setTool('select');
        else if (k === '4') setTool('pen');
        else if (k === '5') setTool('hl');
        else if (k === '6') setTool('eraser');
    }

    return {
        show, hide, setTool, clearAll, handleKey,
        setPenColor(col) {
            penColor = col;
            const n = document.getElementById('ippt-pen-color');
            const n2 = document.getElementById('ippt-pen-color-nav');
            if (n) n.value = col; if (n2) n2.value = col;
        },
        setPenSize(s) { penSize = +s },
        setHlColor(col) { hlColor = col },
        setHlSize(s) { hlSize = +s; _updHlUI(); },
        setHlAlpha(v) { hlAlpha = +v / 100; _updHlUI(); },
        hlSizeUp() { hlSize = Math.min(60, hlSize + 2); _updHlUI(); },
        hlSizeDown() { hlSize = Math.max(4, hlSize - 2); _updHlUI(); },
        hlAlphaUp() { hlAlpha = Math.min(0.90, +(hlAlpha + 0.05).toFixed(2)); _updHlUI(); },
        hlAlphaDown() { hlAlpha = Math.max(0.02, +(hlAlpha - 0.05).toFixed(2)); _updHlUI(); }
    };
})();



/* ═══════════════════════════════════════════════════════════
   A4Ruler — 미리보기 A4 페이지 구분 점선
   297mm(A4 높이) 간격으로 .preview-page 안에 직접 절대 위치 선을 삽입.
   overlay div 방식 대신 페이지 내부 삽입 방식 사용:
   - innerHTML 초기화에 영향받지 않도록 렌더 후 refresh()로 재삽입
   - offsetTop 좌표계 문제 없음 (페이지 자신 기준 절대 좌표)
   - scale/zoom에 자동 대응 (페이지가 stretch되면 선도 같이 stretch)
═══════════════════════════════════════════════════════════ */
const A4Ruler = (() => {
    let on = false;
    const LINE_CLASS = 'a4-rl';
    const LABEL_CLASS = 'a4-rl-label';

    /* 실제 화면상 페이지 높이 기준 297mm가 몇 px인지 계산.
       scale/zoom이 적용된 실제 렌더 크기를 사용한다.
       - offsetWidth: CSS transform 이전 논리 px (scale 무시)
       - getBoundingClientRect().width: 실제 화면 px (scale 반영)
       두 값의 비율 = zoom factor                                   */
    function getA4Px(page) {
        const MM = 96 / 25.4;           // 1mm = 3.7795px at 96dpi
        const cssW = 210 * MM;          // 210mm의 기준 CSS px
        const renderW = page.getBoundingClientRect().width;
        const scale = renderW / cssW;   // 실제 zoom scale
        return Math.round(297 * MM * scale);
    }

    /* 한 페이지 안에 A4 구분선 삽입.
       기준: page 자체의 높이(getBoundingClientRect) 안에서 297mm*n마다 선 */
    function drawPage(page) {
        /* 기존 선 제거 */
        page.querySelectorAll('.' + LINE_CLASS).forEach(el => el.remove());
        if (!on) return;

        const pageH = page.getBoundingClientRect().height;
        const gap = getA4Px(page);
        let n = 1;
        while (n * gap < pageH - 2) {
            /* top 값: 페이지 내부 기준이므로 scale을 역산해 CSS px로 변환 */
            const cssH = page.offsetHeight;
            const scale = pageH / cssH;
            const topCss = Math.round((n * gap) / scale);

            const line = document.createElement('div');
            line.className = LINE_CLASS;
            line.style.top = topCss + 'px';

            const label = document.createElement('span');
            label.className = LABEL_CLASS;
            label.textContent = (297 * n) + ' mm';
            line.appendChild(label);

            page.appendChild(line);
            n++;
        }
    }

    function drawAll() {
        const pages = document.querySelectorAll('#preview-container .preview-page');
        pages.forEach(drawPage);
    }

    function clearAll() {
        document.querySelectorAll('#preview-container .' + LINE_CLASS).forEach(el => el.remove());
    }

    return {
        toggle() {
            on = !on;
            const btn = el('a4-ruler-btn');
            btn.classList.toggle('active', on);
            btn.textContent = on ? '📄 A4 ✓' : '📄 A4';
            if (on) drawAll();
            else clearAll();
        },
        /* 렌더 직후 호출 — 새로 생성된 페이지에 선 재삽입 */
        refresh() {
            if (!on) return;
            /* 한 프레임 대기 후 실행: MathJax/이미지 등 레이아웃 확정 대기 */
            requestAnimationFrame(() => drawAll());
        },
    };
})();


/* ═══════════════════════════════════════════════════════════
   CP — 미리보기 복사 매니저
   📋 복사  : ClipboardItem으로 HTML + plaintext 동시 등록
              → Word / 구글독스 / 한글 붙여넣기 시 서식 유지
   Ａ 텍스트: 순수 텍스트만 (innerText 추출)
═══════════════════════════════════════════════════════════ */
const CP = (() => {

    /* preview-container 내 모든 .preview-page를 합친 HTML 스냅샷 */
    function getPageNodes() {
        return [...el('preview-container').querySelectorAll('.preview-page')];
    }

    /* 복사용 HTML 생성
       - 페이지 번호 가상요소(::after)는 복사 대상이 아니므로 제거
       - 외부 문서에서도 기본 서식이 살아있도록 인라인 스타일 기반 wrapper 추가 */
    function buildHtml(nodes) {
        // 각 페이지 innerHTML 합치기 (페이지 구분은 <hr>)
        const parts = nodes.map((n, i) => {
            // data-page 속성 및 ::after 등은 복사본에 불필요 → cloneNode
            const clone = n.cloneNode(true);
            // 페이지 번호 표시용 after 콘텐츠는 DOM에 없으므로 무시
            return clone.innerHTML;
        });
        const body = parts.join('\n<hr style="border:none;border-top:1px dashed #ccc;margin:18px 0">\n');

        // Word·구글독스 호환 wrapper — 기본 폰트·줄간격 설정
        return `<div style="font-family:serif;font-size:11pt;line-height:1.8;color:#1a1a2e;max-width:170mm;word-break:break-word">${body}</div>`;
    }

    /* 버튼 피드백 애니메이션 */
    function flash(btnId, successLabel, color) {
        const btn = el(btnId);
        const orig = btn.textContent;
        const origColor = btn.style.color;
        btn.textContent = successLabel;
        btn.style.color = color || '#6af7a0';
        btn.style.opacity = '0.7';
        setTimeout(() => {
            btn.textContent = orig;
            btn.style.color = origColor;
            btn.style.opacity = '';
        }, 1600);
    }

    return {
        /* ── 서식 있는 복사 ── */
        async copyRich() {
            const nodes = getPageNodes();
            if (!nodes.length) { alert('미리보기 내용이 없습니다.'); return; }

            const htmlStr = buildHtml(nodes);
            // 순수 텍스트 fallback
            const textStr = nodes.map(n => n.innerText).join('\n\n');

            try {
                // ClipboardItem API — HTML + text/plain 동시 등록
                if (window.ClipboardItem) {
                    const htmlBlob = new Blob([htmlStr], { type: 'text/html' });
                    const textBlob = new Blob([textStr], { type: 'text/plain' });
                    await navigator.clipboard.write([
                        new ClipboardItem({ 'text/html': htmlBlob, 'text/plain': textBlob })
                    ]);
                } else {
                    // fallback: execCommand (구형 브라우저)
                    const tmp = document.createElement('div');
                    tmp.innerHTML = htmlStr;
                    tmp.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
                    document.body.appendChild(tmp);
                    const range = document.createRange();
                    range.selectNodeContents(tmp);
                    const sel = window.getSelection();
                    sel.removeAllRanges();
                    sel.addRange(range);
                    document.execCommand('copy');
                    sel.removeAllRanges();
                    document.body.removeChild(tmp);
                }
                flash('copy-rich-btn', '✓ 복사됨', '#6af7a0');
            } catch (err) {
                // 권한 거부 시 텍스트로 fallback
                try {
                    await navigator.clipboard.writeText(textStr);
                    flash('copy-rich-btn', '✓ 텍스트로 복사', '#f7d06a');
                } catch (e2) {
                    alert('클립보드 복사에 실패했습니다.\n브라우저 주소창을 한 번 클릭한 뒤 다시 시도해 주세요.');
                }
            }
        },

        /* ── 텍스트만 복사 ── */
        async copyText() {
            const nodes = getPageNodes();
            if (!nodes.length) { alert('미리보기 내용이 없습니다.'); return; }

            // innerText: 가시적 텍스트 + 줄바꿈 구조 유지
            const text = nodes.map(n => n.innerText.trim()).join('\n\n');
            try {
                await navigator.clipboard.writeText(text);
                flash('copy-text-btn', '✓ 복사됨', '#6af7a0');
            } catch (err) {
                alert('클립보드 복사에 실패했습니다.');
            }
        },
    };
})();

/* ═══════════════════════════════════════════════════════════
   PREVIEW WINDOW (popup) + scroll sync
═══════════════════════════════════════════════════════════ */
const PW = (() => {
    let win = null, st = null, rm = false, _lastOpenWasSlide = false;
    const CSS = `@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&display=swap');
*{box-sizing:border-box;margin:0;padding:0}body{font-family:sans-serif;background:#6a6e7e;display:flex;flex-direction:column;align-items:center;padding:16px 0 36px;min-height:100vh}
.preview-page{width:210mm;min-height:297mm;background:white;color:#1a1a2e;padding:22mm 18mm;box-shadow:0 6px 40px rgba(0,0,0,.5);font-family:'Libre Baskerville',serif;font-size:11pt;line-height:1.8;word-break:break-word;position:relative;margin-bottom:16px}
.preview-page::after{content:"— " attr(data-page) " —";position:absolute;bottom:10mm;left:50%;transform:translateX(-50%);font-family:sans-serif;font-size:9pt;color:#bbb}
.preview-page h1{font-size:21pt;font-weight:700;margin:0 0 14px;border-bottom:2px solid #1a1a2e;padding-bottom:8px}
.preview-page h2{font-size:15pt;font-weight:700;margin:20px 0 10px}.preview-page h3{font-size:12pt;font-weight:700;margin:16px 0 7px}
.preview-page p{margin:0 0 11px}.preview-page ul,.preview-page ol{margin:0 0 11px;padding-left:22px}.preview-page li{margin-bottom:3px}
.preview-page blockquote{border-left:3px solid #5b4ce4;margin:14px 0;padding:7px 14px;background:#f5f5ff;font-style:italic}
.preview-page code{font-family:'JetBrains Mono',monospace;font-size:9pt;background:#f0f0f8;padding:1px 4px;border-radius:3px;color:#5b4ce4}
.preview-page pre{background:#1a1a2e;color:#e8e8f0;padding:14px;border-radius:6px;overflow-x:auto;margin:11px 0;font-size:9pt}
.preview-page pre code{background:none;color:inherit;padding:0}
.preview-page table{width:100%;border-collapse:collapse;margin:11px 0;font-size:inherit}
.preview-page th{background:#e8e8f0;color:#1a1a2e;padding:7px 11px;text-align:left;font-weight:600;border:1px solid #c0c0d8}
.preview-page td{padding:6px 11px;border:1px solid #d0d0e0}
.preview-page tr:nth-child(even) td{background:#f7f7fc}
.preview-page img{max-width:100%}
.preview-page a{color:#5b4ce4;text-decoration:underline}
.preview-page a[href^="http"]::after{content:" ↗";font-size:8pt;opacity:.5}
.preview-page .ref-block{border-top:1px solid #d0d0e0;margin-top:28px;padding-top:10px;font-size:9pt;color:#4a4a6a}
.preview-page.rm p{padding-left:42px;position:relative}
.rm-ln{position:absolute;left:0;top:0;width:34px;text-align:right;font-family:'JetBrains Mono',monospace;font-size:8pt;line-height:inherit;color:#a0a0c8;user-select:none;pointer-events:none;border-right:1px solid #ddd;padding-right:5px;height:1.8em;overflow:hidden}
@media print{body{background:none;padding:0}.preview-page{box-shadow:none;margin:0;page-break-after:always;width:100%;min-height:0}.preview-page:last-child{page-break-after:auto}/* page number visible in print */.a4-rl,.a4-rl-label{display:none!important}}`;

    function buildHTML(md, title, opts) {
        opts = opts || {};
        const slideMode = !!opts.slideMode;
        const pages = splitPages(md);
        let html;
        if (slideMode) {
            html = pages.map((p, i) => {
                const parsed = parseSlideContent(p);
                const warnClass = parsed.bullets.length > 6 ? ' slide-bullet-warn' : '';
                const warnMsg = parsed.bullets.length > 6 ? '<span class="slide-bullet-warn-msg">⚠ bullet 6개 초과</span>' : '';
                return `<div class="ppt-slide${warnClass}" data-slide-index="${i + 1}"><div class="slide-inner">${mdRender(p)}</div><span class="slide-num">${i + 1}</span>${warnMsg}</div>`;
            }).join('');
        } else {
            html = pages.map((p, i) => `<div class="preview-page${rm ? ' rm' : ''}" data-page="${i + 1}">${mdRender(p)}</div>`).join('');
        }
        const PW_SLIDE_CSS = slideMode ? `
body.pw-slide-mode{background:#2a2e3e}
body.pw-slide-mode #body-inner{display:flex;flex-direction:column;align-items:center;padding:40px 16px 60px;overflow-y:auto;scroll-snap-type:y mandatory;scroll-behavior:smooth}
body.pw-slide-mode .ppt-slide{width:960px;max-width:100%;aspect-ratio:16/9;background:#1a1e2e;margin:40px auto;padding:60px;box-shadow:0 20px 60px rgba(0,0,0,.4);border-radius:12px;position:relative;flex-shrink:0;box-sizing:border-box;scroll-snap-align:start}
body.pw-slide-mode .ppt-slide .slide-inner{width:100%;height:100%;overflow:hidden;position:relative;color:#e0e0ec;font-size:1em}
body.pw-slide-mode .ppt-slide h1{font-size:2em;margin:0 0 24px;color:#fff;border-bottom:none;padding-bottom:0}
body.pw-slide-mode .ppt-slide h2{font-size:1.5em;margin:16px 0 12px;color:#e8e8f0}
body.pw-slide-mode .ppt-slide h3{font-size:1.25em;margin:12px 0 8px;color:#d8d8e8}
body.pw-slide-mode .ppt-slide ul,body.pw-slide-mode .ppt-slide ol{font-size:1.25em;line-height:1.6;margin:12px 0;padding-left:28px}
body.pw-slide-mode .ppt-slide p{margin:0 0 12px;font-size:1.125em;line-height:1.5}
body.pw-slide-mode .ppt-slide .slide-num{position:absolute;bottom:16px;right:24px;font-size:0.75em;color:rgba(255,255,255,.4)}
body.pw-slide-mode .ppt-slide.slide-bullet-warn{outline:2px solid #f39c12;outline-offset:2px}
body.pw-slide-mode .ppt-slide .slide-bullet-warn-msg{position:absolute;top:8px;right:8px;font-size:0.625em;color:#f39c12;background:rgba(243,156,18,.2);padding:2px 8px;border-radius:4px}
/* 슬라이드 모드 + Trans(세로) */
body.pw-slide-mode.trans-mode .ppt-slide{width:540px;max-width:100%;aspect-ratio:9/16}
/* 슬라이드 모드 + 다크 테마 */
body.pw-slide-mode.dark-theme .ppt-slide{background:#1a1a2e;color:#e8e8f0}
body.pw-slide-mode.dark-theme .ppt-slide h1,body.pw-slide-mode.dark-theme .ppt-slide h2,body.pw-slide-mode.dark-theme .ppt-slide h3{color:#a8b8ff}
body.pw-slide-mode.dark-theme .ppt-slide a{color:#6acff7}
body.pw-slide-mode.dark-theme .ppt-slide code{background:#2a2a3e;color:#f7a06a}
body.pw-slide-mode.dark-theme .ppt-slide blockquote{border-left-color:#7c6af7;color:#d4d0f0;background:rgba(40,35,80,.6)}
body.pw-slide-mode.dark-theme .ppt-slide .slide-num{color:rgba(255,255,255,.35)}
` : '';
        const bodyClass = slideMode ? ' class="pw-slide-mode"' : '';
        const A4_CSS = `
/* ── PV 툴바 ── */
#pw-toolbar{position:fixed;top:0;left:0;right:0;height:36px;background:rgba(20,20,32,.93);
  backdrop-filter:blur(8px);border-bottom:1px solid rgba(255,255,255,.1);
  display:flex;align-items:center;padding:0 10px;gap:5px;z-index:10000;font-family:monospace}
#pw-toolbar button{background:none;border:1px solid rgba(255,255,255,.18);border-radius:4px;
  color:#ccc;cursor:pointer;font-size:11px;padding:2px 9px;height:24px;transition:all .15s;white-space:nowrap}
#pw-toolbar button:hover{background:rgba(255,255,255,.12);color:#fff;border-color:rgba(255,255,255,.45)}
#pw-toolbar button.active{background:rgba(240,192,96,.22);color:#f7d06a;border-color:#f0c060}
#pw-toolbar button.active-dark{background:rgba(80,140,255,.22);color:#7ab8ff;border-color:#5090ff}
#pw-toolbar .sep{width:1px;height:18px;background:rgba(255,255,255,.13);flex-shrink:0}
#pw-toolbar .lbl{font-size:10px;color:rgba(255,255,255,.38);flex-shrink:0}
#pw-toolbar #pw-zoom-lbl{font-size:10px;color:#6acff7;min-width:36px;text-align:center}
#pw-toolbar .spacer{flex:1}
/* PPT 네비 */
#pw-ppt-nav{display:none;position:fixed;bottom:22px;left:50%;transform:translateX(-50%);
  z-index:10001;background:rgba(0,0,0,.75);border:1px solid rgba(255,255,255,.2);
  border-radius:28px;padding:6px 16px;gap:10px;align-items:center;backdrop-filter:blur(10px)}
#pw-ppt-nav.vis{display:flex}
#pw-ppt-nav button{background:none;border:none;color:#fff;cursor:pointer;font-size:22px;
  padding:0 6px;border-radius:12px;line-height:1;transition:background .15s}
#pw-ppt-nav button:hover{background:rgba(255,255,255,.18)}
#pw-ppt-nav #pw-ppt-pg{font-size:12px;color:rgba(255,255,255,.78);min-width:56px;text-align:center;font-family:monospace}
body{padding-top:36px;margin:0;background:#555}
html,body{overflow-x:hidden}
/* body-inner: 기본 — 고정 너비 페이지를 중앙에 표시 */
#body-inner{
  display:flex;
  flex-direction:column;
  align-items:center;
  padding:16px 0 48px;
}
/* PPT 모드 */
body.ppt-mode{background:#000;padding-top:36px}
body.ppt-mode #body-inner{
  display:block;
  padding:0;
  height:calc(100vh - 36px);
  overflow:hidden;
}
/* 프레젠테이션 도구 오버레이 */
#pres-overlay{
  position:fixed;inset:0;top:36px;
  z-index:20000;
  pointer-events:none;
  cursor:default;
}
#pres-overlay.mode-pointer{pointer-events:none;cursor:none}
#pres-overlay.mode-pan{pointer-events:all;cursor:grab}
#pres-overlay.mode-pan:active{cursor:grabbing}
#pres-overlay.mode-pen{pointer-events:all;cursor:crosshair}
#pres-overlay.mode-hl{pointer-events:all;cursor:crosshair}
#pres-canvas{position:absolute;inset:0;width:100%;height:100%}
/* 포인터 레이저 닷 */
#laser-dot{
  display:none;
  position:fixed;
  width:18px;height:18px;
  border-radius:50%;
  background:rgba(255,30,30,.92);
  box-shadow:0 0 8px 4px rgba(255,60,60,.6),0 0 20px 8px rgba(255,0,0,.3);
  pointer-events:none;
  z-index:20001;
  transform:translate(-50%,-50%);
  transition:opacity .1s;
}
/* 프레젠테이션 툴바 */
/* ═══ pres-toolbar: PPT 모드 도구 툴바 ═══
   기본(pos-top): 상단 toolbar 아래 수평바
   pos-bottom: 화면 하단 중앙
   pos-right: 화면 우측 중앙 수직
   pos-left: 화면 좌측 중앙 수직 */
#pres-toolbar{
  display:none;
  position:fixed;
  /* 기본: 상단 toolbar 바로 아래 */
  top:40px; left:50%; transform:translateX(-50%);
  z-index:20002;
  background:rgba(10,10,22,.92);
  border:1px solid rgba(255,255,255,.22);
  border-radius:28px;
  padding:5px 14px; gap:6px;
  align-items:center;
  backdrop-filter:blur(12px);
  white-space:nowrap;
}
#pres-toolbar.vis{ display:flex }
/* 하단 */
#pres-toolbar.pos-bottom{
  top:auto; bottom:68px; left:50%; transform:translateX(-50%);
  flex-direction:row;
}
/* 우측 */
#pres-toolbar.pos-right{
  top:50%; left:auto; right:10px; transform:translateY(-50%);
  flex-direction:column; border-radius:16px; padding:10px 6px;
}
/* 좌측 */
#pres-toolbar.pos-left{
  top:50%; left:10px; right:auto; transform:translateY(-50%);
  flex-direction:column; border-radius:16px; padding:10px 6px;
}
#pres-toolbar button{
  background:none;border:1px solid rgba(255,255,255,.15);
  border-radius:8px;color:#ccc;cursor:pointer;font-size:13px;
  padding:3px 9px;height:28px;transition:all .15s;white-space:nowrap;
  display:flex;align-items:center;gap:4px;
}
#pres-toolbar button:hover{background:rgba(255,255,255,.12);color:#fff}
#pres-toolbar button.active-tool{background:rgba(240,192,96,.25);color:#f7d06a;border-color:#f0c060}
#pres-toolbar .pt-sep{width:1px;height:18px;background:rgba(255,255,255,.15)}
#pres-toolbar input[type=color]{width:26px;height:26px;border:none;background:none;cursor:pointer;padding:0;border-radius:4px}
#pres-toolbar input[type=range]{width:60px;accent-color:#f7d06a}
/* Trans 가로 모드 */
body.trans-mode .preview-page{width:297mm;min-height:210mm;padding:15mm 22mm}
/* Dark 반전 테마 */
body.dark-theme{background:#111}
body.dark-theme .preview-page{background:#1a1a2e;color:#e8e8f0}
body.dark-theme .preview-page h1,body.dark-theme .preview-page h2,
body.dark-theme .preview-page h3{color:#a8b8ff}
body.dark-theme .preview-page a{color:#6acff7}
body.dark-theme .preview-page code{background:#2a2a3e;color:#f7a06a}
body.dark-theme .preview-page blockquote{
  border-left-color:#7c6af7;
  color:#d4d0f0;
  background:rgba(40,35,80,.6);
  border-radius:0 6px 6px 0;
}
body.dark-theme .preview-page blockquote p{color:#d4d0f0}
body.dark-theme .preview-page blockquote blockquote{
  border-left-color:#a090ff;
  color:#c0bce8;
  background:rgba(50,45,90,.5);
}
body.dark-theme .preview-page table{color:#e8e8f0 !important;font-size:inherit !important}
body.dark-theme .preview-page table th{background:#252540 !important;color:#c8d8ff !important;border-color:#4a4a68 !important}
body.dark-theme .preview-page table td{border-color:#3a3a58 !important;background:transparent !important;color:#e8e8f0 !important}
body.dark-theme .preview-page table tr:nth-child(even) td{background:#20203a !important;color:#e8e8f0 !important}
body.dark-theme .preview-page table *{color:#e8e8f0 !important}
body.dark-theme .preview-page table th *{color:#c8d8ff !important}
@media print{body{background:none;padding:0}.preview-page{box-shadow:none;margin:0;page-break-after:always;width:100%;min-height:0}.preview-page:last-child{page-break-after:auto}/* page number visible in print */.a4-rl,.a4-rl-label{display:none!important}}
/* ── A4 구분선 오버레이 ── */
#a4-overlay{
  position:absolute;left:0;top:0;right:0;
  pointer-events:none;z-index:50;display:none;
}
#a4-overlay.vis{display:block}
.a4-rl{
  position:absolute;left:0;right:0;height:2px;
  background:repeating-linear-gradient(to right,rgba(220,35,35,.85) 0,rgba(220,35,35,.85) 6px,transparent 6px,transparent 12px);
  pointer-events:none;
}
.a4-rl-label{
  position:absolute;right:6px;top:-15px;font-size:9px;font-family:monospace;
  color:rgba(220,35,35,.9);background:rgba(255,255,255,.92);
  border:1px solid rgba(220,35,35,.3);padding:0 5px;border-radius:3px;
  pointer-events:none;user-select:none;white-space:nowrap;
}
#pw-a4-btn.active{background:rgba(240,96,96,.22)!important;color:#ff8888!important;border-color:#f06060!important}`;

        return `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>${title || 'Preview'}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/mathjax/3.2.2/es5/tex-mml-chtml.min.js"><\/script>
<style>${CSS}${A4_CSS}${PW_SLIDE_CSS}<\/style></head>
<body${bodyClass}>
<div id="pw-toolbar">
  <button onclick="window.print()" title="인쇄 / PDF">🖨 인쇄</button>
  <button onclick="pwDownload()" title="현재 HTML 저장">💾 저장</button>
  <div class="sep"></div>
  <button onclick="pwZoomOut()" title="페이지 축소">－</button>
  <span id="pw-zoom-lbl" title="현재 배율">100%</span>
  <button onclick="pwZoomIn()" title="페이지 확대">＋</button>
  <button onclick="pwZoomReset()" title="100%로 초기화">↺</button>
  <div class="sep"></div>
  <button id="pw-ppt-btn" onclick="pwTogglePPT()" title="PPT 프레젠테이션 모드">🎬 PPT</button>
  <button id="pw-trans-btn" onclick="pwToggleTrans()" title="페이지 방향 전환">↔ Trans</button>
  <button id="pw-dark-btn" onclick="pwToggleDark()" title="다크 테마">◑ Dark</button>
  <button onclick="pwFullscreen()" title="전체화면 (F11)">⛶ 전체화면</button>
  <div class="spacer"></div>
  <span class="lbl" style="color:rgba(255,255,255,.4);font-size:9px">폰트</span>
  <button onclick="pwFontDown()" title="폰트 축소 (텍스트만)">ᴬ－</button>
  <span id="pw-font-lbl" style="color:#6acff7;font-size:10px;min-width:30px;text-align:center">11pt</span>
  <button onclick="pwFontUp()" title="폰트 확대 (텍스트만)">ᴬ＋</button>
  <button onclick="pwFontReset()" title="폰트 초기화">↺</button>
  <div class="sep"></div>
  <button id="pw-a4-btn" onclick="pwToggleA4()" title="A4 구분선 — 297mm 간격 점선 표시" style="color:#f06060;border-color:rgba(240,96,96,.4);font-size:10px;padding:0 7px;height:24px;font-weight:600">📄 A4</button>
  <div class="sep"></div>
  <button id="pw-sync-btn" onclick="pwToggleSync()" title="에디터 스크롤 동기화 ON/OFF"
    style="background:rgba(106,247,176,.15);border-color:rgba(106,247,176,.4);color:#6af7b0;font-size:10px;padding:0 8px;height:24px;font-weight:600">
    🔗 동기화 ON</button>
  <div class="sep"></div>
  <span class="lbl" id="pw-pg-lbl" style="color:rgba(255,255,255,.5)"></span>
</div>
<div id="body-inner">
  ${html}
</div>
<!-- 프레젠테이션 도구 오버레이 -->
<div id="pres-overlay" style="display:none">
  <canvas id="pres-canvas"></canvas>
</div>
<div id="laser-dot"></div>
</div>
<!-- 프레젠테이션 도구 툴바 (PPT 모드에서 표시, 위치 변경 가능) -->
<div id="pres-toolbar">
  <button onclick="PRES.cyclePos()" id="pt-pos-btn" title="툴바 위치: 상단→하단→우측→좌측 [P]" style="font-size:11px">📌</button>
  <div class="pt-sep"></div>
  <button class="pt-tool active-tool" data-tool="laser" onclick="PRES.setTool('laser')" title="레이저 포인터 [1]">❶🔴</button>
  <button class="pt-tool" data-tool="select" onclick="PRES.setTool('select')" title="선택 [2]">❷↖</button>
  <button class="pt-tool" data-tool="pan" onclick="PRES.setTool('pan')" title="이동 [3]">❸✋</button>
  <div class="pt-sep"></div>
  <button class="pt-tool" data-tool="pen" onclick="PRES.setTool('pen')" title="펜 [4]">❹✏</button>
  <span id="pt-pen-opts" style="display:none;align-items:center;gap:3px">
    <input type="color" id="pt-pen-color" value="#e63030" onchange="PRES.setPenColor(this.value)">
    <input type="range" min="1" max="20" value="4" oninput="PRES.setPenSize(this.value)" style="width:60px">
  </span>
  <button class="pt-tool" data-tool="hl" onclick="PRES.setTool('hl')" title="형광펜 [5]">❺🖊</button>
  <span id="pt-hl-opts" style="display:none;align-items:center;gap:3px">
    <input type="color" id="pt-hl-color" value="#ffe040" onchange="PRES.setHlColor(this.value)" title="형광펜 색상">
    <span title="굵기" style="font-size:9px;color:#aaa">굵</span>
    <button onclick="PRES.hlSizeDown()" title="굵기 감소" style="font-size:10px;padding:0 4px;height:20px;background:none;border:1px solid rgba(255,255,255,.2);border-radius:4px;color:#ddd;cursor:pointer">－</button>
    <span id="pt-hl-size-lbl" style="font-size:10px;color:#ffe040;min-width:20px;text-align:center">18</span>
    <button onclick="PRES.hlSizeUp()" title="굵기 증가" style="font-size:10px;padding:0 4px;height:20px;background:none;border:1px solid rgba(255,255,255,.2);border-radius:4px;color:#ddd;cursor:pointer">＋</button>
    <span title="투명도" style="font-size:9px;color:#aaa;margin-left:4px">α</span>
    <button onclick="PRES.hlAlphaDown()" title="투명도 감소 (더 연하게)" style="font-size:10px;padding:0 4px;height:20px;background:none;border:1px solid rgba(255,255,255,.2);border-radius:4px;color:#ddd;cursor:pointer">－</button>
    <span id="pt-hl-alpha-lbl" style="font-size:10px;color:#ffe040;min-width:24px;text-align:center">10%</span>
    <button onclick="PRES.hlAlphaUp()" title="투명도 증가 (더 진하게)" style="font-size:10px;padding:0 4px;height:20px;background:none;border:1px solid rgba(255,255,255,.2);border-radius:4px;color:#ddd;cursor:pointer">＋</button>
  </span>
  <button class="pt-tool" data-tool="eraser" onclick="PRES.setTool('eraser')" title="지우개 [6]">❻⬜</button>
  <div class="pt-sep"></div>
  <button onclick="PRES.clearCanvas()" title="전체 지우기" style="color:#f08080">🗑</button>
</div>
<div id="pw-ppt-nav">
  <button onclick="pwPptPrev()" title="이전 (← ↑ PageUp)">◀</button>
  <span id="pw-ppt-pg">1 / 1</span>
  <button onclick="pwPptNext()" title="다음 (→ ↓ PageDown Space)">▶</button>
  <button onclick="pwTogglePPT()" style="font-size:13px;opacity:.55;margin-left:4px" title="PPT 종료 (Esc)">✕</button>
</div>
<script>
document.querySelectorAll('a').forEach(a=>{a.target='_blank';a.rel='noopener noreferrer'});
/* Research Mode 단락 번호 */
(function(){let n=1;document.querySelectorAll('.preview-page').forEach(pg=>{pg.querySelectorAll(':scope>p').forEach(p=>{const s=document.createElement('span');s.className='rm-ln';s.textContent=n++;s.setAttribute('aria-hidden','true');p.insertBefore(s,p.firstChild)})})})();
/* ── 스크롤 동기화 (헤딩 기반, on/off 가능) ── */
let _syncEnabled = true;

function pwToggleSync() {
  _syncEnabled = !_syncEnabled;
  const btn = document.getElementById('pw-sync-btn');
  if (btn) {
    btn.textContent = _syncEnabled ? '🔗 동기화 ON' : '🔗 동기화 OFF';
    btn.style.background = _syncEnabled ? 'rgba(106,247,176,.15)' : 'rgba(255,255,255,.06)';
    btn.style.borderColor = _syncEnabled ? 'rgba(106,247,176,.4)' : 'rgba(255,255,255,.2)';
    btn.style.color = _syncEnabled ? '#6af7b0' : '#888';
  }
  try { if (window.opener) window.opener.postMessage({ type: 'pwSyncState', enabled: _syncEnabled }, '*'); } catch(e) {}
}

/* ── 에디터 → 새창 스크롤 수신 ─────────────────────────────
   getBoundingClientRect 기반으로 헤딩 Y 계산 (offsetTop 중첩 버그 수정) */
function _pwAbsY(id) {
  /* window가 스크롤 컨테이너 (일반 모드) — window.scrollY 기반 */
  const h = document.querySelector('#' + CSS.escape(id));
  if (!h) return null;
  return window.scrollY + h.getBoundingClientRect().top;
}

window.addEventListener('message', e => {
  if (!e.data) return;

  /* ── pvUpdate: 내용만 교체 (JS 상태 완전 보존) ── */
  if (e.data.type === 'pvUpdate') {
    const bi = document.getElementById('body-inner');
    if (!bi) return;
    const sy = window.scrollY; /* 현재 스크롤 위치 저장 */
    bi.innerHTML = e.data.html || '';
    document.body.classList.toggle('pw-slide-mode', !!e.data.slideMode);
    if (e.data.title) document.title = e.data.title;
    /* scale / font 재적용 (기존 값 그대로 유지) */
    if (typeof _applyScale === 'function') _applyScale();
    /* PPT 모드이면 레이아웃 재적용 */
    if (_pptOn && typeof _pptApply === 'function') _pptApply();
    /* RM 단락번호 재삽입 */
    if (e.data.rm) {
      let n = 1;
      bi.querySelectorAll('.preview-page').forEach(pg => {
        pg.querySelectorAll(':scope>p').forEach(p => {
          const s = document.createElement('span');
          s.className = 'rm-ln'; s.textContent = n++;
          s.setAttribute('aria-hidden','true');
          p.insertBefore(s, p.firstChild);
        });
      });
    }
    /* 링크 새창 열기 */
    bi.querySelectorAll('a').forEach(a => { a.target='_blank'; a.rel='noopener noreferrer'; });
    /* 스크롤 복원 */
    requestAnimationFrame(() => window.scrollTo(0, sy));
    return;
  }

  if (e.data.type === 'pwToggleSync') { pwToggleSync(); return; }

  if (!_syncEnabled) return;
  if (e.data.type === 'ss') {
    if (_pptOn) return; /* PPT 모드 중에는 동기화 무시 */
    const anchor = e.data.anchor;
    if (anchor && anchor.id) {
      const y0 = _pwAbsY(anchor.id);
      if (y0 !== null) {
        const y1 = anchor.nextId ? _pwAbsY(anchor.nextId) : null;
        const docH = document.documentElement.scrollHeight;
        const seg = y1 !== null ? Math.max(0, y1 - y0) : Math.max(0, docH - y0);
        window.scrollTo(0, y0 + seg * (anchor.ratio || 0));
        return;
      }
    }
    /* 헤딩 없으면 비율 fallback */
    if (typeof e.data.ratio === 'number') {
      const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
      window.scrollTo(0, e.data.ratio * maxScroll);
    }
  }
});
setTimeout(function(){ try { if (window.opener) window.opener.postMessage({ type: 'pwSyncState', enabled: _syncEnabled }, '*'); } catch(e) {} }, 150);

/* 새창 → 에디터 방향 스크롤 알림 (window scroll 기반) */
let _st;
window.addEventListener('scroll', () => {
  if (_pptOn) return; /* PPT 모드 중에는 전송 안 함 */
  clearTimeout(_st); _st = setTimeout(() => {
    const r = window.scrollY / Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
    try { window.opener.postMessage({ type: 'pvS', ratio: r }, '*'); } catch(e) {}
  }, 10);
}, { passive: true });

/* ══ 확대/축소 ══
   내부 PV와 동일한 방식: 페이지 width를 px로 직접 설정.
   확대 시 body-inner(flex center)가 중앙 정렬을 보장.
*/
let _scale=1.0;
const MIN_S=0.2, MAX_S=5.0, STEP_S=0.15;
const _MM=96/25.4;
const _A4W_PX=Math.round(210*_MM); /* ≈794 */

let _fontPt=11; /* 기본 폰트 크기(pt) */
const FONT_MIN=6,FONT_MAX=24,FONT_STEP=1;

function _applyScale(){
  if(_pptOn) return;
  if(document.body.classList.contains('pw-slide-mode')){
    const slides=document.querySelectorAll('.ppt-slide');
    const baseW=document.body.classList.contains('trans-mode')?540:960;
    const w=Math.round(baseW*_scale);
    const fontPx=Math.round(_fontPt*(96/72));
    slides.forEach(s=>{
      s.style.width=w+'px';
      s.style.maxWidth='100%';
      s.style.fontSize=fontPx+'px';
      s.style.lineHeight='1.8';
      const inner=s.querySelector('.slide-inner');
      if(inner) inner.style.fontSize=fontPx+'px';
    });
    const zl=document.getElementById('pw-zoom-lbl');
    if(zl)zl.textContent=Math.round(_scale*100)+'%';
    const lbl=document.getElementById('pw-font-lbl');
    if(lbl)lbl.textContent=_fontPt+'pt';
    return;
  }
  const pages=document.querySelectorAll('.preview-page');
  const fontPx=Math.round(_fontPt*(96/72)); /* pt→px */
  pages.forEach(p=>{
    p.style.padding=''; p.style.minHeight=''; p.style.boxSizing='';
    p.style.maxWidth=''; p.style.transform=''; p.style.transformOrigin='';
    if(_scale===1){
      p.style.width=''; p.style.marginBottom='';
    } else {
      p.style.width=Math.round(_A4W_PX*_scale)+'px';
      p.style.marginBottom='16px';
    }
    /* 폰트 크기: 페이지 전체에 적용 (table 포함 상속) */
    p.style.fontSize=fontPx+'px';
    p.style.lineHeight='1.8'; /* 폰트 변경 시 줄간격 유지 */
  });
  document.getElementById('pw-zoom-lbl').textContent=Math.round(_scale*100)+'%';
  const lbl=document.getElementById('pw-font-lbl');
  if(lbl)lbl.textContent=_fontPt+'pt';
}

function _applyFont(){
  const lbl=document.getElementById('pw-font-lbl');
  if(lbl)lbl.textContent=_fontPt+'pt';
  const fontPx=Math.round(_fontPt*(96/72)*10)/10;
  if(_pptOn){
    /* PPT 모드: 현재 페이지 비율 계산 후 pages에 직접 적용 */
    const pages=_getPages();
    if(pages.length){
      const curW=parseFloat(pages[0].style.width)||window.innerWidth;
      const ratio=curW/_A4W_PX;
      const szPx=Math.round(_fontPt*(96/72)*ratio*10)/10;
      pages.forEach(p=>{ p.style.fontSize=szPx+'px'; p.style.lineHeight='1.8'; });
    }
    /* body-inner도 함께 적용 (상속 보조) */
    const bi=document.getElementById('body-inner');
    const ratio=window.innerWidth/_A4W_PX;
    if(bi)bi.style.fontSize=Math.round(_fontPt*(96/72)*ratio*10)/10+'px';
  } else if(document.body.classList.contains('pw-slide-mode')){
    document.querySelectorAll('.ppt-slide').forEach(s=>{
      s.style.fontSize=fontPx+'px';
      s.style.lineHeight='1.8';
      const inner=s.querySelector('.slide-inner');
      if(inner) inner.style.fontSize=fontPx+'px';
    });
    const zl=document.getElementById('pw-zoom-lbl');
    if(zl)zl.textContent=Math.round(_scale*100)+'%';
  } else {
    /* 일반 모드: preview-page에 직접 fontSize 적용 */
    document.querySelectorAll('.preview-page').forEach(p=>{
      p.style.fontSize=fontPx+'px';
      p.style.lineHeight='1.8';
    });
    /* zoom 레이블도 갱신 */
    const zl=document.getElementById('pw-zoom-lbl');
    if(zl)zl.textContent=Math.round(_scale*100)+'%';
  }
}
function pwFontUp(){_fontPt=Math.min(FONT_MAX,_fontPt+FONT_STEP);_applyFont();}
function pwFontDown(){_fontPt=Math.max(FONT_MIN,_fontPt-FONT_STEP);_applyFont();}
function pwFontReset(){_fontPt=11;_applyFont();}

/* 창 너비에 fit */
function _fitToWindow(){
  const avail=window.innerWidth-40;
  _scale=Math.max(MIN_S, Math.min(MAX_S, Math.floor((avail/_A4W_PX)*100)/100));
  _applyScale();
}

/* PPT 모드 전용 zoom: 페이지 비례 조정 (vw 기준 ±15%) */
function _pptZoomExternal(delta){
  const pages=_getPages();
  if(!pages.length)return;
  const curW=parseFloat(pages[0].style.width)||window.innerWidth;
  const newW=Math.round(Math.max(window.innerWidth*0.5,
                        Math.min(window.innerWidth*2.0, curW+delta*_A4W_PX)));
  const ratio=newW/_A4W_PX;
  const fontPx=Math.round(_fontPt*(96/72)*ratio*10)/10;
  pages.forEach(p=>{
    p.style.width=newW+'px';
    p.style.padding=Math.round(22*_MM*ratio)+'px '+Math.round(18*_MM*ratio)+'px';
    p.style.minHeight=Math.round(297*_MM*ratio)+'px';
    p.style.fontSize=fontPx+'px';
    p.style.lineHeight='1.8';
  });
  const bi=document.getElementById('body-inner');
  bi.style.fontSize=fontPx+'px';
  document.getElementById('pw-zoom-lbl').textContent=Math.round(ratio*100)+'%';
}

function pwZoomIn(){
  if(_pptOn){ _pptZoomExternal(+0.15); return; }
  _scale=Math.min(MAX_S, Math.round((_scale+STEP_S)*100)/100);
  _applyScale();
}
function pwZoomOut(){
  if(_pptOn){ _pptZoomExternal(-0.15); return; }
  _scale=Math.max(MIN_S, Math.round((_scale-STEP_S)*100)/100);
  _applyScale();
}
function pwZoomReset(){ _scale=1.0; _applyScale(); }

/* ══ 전체화면 ══ */
function pwFullscreen(){
  if(!document.fullscreenElement) document.documentElement.requestFullscreen().catch(()=>{});
  else document.exitFullscreen();
}

/* ══ PPT 모드 ══
   전체화면 후 vw에 맞게 각 페이지 width/padding/fontSize 직접 설정.
   transform 없음 → 잘림 없음.
   zoom 버튼은 PPT 모드 중 비활성.
*/
let _pptOn=false;
function _getPages(){
  if(document.body.classList.contains('pw-slide-mode')) return [...document.querySelectorAll('.ppt-slide')];
  return [...document.querySelectorAll('.preview-page')];
}

function _pptApply(){
  const vw=window.innerWidth;
  const ratio=vw/_A4W_PX;
  const fontPx=Math.round(_fontPt*(96/72)*ratio*10)/10;
  _getPages().forEach(p=>{
    p.style.transform=''; p.style.transformOrigin='';
    p.style.width=vw+'px';
    p.style.maxWidth='none';
    p.style.padding=Math.round(22*_MM*ratio)+'px '+Math.round(18*_MM*ratio)+'px';
    p.style.minHeight=Math.round(297*_MM*ratio)+'px';
    p.style.marginBottom='0';
    p.style.boxSizing='border-box';
    p.style.fontSize=fontPx+'px';
    p.style.lineHeight='1.8';
  });
  const bi=document.getElementById('body-inner');
  bi.style.fontSize=fontPx+'px';
  bi.style.alignItems='flex-start';
  document.getElementById('pw-zoom-lbl').textContent=Math.round(ratio*100)+'%';
  _updatePptPg();
}

function _pptRestore(){
  _getPages().forEach(p=>{
    p.style.width=''; p.style.padding=''; p.style.minHeight='';
    p.style.marginBottom=''; p.style.boxSizing=''; p.style.maxWidth='';
  });
  const bi=document.getElementById('body-inner');
  bi.style.fontSize=''; bi.style.alignItems='';
  document.getElementById('pw-zoom-lbl').style.opacity='';
  _applyScale();
  /* font lbl 복원 */
  const fl=document.getElementById('pw-font-lbl');
  if(fl)fl.textContent=_fontPt+'pt';
}

function _vpH(){ return window.innerHeight-36; }

function _pptStep(dir){
  const bi=document.getElementById('body-inner');
  const vh=_vpH();
  let next=bi.scrollTop+dir*vh;
  next=Math.max(0,next);
  _getPages().forEach(p=>{
    if(Math.abs(next-p.offsetTop)<vh*0.18) next=p.offsetTop;
  });
  next=Math.min(next, bi.scrollHeight-bi.clientHeight);
  bi.scrollTo({top:next, behavior:'smooth'});
  setTimeout(_updatePptPg,350);
}

function _updatePptPg(){
  const bi=document.getElementById('body-inner');
  const pages=_getPages(); if(!pages.length) return;
  const mid=bi.scrollTop+_vpH()/2;
  let best=0,bestD=Infinity;
  pages.forEach((p,i)=>{
    const d=Math.abs(p.offsetTop+p.offsetHeight/2-mid);
    if(d<bestD){bestD=d;best=i;}
  });
  const pgText=(best+1)+' / '+pages.length;
  document.getElementById('pw-ppt-pg').textContent=pgText;
  document.getElementById('pw-pg-lbl').textContent=pgText;
}

function pwPptPrev(){ _pptStep(-1); }
function pwPptNext(){ _pptStep(1); }

function pwTogglePPT(autoStart){
  const btn=document.getElementById('pw-ppt-btn');
  const nav=document.getElementById('pw-ppt-nav');
  if(!_pptOn){
    _pptOn=true;
    document.body.classList.add('ppt-mode');
    btn.classList.add('active'); btn.textContent='🎬 종료';
    nav.classList.add('vis');
    PRES.show(); /* 프레젠테이션 도구 툴바 표시 */
    const doApply=()=>requestAnimationFrame(()=>{
      _pptApply();
      document.getElementById('body-inner').scrollTop=0;
    });
    if(!document.fullscreenElement){
      document.documentElement.requestFullscreen()
        .then(()=>setTimeout(doApply,120))
        .catch(()=>doApply());
    } else { doApply(); }
    window._pptResizeH=()=>{
      if(!_pptOn) return;
      const bi=document.getElementById('body-inner');
      const r=bi.scrollTop/Math.max(1,bi.scrollHeight);
      _pptApply();
      setTimeout(()=>{bi.scrollTop=r*bi.scrollHeight;_updatePptPg();},50);
    };
    window.addEventListener('resize',window._pptResizeH);
  } else {
    _pptOn=false;
    document.body.classList.remove('ppt-mode');
    btn.classList.remove('active'); btn.textContent='🎬 PPT';
    nav.classList.remove('vis');
    PRES.hide(); /* 도구 툴바 숨김 */
    _pptRestore();
    if(document.fullscreenElement) document.exitFullscreen();
    if(window._pptResizeH){ window.removeEventListener('resize',window._pptResizeH); window._pptResizeH=null; }
    document.getElementById('pw-pg-lbl').textContent=_getPages().length+' 페이지';
  }
}

/* ══ 프레젠테이션 도구 (PRES) ══
   도구: select(기본), pan(이동), pen(펜), hl(형광펜), laser(포인터)
   캔버스에 drawing, pan은 body-inner 스크롤 조작
*/
const PRES=(()=>{
  let tool='laser', penColor='#e63030', penSize=4;
  let hlColor='#ffe040', hlSize=18, hlAlpha=0.40;
  let drawing=false;
  let panStartY=0, panStartScroll=0;
  let canvas,ctx,overlay,laserDot;
  let _init=false;

  function init(){
    if(_init)return; _init=true;
    overlay=document.getElementById('pres-overlay');
    canvas=document.getElementById('pres-canvas');
    laserDot=document.getElementById('laser-dot');

    function resize(){
      const imgData=ctx?ctx.getImageData(0,0,canvas.width,canvas.height):null;
      canvas.width=window.innerWidth;
      canvas.height=window.innerHeight;
      ctx=canvas.getContext('2d');
      if(imgData)ctx.putImageData(imgData,0,0);
    }
    resize();
    window.addEventListener('resize',resize);

    /* mousemove는 document에 등록 → 오버레이 밖에서도 레이저/pan 추적 */
    document.addEventListener('mousemove',onMove);
    overlay.addEventListener('mousedown',onDown);
    document.addEventListener('mouseup',onUp);

    /* 마우스 휠로 스크롤 (pan/laser 도구일 때) */
    window.addEventListener('wheel',e=>{
      if(!['pan','laser','select'].includes(tool))return;
      const bi=document.getElementById('body-inner');
      if(bi){bi.scrollTop+=e.deltaY;setTimeout(_updatePptPg,100);}
    },{passive:true});
  }

  function setTool(t){
    tool=t;
    if(!overlay)return;
    document.querySelectorAll('#pres-toolbar .pt-tool').forEach(b=>{
      b.classList.toggle('active-tool',b.dataset.tool===t);
    });
    /* 오버레이 pointer-events */
    overlay.className='';
    if(t==='laser'){
      overlay.className='mode-pointer';
      laserDot.style.display='block';
    } else {
      laserDot.style.display='none';
      if(t==='pan') overlay.className='mode-pan';
      else if(t==='pen'||t==='hl'||t==='eraser') overlay.className='mode-pen';
    }
    /* 옵션 패널 */
    document.getElementById('pt-pen-opts').style.display=(t==='pen')?'flex':'none';
    document.getElementById('pt-hl-opts').style.display=(t==='hl')?'flex':'none';
  }

  function onDown(e){
    if(tool==='pan'){
      drawing=true;
      panStartY=e.clientY;
      const bi=document.getElementById('body-inner');
      panStartScroll=bi?bi.scrollTop:0;
      return;
    }
    if(tool==='pen'||tool==='hl'||tool==='eraser'){
      drawing=true;
      /* 경로 시작: canvas 기준 좌표로 변환 */
      const cr=canvas.getBoundingClientRect();
      const sx=e.clientX-cr.left, sy=e.clientY-cr.top;
      ctx.beginPath();
      _setCtxStyle();
      ctx.moveTo(sx,sy);
      /* 첫 점 기록 — onMove가 다른 좌표계 쓰는 버그 방지 */
      canvas._lastX=sx; canvas._lastY=sy;
    }
  }

  function _setCtxStyle(){
    if(tool==='eraser'){
      ctx.globalCompositeOperation='destination-out';
      ctx.globalAlpha=1;
      ctx.lineWidth=24;
      ctx.strokeStyle='rgba(0,0,0,1)';
    } else if(tool==='pen'){
      ctx.globalCompositeOperation='source-over';
      ctx.globalAlpha=1;
      ctx.strokeStyle=penColor;
      ctx.lineWidth=penSize;
    } else {
      ctx.globalCompositeOperation='source-over';
      ctx.globalAlpha=hlAlpha;
      ctx.strokeStyle=hlColor;
      ctx.lineWidth=hlSize;
    }
    ctx.lineCap='round';
    ctx.lineJoin='round';
  }

  function onMove(e){
    /* 레이저: overlay 밖에서도 추적 */
    if(tool==='laser'){
      laserDot.style.left=e.clientX+'px';
      laserDot.style.top=e.clientY+'px';
      return;
    }
    if(!drawing)return;
    if(tool==='pan'){
      const bi=document.getElementById('body-inner');
      if(bi)bi.scrollTop=panStartScroll+(panStartY-e.clientY);
      return;
    }
    if(tool==='pen'||tool==='hl'||tool==='eraser'){
      const cr=canvas.getBoundingClientRect();
      const cx=e.clientX-cr.left, cy=e.clientY-cr.top;
      ctx.moveTo(canvas._lastX!==undefined?canvas._lastX:cx,
                 canvas._lastY!==undefined?canvas._lastY:cy);
      ctx.lineTo(cx,cy);
      ctx.stroke();
      ctx.beginPath();
      canvas._lastX=cx; canvas._lastY=cy;
    }
  }

  function onUp(){
    drawing=false;
    if(canvas){canvas._lastX=undefined;canvas._lastY=undefined;}
    if(ctx){ctx.globalAlpha=1;ctx.globalCompositeOperation='source-over';}
  }

  function clearCanvas(){
    if(ctx)ctx.clearRect(0,0,canvas.width,canvas.height);
  }

  function show(){
    init();
    const tb=document.getElementById('pres-toolbar');
    if(tb){
      /* 이전 포지션 클래스 복원 */
      tb.classList.remove('vis','pos-bottom','pos-right','pos-left');
      tb.classList.add('vis');
      if(_posClasses[_posIdx]) tb.classList.add(_posClasses[_posIdx]);
    }
    const ov=document.getElementById('pres-overlay');
    if(ov) ov.style.display='block';
    setTool('laser');
  }
  function hide(){
    const tb=document.getElementById('pres-toolbar');
    if(tb) tb.classList.remove('vis','pos-bottom','pos-right','pos-left');
    const ov=document.getElementById('pres-overlay');
    if(ov) ov.style.display='none';
    if(laserDot)laserDot.style.display='none';
    clearCanvas();
    tool='laser'; _posIdx=0; /* 0=pos-right (기본 우측) */
  }

  /* 툴바 위치 순환: 우측(기본) → 하단 → 상단 → 좌측 → 우측 */
  const _posClasses=['pos-right','pos-bottom','','pos-left'];
  const _posLabels=['📌▶','📌⬇','📌⬆','📌◀'];
  let _posIdx=0;
  function cyclePos(){
    const tb=document.getElementById('pres-toolbar');
    if(!tb||!tb.classList.contains('vis'))return;
    _posIdx=(_posIdx+1)%_posClasses.length;
    /* 기존 위치 클래스 제거 후 새 클래스 추가 */
    tb.classList.remove('pos-bottom','pos-right','pos-left');
    if(_posClasses[_posIdx]) tb.classList.add(_posClasses[_posIdx]);
    const btn=document.getElementById('pt-pos-btn');
    if(btn)btn.title='현재: '+['상단','하단','우측','좌측'][_posIdx]+' → 클릭으로 변경';
  }

  function _updHlUI(){
    const sl=document.getElementById('pt-hl-size-lbl');
    const al=document.getElementById('pt-hl-alpha-lbl');
    if(sl)sl.textContent=hlSize;
    if(al)al.textContent=Math.round(hlAlpha*100)+'%';
  }
  return{
    show,hide,setTool,clearCanvas,cyclePos,
    setPenColor(col){penColor=col},
    setPenSize(s){penSize=+s},
    setHlColor(col){hlColor=col},
    setHlSize(s){hlSize=+s; _updHlUI();},
    setHlAlpha(v){hlAlpha=+v/100; _updHlUI();},
    hlSizeUp(){hlSize=Math.min(60,hlSize+2); _updHlUI();},
    hlSizeDown(){hlSize=Math.max(4,hlSize-2); _updHlUI();},
    hlAlphaUp(){hlAlpha=Math.min(0.90,+(hlAlpha+0.05).toFixed(2)); _updHlUI();},
    hlAlphaDown(){hlAlpha=Math.max(0.02,+(hlAlpha-0.05).toFixed(2)); _updHlUI();}
  };
})();

/* ══ Trans ══ */
let _transOn=false;
function pwToggleTrans(){
  _transOn=!_transOn;
  const btn=document.getElementById('pw-trans-btn');
  document.body.classList.toggle('trans-mode',_transOn);
  btn.classList.toggle('active',_transOn);
  btn.textContent=_transOn?'↕ Portrait':'↔ Trans';
  if(_pptOn){setTimeout(()=>{_pptApply();},80);}
  else {_applyScale();}
}

/* ══ Dark 반전 테마 ══ */
let _darkOn=false;
function pwToggleDark(){
  _darkOn=!_darkOn;
  const btn=document.getElementById('pw-dark-btn');
  document.body.classList.toggle('dark-theme',_darkOn);
  btn.classList.toggle('active-dark',_darkOn);
  btn.textContent=_darkOn?'☀ Light':'◑ Dark';
}

/* ══ 키보드 단축키 ══ */
document.addEventListener('keydown',e=>{
  if(e.key==='F11'){e.preventDefault();pwFullscreen();return;}
  if(!_pptOn)return;
  if(e.key==='ArrowRight'||e.key==='ArrowDown'||e.key==='PageDown'||e.key===' '){e.preventDefault();pwPptNext();}
  else if(e.key==='ArrowLeft'||e.key==='ArrowUp'||e.key==='PageUp'){e.preventDefault();pwPptPrev();}
  else if(e.key==='Escape'){e.preventDefault();pwTogglePPT();}
  else if(e.key==='Home'){e.preventDefault();document.getElementById('body-inner').scrollTo({top:0,behavior:'smooth'});}
  else if(e.key==='End'){const bi=document.getElementById('body-inner');bi.scrollTo({top:bi.scrollHeight,behavior:'smooth'});}
  /* 프레젠테이션 도구 단축키 1~6 */
  else if(e.key==='1')PRES.setTool('laser');
  else if(e.key==='2')PRES.setTool('select');
  else if(e.key==='3')PRES.setTool('pan');
  else if(e.key==='4')PRES.setTool('pen');
  else if(e.key==='5')PRES.setTool('hl');
  else if(e.key==='6')PRES.setTool('eraser');
  else if(e.key==='p'||e.key==='P')PRES.cyclePos();
});

/* ══ 마우스 휠 스크롤 (PPT 모드) ══ */
window.addEventListener('wheel',e=>{
  if(!_pptOn)return;
  const bi=document.getElementById('body-inner');
  bi.scrollTop+=e.deltaY;
  setTimeout(_updatePptPg,100);
},{passive:true});

/* 페이지 수 표시 + 창 크기에 항상 fit */

/* ══ A4 구분선 ══ */
/* ── 외부 PV A4 구분선 ─────────────────────────────────────
   내부 PV와 동일하게 preview-page 내부에 직접 선을 삽입하는 방식.
   overlay div가 아니라 각 페이지(position:relative) 안에 absolute로 삽입하므로
   body-inner의 position/scroll/zoom에 무관하게 정확히 동작한다.       */
let _a4On=false;

function _pwA4DrawPage(p){
  /* 기존 선 제거 */
  p.querySelectorAll('.a4-rl').forEach(function(el){el.remove();});
  if(!_a4On)return;
  const MM=96/25.4;
  const cssW=210*MM;
  /* getBoundingClientRect: scale/zoom 적용된 실제 화면 크기 */
  const rect=p.getBoundingClientRect();
  const scale=rect.width/cssW;
  const gap=Math.round(297*MM*scale);       /* 297mm의 실제 화면 px */
  const pageH=rect.height;
  const cssH=p.offsetHeight;               /* scale 전 논리 CSS px */
  const scaleY=pageH/cssH;
  let n=1;
  while(n*gap<pageH-2){
    const topCss=Math.round((n*gap)/scaleY);  /* CSS px로 역산 */
    const line=document.createElement('div');
    line.className='a4-rl';
    line.style.top=topCss+'px';
    const lbl=document.createElement('span');
    lbl.className='a4-rl-label';
    lbl.textContent=(297*n)+' mm';
    line.appendChild(lbl);p.appendChild(line);
    n++;
  }
}

function _pwA4DrawAll(){
  document.querySelectorAll('.preview-page').forEach(_pwA4DrawPage);
}

function pwToggleA4(){
  _a4On=!_a4On;
  const btn=document.getElementById('pw-a4-btn');
  if(btn){btn.classList.toggle('active',_a4On);btn.textContent=_a4On?'📄 A4 ✓':'📄 A4';}
  _pwA4DrawAll();
}

/* 창 크기·줌 변경 시 재그리기 */
(function(){
  if(!window.ResizeObserver)return;
  const ro=new ResizeObserver(function(){if(_a4On)_pwA4DrawAll();});
  document.querySelectorAll('.preview-page').forEach(function(p){ro.observe(p);});
})();

window.addEventListener('load',()=>{
  const n=document.querySelectorAll('.preview-page').length;
  const nSlide=document.querySelectorAll('.ppt-slide').length;
  const pgLbl=document.getElementById('pw-pg-lbl');
  if(document.body.classList.contains('pw-slide-mode')&&nSlide>0){
    if(pgLbl)pgLbl.textContent=(nSlide)+' 슬라이드';
    const baseW=document.body.classList.contains('trans-mode')?540:960;
    _scale=Math.max(MIN_S,Math.min(MAX_S,Math.floor((window.innerWidth-60)/baseW*100)/100));
    _applyScale();
  } else {
    if(pgLbl)pgLbl.textContent='1 / '+n;
    _fitToWindow();
  }
  /* 일반 모드 스크롤 시 페이지 표시 갱신 */
  const bi=document.getElementById('body-inner');
  bi.addEventListener('scroll',()=>{
    if(_pptOn)return; /* PPT 모드는 _updatePptPg가 처리 */
    const pages=_getPages();
    if(!pages.length)return;
    const mid=bi.scrollTop+window.innerHeight*0.3;
    let cur=0;
    for(let i=0;i<pages.length;i++){if(pages[i].offsetTop<=mid)cur=i;}
    document.getElementById('pw-pg-lbl').textContent=(cur+1)+' / '+pages.length;
  },{passive:true});
});<\/script></body></html>`;
    }

    // 이슈1 수정: 메시지 리스너를 open() 밖에서 1회만 등록
    let _msgListenerRegistered = false;
    function _initMsgListener() {
        if (_msgListenerRegistered) return;
        _msgListenerRegistered = true;
        window.addEventListener('message', e => {
            if (e.data && e.data.type === 'pvS') {
                /* 새창PW 스크롤 → 에디터 이동
                   내부 SS sync OFF일 땐 에디터만 이동, 내부PV는 건드리지 않음 */
                const r = e.data.ratio;
                const ed2 = el('editor');
                ed2.scrollTop = r * (ed2.scrollHeight - ed2.clientHeight);
                if (SS.isEnabled()) {
                    const pc = el('preview-container');
                    pc.scrollTop = r * (pc.scrollHeight - pc.clientHeight);
                }
            }
            if (e.data && e.data.type === 'pwSyncState') {
                const btn = el('ed-pv-sync-btn');
                if (!btn) return;
                const on = !!e.data.enabled;
                btn.textContent = on ? '🔗 PV 동기화 ON' : '🔗 PV 동기화 OFF';
                btn.style.color = on ? '#6af7b0' : '#888';
                btn.style.background = on ? 'rgba(106,247,176,.12)' : 'rgba(255,255,255,.05)';
                btn.style.borderColor = on ? 'rgba(106,247,176,.35)' : 'rgba(255,255,255,.15)';
            }
        });
    }

    function open() {
        _initMsgListener();
        const title = el('doc-title').value;
        if (win && !win.closed) { win.focus(); sync(); return }
        const w = 920, h = Math.floor(window.screen.height * .88);
        const left = window.screenX + window.outerWidth + 10, top = window.screenY;
        try {
            win = window.open('', '_blank', `width=${w},height=${h},left=${left},top=${top},resizable=yes,scrollbars=yes`);
            if (!win) throw 0;
            _lastOpenWasSlide = false;
            win.document.open(); win.document.write(buildHTML(el('editor').value, title)); win.document.close();
            el('pw-btn').classList.add('open');
            win.addEventListener('beforeunload', () => el('pw-btn').classList.remove('open'));
        } catch (e) { alert('팝업이 차단되었습니다.'); }
    }

    function pushScroll(r, anchor) { if (!win || win.closed) return; try { win.postMessage({ type: 'ss', ratio: r, anchor: anchor || null }, '*') } catch (e) { } }

    function sync() {
        clearTimeout(st); st = setTimeout(() => {
            if (!win || win.closed) { el('pw-btn').classList.remove('open'); return }
            const title = el('doc-title').value;
            const md    = el('editor').value;
            try {
                const pages = splitPages(md);
                const html  = _lastOpenWasSlide
                    ? pages.map((p, i) => {
                        const parsed = parseSlideContent(p);
                        const warnClass = parsed.bullets.length > 6 ? ' slide-bullet-warn' : '';
                        const warnMsg = parsed.bullets.length > 6 ? '<span class="slide-bullet-warn-msg">⚠ bullet 6개 초과</span>' : '';
                        return `<div class="ppt-slide${warnClass}" data-slide-index="${i + 1}"><div class="slide-inner">${mdRender(p)}</div><span class="slide-num">${i + 1}</span>${warnMsg}</div>`;
                    }).join('')
                    : pages.map((p, i) =>
                        `<div class="preview-page${rm ? ' rm' : ''}" data-page="${i + 1}">${mdRender(p)}</div>`
                    ).join('');
                win.postMessage({ type: 'pvUpdate', html, title, rm, slideMode: _lastOpenWasSlide }, '*');
            } catch (e) { }
        }, 200);
    }

    function forceRefresh() { if (win && !win.closed) { const t = el('doc-title').value; try { win.document.open(); win.document.write(buildHTML(el('editor').value, t)); win.document.close() } catch (e) { } } else open() }
    function checkClosed() {
        if (win && win.closed) {
            el('pw-btn').classList.remove('open');
            win = null;
            const btn = el('ed-pv-sync-btn');
            if (btn) { btn.textContent = '🔗 PV 동기화 OFF'; btn.style.color = '#888'; btn.style.background = 'rgba(255,255,255,.05)'; btn.style.borderColor = 'rgba(255,255,255,.15)'; }
        }
    }
    function setRM(v) { rm = v }
    function sendToggleSync() { if (win && !win.closed) try { win.postMessage({ type: 'pwToggleSync' }, '*'); } catch (e) { } }

    /* PPT 모드로 바로 열기 */
    function openPPT() {
        _initMsgListener();
        const title = el('doc-title').value;
        /* 이미 창이 열려있으면 재사용 */
        if (win && !win.closed) {
            win.focus();
            // 약간 딜레이 후 PPT 시작 메시지
            setTimeout(() => { try { win.postMessage({ type: 'startPPT' }, '*') } catch (e) { } }, 300);
            return;
        }
        const w = Math.floor(window.screen.width * .9);
        const h = Math.floor(window.screen.height * .9);
        const left = Math.floor((window.screen.width - w) / 2);
        const top = Math.floor((window.screen.height - h) / 2);
        try {
            win = window.open('', '_blank', `width=${w},height=${h},left=${left},top=${top},resizable=yes,scrollbars=no`);
            if (!win) throw 0;
            win.document.open(); win.document.write(buildHTML(el('editor').value, title)); win.document.close();
            el('pw-btn').classList.add('open');
            win.addEventListener('beforeunload', () => el('pw-btn').classList.remove('open'));
            // 로드 완료 후 PPT 자동 시작
            setTimeout(() => { try { win.postMessage({ type: 'startPPT' }, '*') } catch (e) { } }, 800);
        } catch (e) { alert('팝업이 차단되었습니다.'); }
    }

    /* 슬라이드 모드로 바로 열기 (새창에서 16:9 카드 뷰) */
    function openSlide() {
        _initMsgListener();
        const title = el('doc-title').value;
        if (win && !win.closed) { win.focus(); sync(); return }
        const w = 920, h = Math.floor(window.screen.height * .88);
        const left = window.screenX + window.outerWidth + 10, top = window.screenY;
        try {
            win = window.open('', '_blank', `width=${w},height=${h},left=${left},top=${top},resizable=yes,scrollbars=yes`);
            if (!win) throw 0;
            _lastOpenWasSlide = true;
            win.document.open(); win.document.write(buildHTML(el('editor').value, title, { slideMode: true })); win.document.close();
            el('pw-btn').classList.add('open');
            win.addEventListener('beforeunload', () => el('pw-btn').classList.remove('open'));
        } catch (e) { alert('팝업이 차단되었습니다.'); }
    }

    function hasWin() { return !!(win && !win.closed); }
    function closeWin() {
        if (win && !win.closed) { try { win.close(); } catch (e) { } win = null; }
        el('pw-btn').classList.remove('open');
    }
    return { open, sync, forceRefresh, checkClosed, pushScroll, setRM, openPPT, openSlide, hasWin, closeWin, sendToggleSync };
})();

/* ═══════════════════════════════════════════════════════════
   SCROLL SYNC — 헤딩 앵커 기반 동기화
   에디터의 현재 스크롤 위치에서 직전 헤딩을 찾아
   미리보기의 같은 헤딩으로 점프 + 헤딩 사이 비율로 보정
═══════════════════════════════════════════════════════════ */
const SS = (() => {
    /* ─────────────────────────────────────────────────────────────
       스크롤 동기화 v2 — 커서 기반 + 헤딩 앵커 + on/off 제어
       에디터 → 내부PV / 에디터 → 새창PW 를 동시에 처리
    ───────────────────────────────────────────────────────────── */
    let _enabled = true;          // 내부 PV sync on/off
    let _lock = false;            // 역방향 재진입 방지
    let _tScroll = null;          // 스크롤 debounce timer
    let _tCursor = null;          // 커서 debounce timer

    /* ── 헤딩 ID 생성 (marked 렌더러와 동일 알고리즘) ────────── */
    function _makeId(text) {
        return 'h-' + text.replace(/[*_`]/g, '')
            .toLowerCase()
            .replace(/[^a-z0-9가-힣\s]/g, '')
            .replace(/\s+/g, '-')
            .substring(0, 50);
    }

    /* ── 에디터 헤딩 맵 빌드 ─────────────────────────────────
       각 헤딩의 에디터 내 절대 Y픽셀 위치를 계산
       lineH를 각 줄에 균등 적용하되, scrollHeight 기반으로 보정  */
    function _buildMap(ed) {
        const lines = ed.value.split('\n');
        const lineH = ed.scrollHeight / Math.max(1, lines.length);
        const map = [];
        lines.forEach((ln, i) => {
            const m = ln.match(/^(#{1,3})\s+(.+)/);
            if (!m) return;
            map.push({ line: i, id: _makeId(m[2]), edY: Math.round(i * lineH) });
        });
        return map;
    }

    /* ── PV 컨테이너에서 헤딩 절대Y 계산 (getBCR 기반, 정확) ── */
    function _pvY(pc, id) {
        const h = pc.querySelector('#' + CSS.escape(id));
        if (!h) return null;
        const pcR = pc.getBoundingClientRect();
        const hR  = h.getBoundingClientRect();
        return pc.scrollTop + (hR.top - pcR.top);
    }

    /* ── 에디터 현재 상태(scrollTop 또는 커서 줄) → anchor ────
       useCursor=true : 커서가 있는 줄 기준으로 직전 헤딩 찾기
       useCursor=false: scrollTop 기준                          */
    function _getAnchor(ed, useCursor) {
        const map = _buildMap(ed);
        if (!map.length) return null;

        let refY;
        if (useCursor) {
            const pos = ed.selectionStart;
            const curLine = ed.value.substring(0, pos).split('\n').length - 1;
            const lineH = ed.scrollHeight / Math.max(1, ed.value.split('\n').length);
            refY = curLine * lineH;
        } else {
            refY = ed.scrollTop;
        }

        let prev = map[0], next = null;
        for (let i = 0; i < map.length; i++) {
            if (map[i].edY <= refY + 2) { prev = map[i]; next = map[i + 1] || null; }
            else break;
        }
        const segLen = next ? next.edY - prev.edY : ed.scrollHeight - prev.edY;
        const ratio  = segLen > 0 ? Math.min(1, (refY - prev.edY) / segLen) : 0;
        return { id: prev.id, ratio, nextId: next ? next.id : null };
    }

    /* ── 에디터 → 내부PV + 새창PW 동기화 ───────────────────── */
    function _syncToPv(useCursor) {
        const ed = el('editor'), pc = el('preview-container');
        if (!ed || !pc) return;

        const anchor = _getAnchor(ed, useCursor);

        /* ① 내부 PV — _enabled일 때만 (PV scroll 이벤트가 역방향 동기화를 트리거하지 않도록 lock) */
        if (_enabled) {
            _lock = true;
            if (anchor) {
                const y0 = _pvY(pc, anchor.id);
                if (y0 !== null) {
                    const y1 = anchor.nextId ? _pvY(pc, anchor.nextId) : null;
                    const seg = y1 !== null ? Math.max(0, y1 - y0) : Math.max(0, pc.scrollHeight - y0);
                    pc.scrollTop = y0 + seg * anchor.ratio;
                } else {
                    const r = ed.scrollTop / Math.max(1, ed.scrollHeight - ed.clientHeight);
                    pc.scrollTop = r * (pc.scrollHeight - pc.clientHeight);
                }
            } else {
                const r = ed.scrollTop / Math.max(1, ed.scrollHeight - ed.clientHeight);
                pc.scrollTop = r * (pc.scrollHeight - pc.clientHeight);
            }
            setTimeout(() => { _lock = false; }, 120);
        }

        /* ② 새창 PW — _enabled 여부와 무관하게 항상 에디터 기반으로 전송
              rGlobal은 내부 pc.scrollTop 이 아닌 에디터 비율로 계산            */
        const rEd = ed.scrollTop / Math.max(1, ed.scrollHeight - ed.clientHeight);
        PW.pushScroll(rEd, anchor);
    }

    /* ── PV → 에디터 역방향 동기화 ─────────────────────────── */
    function _syncToEd() {
        const ed = el('editor'), pc = el('preview-container');
        if (!ed || !pc) return;
        const map = _buildMap(ed);
        if (!map.length) {
            const r = pc.scrollTop / Math.max(1, pc.scrollHeight - pc.clientHeight);
            ed.scrollTop = r * (ed.scrollHeight - ed.clientHeight);
            return;
        }
        let bestId = null, bestY = -Infinity;
        map.forEach(m => {
            const y = _pvY(pc, m.id);
            if (y !== null && y <= pc.scrollTop + 4 && y > bestY) { bestY = y; bestId = m.id; }
        });
        if (!bestId) {
            const r = pc.scrollTop / Math.max(1, pc.scrollHeight - pc.clientHeight);
            ed.scrollTop = r * (ed.scrollHeight - ed.clientHeight);
            return;
        }
        const idx = map.findIndex(m => m.id === bestId);
        const cur = map[idx], nxt = map[idx + 1] || null;
        const pvSeg = nxt ? (_pvY(pc, nxt.id) || 0) - bestY : pc.scrollHeight - bestY;
        const pvOff = Math.max(0, pc.scrollTop - bestY);
        const ratio = pvSeg > 0 ? Math.min(1, pvOff / pvSeg) : 0;
        const edSeg = nxt ? nxt.edY - cur.edY : ed.scrollHeight - cur.edY;
        ed.scrollTop = cur.edY + edSeg * ratio;
    }

    /* ── on/off 토글 (내부 PV) ──────────────────────────────── */
    function toggle() {
        _enabled = !_enabled;
        _updateBtn();
        if (_enabled) _syncToPv(false);   // 켜자마자 한 번 동기화
    }

    function _updateBtn() {
        /* pv 창 버튼 + 에디터 툴바 버튼 동시 업데이트 (에디터 헤더 PV동기화는 새창 PV 전용이라 제외) */
        ['pv-sync-btn', 'ed-sync-btn'].forEach(id => {
            const btn = el(id);
            if (!btn) return;
            btn.textContent = _enabled ? '🔗 동기화 ON' : '🔗 동기화 OFF';
            btn.style.color       = _enabled ? '#6af7b0' : '#888';
            btn.style.background  = _enabled ? 'rgba(106,247,176,.12)' : 'rgba(255,255,255,.05)';
            btn.style.borderColor = _enabled ? 'rgba(106,247,176,.35)' : 'rgba(255,255,255,.15)';
        });
    }

    /* ── 커서 이동 시 PV 동기화 (click / keyup) ─────────────── */
    function onCursor() {
        /* 내부 PV가 OFF여도 외부 PW(새창)는 별개로 동기화해야 하므로
           _enabled 체크를 제거 → _syncToPv 내부에서 각각 분기 처리 */
        clearTimeout(_tCursor);
        _tCursor = setTimeout(() => { _syncToPv(true); }, 60);
    }

    /* ── 외부 공개 API ──────────────────────────────────────── */
    function init() {
        const ed = el('editor'), pc = el('preview-container');
        if (!ed || !pc) return;

        /* 에디터 스크롤 → PV 동기화 */
        ed.addEventListener('scroll', () => {
            if (_lock) return;
            clearTimeout(_tScroll);
            _tScroll = setTimeout(() => {
                _lock = true; _syncToPv(false);
                setTimeout(() => { _lock = false; }, 120);
            }, 10);
        }, { passive: true });

        /* PV 스크롤 → 에디터 역방향 — _enabled일 때만 (OFF면 독립 이동) */
        pc.addEventListener('scroll', () => {
            if (_lock || !_enabled) return;
            clearTimeout(_tScroll);
            _tScroll = setTimeout(() => {
                _lock = true; _syncToEd();
                setTimeout(() => { _lock = false; }, 120);
            }, 10);
        }, { passive: true });

        /* 버튼 초기 상태 */
        _updateBtn();
    }

    return { init, toggle, onCursor, isEnabled: () => _enabled };
})();

/* ═══════════════════════════════════════════════════════════
   TM — Tab Manager (멀티파일 탭 편집)
   각 탭은 독립적인 content, title, undo stack을 가진다.
   localStorage key: 'mdpro_tabs_v1' (탭 목록 + 내용 영속)
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   TM — Tab Manager  (멀티파일 탭 편집)
   ─ 탭별 독립 content / undo stack / dirty flag
   ─ localStorage 'mdpro_tabs_v1' 에 전체 세션 영속
   ─ 구버전 'mdpro_v7' 자동 마이그레이션
═══════════════════════════════════════════════════════════ */
const TM = (() => {
    const STORE_KEY = 'mdpro_tabs_v1';
    let tabs     = [];   // [{id,title,content,isDirty,filePath,fileType,undoSt,undoPtr}]
    let activeId = null;
    let _nextId  = 1;

    /* ── 탭 객체 팩토리 ──────────────────────────────── */
    function _makeTab(title = 'Untitled', content = '', fileType = 'md') {
        return { id: _nextId++, title, content,
                 isDirty: false, filePath: null, fileType,
                 undoSt: [content], undoPtr: 0 };
    }

    /* ── localStorage 영속 ───────────────────────────── */
    function persist() {
        try {
            localStorage.setItem(STORE_KEY, JSON.stringify({
                tabs: tabs.map(t => ({
                    id: t.id, title: t.title, content: t.content,
                    filePath: t.filePath, fileType: t.fileType
                })),
                activeId, nextId: _nextId
            }));
        } catch(e) {}
    }

    function _restore() {
        try {
            const d = JSON.parse(localStorage.getItem(STORE_KEY));
            if (!d || !d.tabs || !d.tabs.length) return false;
            _nextId = d.nextId || d.tabs.length + 1;
            tabs = d.tabs.map(t => _makeTab(t.title, t.content, t.fileType || 'md'));
            /* id를 저장값으로 덮어씀 (makeTab이 _nextId++ 를 쓰므로 별도 복원) */
            d.tabs.forEach((src, i) => { tabs[i].id = src.id; tabs[i].filePath = src.filePath || null; });
            activeId = d.tabs.some(t => t.id === d.activeId) ? d.activeId : tabs[0].id;
            return true;
        } catch(e) { return false; }
    }

    /* ── undo 상태 백업 / 복원 ──────────────────────── */
    function _saveUndo() {
        const t = _active();
        if (!t) return;
        try { const s = US._getState(); t.undoSt = s.stack; t.undoPtr = s.ptr; } catch(e) {}
    }
    function _loadUndo(t) {
        try { US._setState(t.undoSt || [t.content], t.undoPtr ?? 0); } catch(e) { US.snap(); }
    }

    /* ── 에디터 ↔ 탭 IO ─────────────────────────────── */
    function _pushToEditor(tab) {
        const edi = el('editor'), ti = el('doc-title');
        if (edi) { edi.value = tab.content; edi.setSelectionRange(0, 0); }
        if (ti)  ti.value = tab.title;
        /* 상단 타이틀바 — 탭과 동일한 텍스트 표시 */
        _updateTitlebar(tab);
    }

    function _updateTitlebar(tab) {
        const titleDisp = el('titlebar-path-display');
        if (!titleDisp) return;
        /* 상단 타이틀: 파일명만 (확장자 제거) — 탭은 경로 포함, 상단은 파일명만 */
        const fullText = tab.ghPath ? tab.ghPath : tab.title;
        const fileName = fullText.split('/').pop().replace(/\.[^.]+$/, '');
        titleDisp.textContent = fileName || tab.title;
        titleDisp.title = fullText;  /* 호버 시 전체 경로 툴팁 */
    }
    function _pullFromEditor() {
        const t = _active();
        if (!t) return;
        const edi = el('editor'), ti = el('doc-title');
        if (edi) t.content = edi.value;
        if (ti)  t.title   = ti.value;
    }

    /* ── 탭 UI 렌더 ──────────────────────────────────── */
    function renderTabs() {
        const list = document.getElementById('tab-list');
        if (!list) return;
        list.innerHTML = '';

        tabs.forEach(t => {
            const div = document.createElement('div');
            div.className = 'tab' +
                (t.id === activeId ? ' active' : '') +
                (t.isDirty ? ' dirty' : '');
            div.dataset.id = t.id;
            div.title = t.ghPath ? t.ghPath : (t.filePath ? t.filePath : t.title);

            /* 탭에 표시할 텍스트: ghPath가 있으면 경로/파일명 형식으로 */
            const tabDisplayText = t.ghPath ? t.ghPath : t.title;

            div.innerHTML =
                `<span class="tab-icon">${_icon(t.fileType)}</span>` +
                (t.ghPath ? `<span class="tab-gh-indicator" title="GitHub: ${_esc(t.ghPath)}">🐙</span>` : '') +
                `<span class="tab-title">${_esc(tabDisplayText)}</span>` +
                `<span class="tab-dirty" title="저장되지 않은 변경사항">●</span>` +
                `<button class="tab-close" title="닫기 (Ctrl+W)">✕</button>`;

            /* 클릭: 전환 / 닫기 */
            div.addEventListener('click', ev => {
                if (ev.target.classList.contains('tab-close')) { closeTab(t.id); return; }
                switchTab(t.id);
            });
            /* 더블클릭: 제목 인라인 편집 */
            div.querySelector('.tab-title').addEventListener('dblclick', ev => {
                ev.stopPropagation();
                _renameInline(t.id, div.querySelector('.tab-title'));
            });
            /* 중간 버튼: 닫기 */
            div.addEventListener('mousedown', ev => {
                if (ev.button === 1) { ev.preventDefault(); closeTab(t.id); }
            });
            list.appendChild(div);
        });

        /* 모두저장 버튼 dirty 상태 표시 (항상 노출) */
        const btn = document.getElementById('tab-save-all-btn');
        if (btn) btn.classList.toggle('has-dirty', tabs.some(t => t.isDirty));
    }

    function _icon(ft) {
        return ft === 'html' ? '🌐' : ft === 'txt' ? '📄' : '📝';
    }
    function _esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    /* ── 탭 전환 ─────────────────────────────────────── */
    function switchTab(id) {
        if (id === activeId) return;
        _pullFromEditor();
        _saveUndo();

        activeId = id;
        const tab = _active();
        if (!tab) return;

        _pushToEditor(tab);
        _loadUndo(tab);
        renderTabs();
        persist();
        App.render();
        el('editor') && el('editor').focus();
        /* 활성 탭이 GitHub 파일이면 폴더 뷰를 GitHub로, 로컬 파일이면 로컬로 자동 전환 */
        if (typeof SB !== 'undefined' && SB.currentSource) {
            const wantSource = tab.ghPath ? 'github' : 'local';
            if (SB.currentSource() !== wantSource) SB.switchSource(wantSource);
        }
        if (typeof GH !== 'undefined' && GH.syncHighlightFromActiveTab) GH.syncHighlightFromActiveTab();
    }

    /* ── 새 탭 ───────────────────────────────────────── */
    function newTab(title, content, fileType) {
        _pullFromEditor();
        _saveUndo();
        const tab = _makeTab(title || 'Untitled', content || '', fileType || 'md');
        tabs.push(tab);
        activeId = tab.id;
        _pushToEditor(tab);
        US._setState([tab.content], 0);
        renderTabs();
        persist();
        App.render();
        setTimeout(() => el('editor') && el('editor').focus(), 50);
        return tab;
    }

    /* ── 탭 닫기 ─────────────────────────────────────── */
    function closeTab(id) {
        const tab = tabs.find(t => t.id === id);
        if (!tab) return;
        if (tab.isDirty &&
            !confirm(`'${tab.title}' 의 변경사항이 저장되지 않았습니다.\n닫으시겠습니까?`)) return;

        const idx    = tabs.indexOf(tab);
        const wasActive = id === activeId;
        tabs.splice(idx, 1);

        if (tabs.length === 0) {
            /* 마지막 탭을 닫은 경우: 빈 탭 하나 자동 생성 (파일은 항상 한 개 열려 있음) */
            newTab('Untitled', '', 'md');
            return;
        }

        if (wasActive) {
            /* 오른쪽 탭 → 없으면 왼쪽 탭으로 이동 */
            const next = tabs[idx] || tabs[idx - 1];
            activeId = next.id;
            _pushToEditor(next);
            _loadUndo(next);
            App.render();
        }
        renderTabs();
        persist();
    }

    /* ── dirty 관리 ──────────────────────────────────── */
    function markDirty() {
        const t = _active();
        if (!t || t.isDirty) return;      /* 이미 dirty면 DOM 조작 생략 */
        t.isDirty = true;
        const el2 = document.querySelector(`.tab[data-id="${activeId}"]`);
        if (el2) el2.classList.add('dirty');
        /* 모두저장 버튼 dirty 표시 */
        const btn = document.getElementById('tab-save-all-btn');
        if (btn) btn.classList.add('has-dirty');
    }

    function markClean(id) {
        const t = tabs.find(t => t.id === (id ?? activeId));
        if (!t) return;
        t.isDirty = false;
        const el2 = document.querySelector(`.tab[data-id="${t.id}"]`);
        if (el2) el2.classList.remove('dirty');
    }

    /* ── 파일 열기 ───────────────────────────────────── */
    function openFile() {
        const inp = document.getElementById('tab-file-input');
        if (inp) inp.click();
    }

    /* HTML 파일에서 마크다운으로 변환 가능한 텍스트 추출 */
    function _htmlToEditableContent(htmlStr) {
        try {
            const parser = new DOMParser();
            const doc    = parser.parseFromString(htmlStr, 'text/html');
            const body   = doc.body;
            if (!body) return htmlStr;

            /* preview-page div들 순서대로 내용 추출 */
            const pages = body.querySelectorAll('.preview-page');
            if (pages.length > 0) {
                return Array.from(pages).map(pg => {
                    /* page-break 유지 */
                    return _nodeToMd(pg) + '\n\n<div class="page-break"></div>';
                }).join('\n').replace(/(<div class="page-break"><\/div>\n*)$/, '').trim();
            }
            /* preview-page 없으면 body 전체 텍스트 변환 */
            return _nodeToMd(body);
        } catch(e) {
            return htmlStr;
        }
    }

    /* DOM 노드를 마크다운으로 변환 (헤딩, 굵기, 단락 등 기본 처리) */
    function _nodeToMd(root) {
        const lines = [];
        function walk(node) {
            if (node.nodeType === 3) { /* TEXT_NODE */
                const t = node.textContent;
                if (t.trim()) lines.push(t);
                return;
            }
            if (node.nodeType !== 1) return;
            const tag = node.tagName.toLowerCase();
            if (tag === 'h1') { lines.push('\n# ' + node.textContent.trim() + '\n'); }
            else if (tag === 'h2') { lines.push('\n## ' + node.textContent.trim() + '\n'); }
            else if (tag === 'h3') { lines.push('\n### ' + node.textContent.trim() + '\n'); }
            else if (tag === 'h4') { lines.push('\n#### ' + node.textContent.trim() + '\n'); }
            else if (tag === 'hr') { lines.push('\n---\n'); }
            else if (tag === 'p') { lines.push('\n' + _inlineToMd(node) + '\n'); }
            else if (tag === 'ul') {
                node.querySelectorAll(':scope > li').forEach(li => lines.push('- ' + _inlineToMd(li)));
                lines.push('');
            }
            else if (tag === 'ol') {
                let n = 1;
                node.querySelectorAll(':scope > li').forEach(li => { lines.push(n++ + '. ' + _inlineToMd(li)); });
                lines.push('');
            }
            else if (tag === 'blockquote') { lines.push('> ' + node.textContent.trim()); }
            else if (tag === 'pre') { lines.push('\n```\n' + node.textContent + '\n```\n'); }
            else if (tag === 'table') {
                const rows = node.querySelectorAll('tr');
                rows.forEach((row, ri) => {
                    const cells = Array.from(row.querySelectorAll('th,td')).map(c => c.textContent.trim());
                    lines.push('| ' + cells.join(' | ') + ' |');
                    if (ri === 0) lines.push('| ' + cells.map(() => '---').join(' | ') + ' |');
                });
                lines.push('');
            }
            else { node.childNodes.forEach(walk); }
        }
        root.childNodes.forEach(walk);
        return lines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
    }

    function _inlineToMd(node) {
        let out = '';
        node.childNodes.forEach(c => {
            if (c.nodeType === 3) { out += c.textContent; return; }
            if (c.nodeType !== 1) return;
            const tag = c.tagName.toLowerCase();
            if (tag === 'b' || tag === 'strong') out += '**' + c.textContent + '**';
            else if (tag === 'i' || tag === 'em') out += '*' + c.textContent + '*';
            else if (tag === 'code') out += '`' + c.textContent + '`';
            else if (tag === 'a') out += '[' + c.textContent + '](' + (c.href || '#') + ')';
            else if (tag === 'sup') out += '[^' + c.textContent + ']';
            else out += _inlineToMd(c);
        });
        return out;
    }

    function _onFileSelected(ev) {
        const files = [...(ev.target.files || [])];
        files.forEach(file => {
            const reader = new FileReader();
            reader.onload = e => {
                const rawText = e.target.result;
                const ext     = file.name.split('.').pop().toLowerCase();
                const ft      = ['md','txt','html'].includes(ext) ? ext : 'md';
                const name    = file.name.replace(/\.[^.]+$/, '');

                /* HTML 파일: body 내용을 마크다운으로 변환하여 편집 가능하게 */
                const text = (ft === 'html') ? _htmlToEditableContent(rawText) : rawText;

                /* 동일 파일 이미 열려 있으면 덮어쓰기 확인 */
                const dup = tabs.find(t => t.filePath === file.name || t.title === name);
                if (dup) {
                    if (!dup.isDirty || confirm(`'${dup.title}' 이(가) 이미 열려 있습니다.\n다시 불러오시겠습니까?`)) {
                        dup.content  = text;
                        dup.title    = name;
                        dup.filePath = file.name;
                        dup.fileType = ft;
                        dup.isDirty  = false;
                        if (dup.id === activeId) { _pushToEditor(dup); App.render(); }
                        else switchTab(dup.id);
                        renderTabs(); persist();
                    }
                    return;
                }

                const tab = newTab(name, text, ft === 'html' ? 'md' : ft);
                tab.filePath = file.name;
                markClean(tab.id);
                renderTabs(); persist();
            };
            reader.readAsText(file, 'UTF-8');
        });
        ev.target.value = '';
    }

    /* ── 일괄 저장 (.md) ─────────────────────────────── */
    function saveAll() {
        _pullFromEditor();
        let saved = 0;
        tabs.forEach(tab => {
            if (!tab.isDirty && !tab.filePath && tab.content === '') return;
            const fname = (tab.title || 'document').replace(/[^a-z0-9가-힣\-_. ]/gi, '_');
            dlBlob(tab.content, fname + '.md', 'text/markdown;charset=utf-8');
            tab.isDirty = false;
            saved++;
        });
        if (saved === 0) { alert('저장할 변경사항이 없습니다.'); return; }
        renderTabs(); persist();
    }

    /* ── 탭 제목 인라인 편집 ─────────────────────────── */
    function _renameInline(id, el2) {
        const tab = tabs.find(t => t.id === id);
        if (!tab) return;
        const orig = tab.title;
        el2.contentEditable = 'true';
        el2.focus();
        const sel = window.getSelection();
        const rng = document.createRange();
        rng.selectNodeContents(el2);
        sel.removeAllRanges(); sel.addRange(rng);

        const commit = () => {
            el2.contentEditable = 'false';
            const v = el2.textContent.trim() || orig;
            tab.title = v;
            el2.textContent = v;
            if (id === activeId) { const ti = el('doc-title'); if (ti) ti.value = v; }
            persist();
        };
        el2.onblur    = commit;
        el2.onkeydown = e => {
            if (e.key === 'Enter')  { e.preventDefault(); commit(); }
            if (e.key === 'Escape') { el2.textContent = orig; el2.contentEditable = 'false'; }
        };
    }

    /* ── doc-title 입력 → 탭 제목 동기화 ────────────── */
    function syncTitle(v) {
        const t = _active();
        if (!t) return;
        if (t.title === v) return;
        t.title = v;
        /* 탭 전체 재렌더 — ghPath가 있는 탭은 경로/파일명 전체가 유지됨 */
        renderTabs();
        /* 상단 타이틀바 (파일명만) */
        _updateTitlebar(t);
        persist();
    }

    /* ── 초기화 ──────────────────────────────────────── */
    function init() {
        if (!_restore()) {
            /* 구버전 단일 파일 마이그레이션 */
            try {
                const old = JSON.parse(localStorage.getItem('mdpro_v7') || '{}');
                tabs.push(_makeTab(old.t || 'Untitled', old.c || '', 'md'));
            } catch(e) {
                tabs.push(_makeTab());
            }
            activeId = tabs[0].id;
        }
        _pushToEditor(_active());
        _loadUndo(_active());
        renderTabs();

        /* tab-list 가로 휠 스크롤 */
        const tl = document.getElementById('tab-list');
        if (tl) tl.addEventListener('wheel', e => {
            if (e.deltaY !== 0) { e.preventDefault(); tl.scrollLeft += e.deltaY; }
        }, { passive: false });
    }

    function _active() { return tabs.find(t => t.id === activeId) || null; }

    return {
        init, newTab, switchTab, closeTab,
        openFile, saveAll, markDirty, markClean,
        syncTitle, renderTabs, persist,
        saveFromEditor: _pullFromEditor,
        getActive: _active, getAll: () => tabs,
        _onFileSelected, _htmlToEditableContent,
    };
})();


/* ═══════════════════════════════════════════════════════════
   CITATION MANAGER
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   SB — Sidebar Tab Controller  (TOC ↔ FILES 전환)
═══════════════════════════════════════════════════════════ */
const SB = (() => {
    let current = 'toc';
    let source  = localStorage.getItem('mdpro_files_src') || 'local'; // 'local' | 'github'

    function switchTab(id) {
        current = id;
        document.querySelectorAll('.sb-tab').forEach(b =>
            b.classList.toggle('active', b.id === `sb-tab-${id}`));
        document.querySelectorAll('.sb-panel').forEach(p =>
            p.classList.toggle('active', p.id === `sb-panel-${id}`));
        if (id === 'files') {
            _applySource(source);
            if (source === 'local')  FM._render();
            if (source === 'github') GH._render();
        }
    }

    function switchSource(src) {
        source = src;
        localStorage.setItem('mdpro_files_src', src);
        _applySource(src);
        if (src === 'local')  FM._render();
        if (src === 'github') GH._render();
    }

    function _applySource(src) {
        document.querySelectorAll('.fsrc-tab').forEach(b =>
            b.classList.toggle('active', b.id === `fsrc-${src}`));
        document.querySelectorAll('.files-sub').forEach(p =>
            p.classList.toggle('active', p.id === `files-sub-${src}`));
    }

    function init() { _applySource(source); }

    return { switchTab, switchSource, init, currentSource: () => source };
})();

/* ═══════════════════════════════════════════════════════════
   FM — File Manager  (폴더 선택 → 파일 목록 → 탭 열기)
   File System Access API 사용 (Chrome/Edge 지원)
   Safari·Firefox: 미지원 → 파일 개별 선택 폴백
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   FM — File Manager
   ─ File System Access API (Chrome/Edge 86+)
   ─ FileSystemDirectoryHandle → IndexedDB 저장으로 세션 간 영속
   ─ 앱 재시작 시: IDB 복원 → requestPermission → 자동 로드
   ─ Firefox/Safari: 수동 선택 폴백
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   FM — File Manager  v3  (IDB 파일 내용 캐시 방식)

   브라우저 보안 제약:
   - FileSystemDirectoryHandle은 앱 재시작 후 permission 리셋
   - requestPermission()은 사용자 클릭 없이 호출 불가
   → 해결: 파일 목록 + 내용을 IDB에 직접 캐시
            재시작 후 캐시로 즉시 복원, 실제 파일 동기화는 클릭 한 번

   IDB 스키마:
   - DB: 'mdpro-fm-v3'
   - store 'meta'  : key='root' → {folderName, fileCount, syncedAt}
   - store 'files' : key=상대경로 → {name, ext, folder, path, content, modified}
═══════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════
   GH — GitHub File Manager
   ─ GitHub REST API v3 (api.github.com)
   ─ PAT(Personal Access Token) + owner/repo 기반 인증
   ─ 파일 목록: GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1
   ─ 파일 읽기: GET /repos/{owner}/{repo}/contents/{path}
   ─ 파일 저장: PUT /repos/{owner}/{repo}/contents/{path}  (SHA 필요)
   ─ 설정 저장: localStorage (토큰은 암호화 없이 저장 — 신뢰 기기 전제)
   ─ 파일 목록 캐시: IDB 'mdpro-gh-v1' (재시작 후 즉시 표시)
═══════════════════════════════════════════════════════════ */
const GH = (() => {

    /* ── 설정 저장/복원 ───────────────────────────────── */
    const CFG_KEY = 'mdpro_gh_cfg';

    function _loadCfg() {
        try { return JSON.parse(localStorage.getItem(CFG_KEY) || 'null'); } catch(e) { return null; }
    }
    function _saveCfg(cfg) {
        try { localStorage.setItem(CFG_KEY, JSON.stringify(cfg)); } catch(e) {}
    }

    let cfg = _loadCfg();
    // cfg = { token, repo:'owner/repo', branch:'main', basePath:'' }

    /* ── IDB 캐시 (파일 목록 + 내용) ─────────────────── */
    const GH_DB = 'mdpro-gh-v1';
    let _ghdb = null;

    function _ghDB() {
        if (_ghdb) return Promise.resolve(_ghdb);
        return new Promise((res, rej) => {
            const req = indexedDB.open(GH_DB, 1);
            req.onupgradeneeded = ev => {
                const db = ev.target.result;
                if (!db.objectStoreNames.contains('files')) db.createObjectStore('files');
                if (!db.objectStoreNames.contains('meta'))  db.createObjectStore('meta');
            };
            req.onsuccess = ev => { _ghdb = ev.target.result; res(_ghdb); };
            req.onerror   = ev => rej(ev.target.error);
        });
    }
    async function _ghGet(store, key) {
        const db = await _ghDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store,'readonly').objectStore(store).get(key);
            req.onsuccess = ev => res(ev.target.result ?? null);
            req.onerror   = ev => rej(ev.target.error);
        });
    }
    async function _ghPut(store, key, val) {
        const db = await _ghDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store,'readwrite').objectStore(store).put(val, key);
            req.onsuccess = () => res();
            req.onerror   = ev => rej(ev.target.error);
        });
    }
    async function _ghAll(store) {
        const db = await _ghDB();
        return new Promise((res, rej) => {
            const rows = [];
            const req = db.transaction(store,'readonly').objectStore(store).openCursor();
            req.onsuccess = ev => {
                const cur = ev.target.result;
                if (cur) { rows.push(cur.value); cur.continue(); }
                else res(rows);
            };
            req.onerror = ev => rej(ev.target.error);
        });
    }
    async function _ghClear(store) {
        const db = await _ghDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store,'readwrite').objectStore(store).clear();
            req.onsuccess = () => res();
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    /* ── 상태 ─────────────────────────────────────────── */
    let allFiles  = [];   // [{name, ext, path, sha, size, modified}]
    let filtered  = [];
    let activeFile = null;
    let _fileContentCache = {};  // path → {content, sha} (세션 캐시)
    let _ghEmptyFolders = {};    // folderRelPath → true (.gitkeep 기반 빈 폴더)

    /* ── GitHub API 헬퍼 ──────────────────────────────── */
    function _apiBase() {
        if (!cfg) return null;
        const [owner, repo] = cfg.repo.split('/');
        return `https://api.github.com/repos/${owner}/${repo}`;
    }

    async function _apiFetch(path, opts = {}) {
        if (!cfg?.token) throw new Error('토큰이 설정되지 않았습니다');
        const url = path.startsWith('http') ? path : _apiBase() + path;
        const res = await fetch(url, {
            ...opts,
            headers: {
                'Authorization': `token ${cfg.token}`,
                'Accept': 'application/vnd.github.v3+json',
                'X-GitHub-Api-Version': '2022-11-28',
                ...(opts.headers || {}),
            },
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(`GitHub API ${res.status}: ${err.message || res.statusText}`);
        }
        return res.json();
    }

    /* ── 설정 모달 ────────────────────────────────────── */
    function showSettings() {
        const el2 = id => document.getElementById(id);
        const devName = localStorage.getItem('mdpro_device_name') || '';
        if (cfg) {
            el2('gh-token-input').value  = cfg.token    || '';
            el2('gh-repo-input').value   = cfg.repo     || '';
            el2('gh-branch-input').value = cfg.branch   || 'main';
            el2('gh-path-input').value   = cfg.basePath || '';
        } else {
            if (el2('gh-branch-input')) el2('gh-branch-input').value = 'main';
        }
        if (el2('gh-device-input')) el2('gh-device-input').value = devName;
        /* md-viewer 저장소 표시 */
        const pvsEl = el2('pvs-repo-inline');
        if (pvsEl) {
            try {
                const pvcfg = JSON.parse(localStorage.getItem('pvshare_cfg') || '{}');
                pvsEl.value = pvcfg.repo || '';
            } catch(e) {}
        }
        /* 앱 소스 주소 복원 */
        const appSrcSaved = localStorage.getItem('mdpro_app_src');
        const appSrcLnk = el2('app-src-link');
        if (appSrcSaved && appSrcLnk) {
            appSrcLnk.href = 'https://github.com/' + appSrcSaved;
            appSrcLnk.textContent = appSrcSaved + ' ↗';
        }
        const st = el2('gh-conn-status');
        if (st) { st.className = ''; st.textContent = ''; }
        App.showModal('gh-modal');
        /* 모달 내 자동새로고침 버튼/시간표시 동기화 */
        _ghArUpdateBtn();
        _ghArUpdateCountdown();
    }

    function hideSettings() { App.hideModal('gh-modal'); }

    /** 헤더의 연결 테스트 버튼: 저장된 설정으로 연결 테스트만 수행 (설정 없으면 설정창 열기) */
    async function handleHdrSaveClick(ev) {
        if (ev) ev.stopPropagation();
        const currentCfg = cfg || _loadCfg();
        if (!currentCfg || !currentCfg.token || !currentCfg.repo) {
            showSettings();
            return;
        }
        const nameEl = document.getElementById('gh-repo-name');
        if (nameEl) { nameEl.textContent = '⟳ 연결 테스트 중…'; nameEl.style.color = 'var(--tx3)'; }
        try {
            const info = await _apiFetch('');
            cfg = currentCfg;
            _setRepoUI(cfg.repo);
            const hdrOk = document.getElementById('gh-hdr-ok-msg');
            if (hdrOk) {
                hdrOk.textContent = '연결성공';
                hdrOk.style.display = 'inline';
                hdrOk.style.opacity = '1';
                clearTimeout(hdrOk._hideTid);
                hdrOk._hideTid = setTimeout(() => {
                    hdrOk.style.opacity = '0';
                    setTimeout(() => { hdrOk.style.display = 'none'; hdrOk.textContent = ''; }, 280);
                }, 2200);
            }
            refresh();
        } catch (e) {
            cfg = _loadCfg();
            _setRepoUI(currentCfg.repo, 'err');
            const saveBtn = document.getElementById('gh-hdr-save-btn');
            if (saveBtn) saveBtn.classList.remove('gh-hdr-save-connected');
            if (typeof App !== 'undefined' && App._toast) App._toast('✗ 연결 실패: ' + (e.message || e));
            else alert('연결 실패: ' + (e.message || e));
        }
    }

    async function saveSettings() {
        const eid = id => document.getElementById(id);
        const tokenEl = eid('gh-token-input');
        if (!tokenEl) {
            showSettings();
            return;
        }
        const token    = tokenEl.value.trim();
        const repoEl   = eid('gh-repo-input');
        const repo     = (repoEl && repoEl.value ? repoEl.value : '').trim();
        const branchEl = eid('gh-branch-input');
        const branch   = (branchEl && branchEl.value ? branchEl.value : '') || 'main';
        const pathEl   = eid('gh-path-input');
        const basePath = (pathEl && pathEl.value ? pathEl.value : '').trim().replace(/^\/|\/$/g, '');
        const device   = eid('gh-device-input') ? eid('gh-device-input').value.trim() : '';
        if (device) localStorage.setItem('mdpro_device_name', device);
        else        localStorage.removeItem('mdpro_device_name');
        /* md-viewer 저장소 저장 */
        const pvsInline = eid('pvs-repo-inline');
        if (pvsInline && pvsInline.value.trim()) {
            try {
                const pvcfg = JSON.parse(localStorage.getItem('pvshare_cfg') || '{}');
                pvcfg.repo = pvsInline.value.trim();
                localStorage.setItem('pvshare_cfg', JSON.stringify(pvcfg));
            } catch(e) {}
        }
        const st       = eid('gh-conn-status');

        if (!token || !repo || !repo.includes('/')) {
            _setStatus('err', '토큰과 저장소(owner/repo)를 모두 입력하세요');
            return;
        }

        _setStatus('loading', '⟳ 연결 테스트 중…');
        cfg = { token, repo, branch, basePath };

        try {
            /* 연결 테스트: 저장소 정보 조회 */
            const info = await _apiFetch('');
            _setStatus('ok', `✓ 연결 성공 — ${info.full_name}  (${info.visibility})`);
            _saveCfg(cfg);
            _setRepoUI(cfg.repo);
            /* #gh-hdr에 연결성공 메시지 표시 후 사라지게 */
            const hdrOk = document.getElementById('gh-hdr-ok-msg');
            if (hdrOk) {
                hdrOk.textContent = '연결성공';
                hdrOk.style.display = 'inline';
                hdrOk.style.opacity = '1';
                clearTimeout(hdrOk._hideTid);
                hdrOk._hideTid = setTimeout(() => {
                    hdrOk.style.opacity = '0';
                    setTimeout(() => { hdrOk.style.display = 'none'; hdrOk.textContent = ''; }, 280);
                }, 2200);
            }
            /* 즉시 파일 목록 로드 */
            setTimeout(() => {
                hideSettings();
                refresh();
            }, 900);
        } catch(e) {
            _setStatus('err', `✗ ${e.message}`);
            cfg = _loadCfg(); // 롤백
        }
    }

    function _setStatus(cls, msg) {
        const st = document.getElementById('gh-conn-status');
        if (!st) return;
        st.className = cls;
        st.textContent = msg;
    }

    /* ── 초기화: IDB 캐시에서 즉시 복원 ─────────────────
       재시작/새로고침 후 설정이 있으면 캐시 목록 표시     */
    async function restore() {
        cfg = _loadCfg();
        if (!cfg) return;
        try {
            const cached = await _ghAll('files');
            if (!cached.length) return;
            allFiles = cached;
            filtered = allFiles;
            /* IDB에서 빈 폴더 목록 복원 */
            try {
                const ef = await _ghGet('meta', 'emptyFolders');
                if (ef && ef.folders) {
                    _ghEmptyFolders = {};
                    ef.folders.forEach(p => { _ghEmptyFolders[p] = true; });
                }
            } catch(e2) { _ghEmptyFolders = {}; }
            _setRepoUI(cfg.repo);
            setTimeout(() => _render(), 0);
        } catch(e) {
            console.warn('GH.restore:', e);
        }
    }

    /* ── 파일 목록 로드 (API) ──────────────────────────── */
    async function refresh() {
        if (!cfg) { showSettings(); return; }
        _setRepoUI(cfg.repo, 'loading');
        try {
            /* Git Trees API: 재귀적으로 전체 트리 한 번에 가져옴 */
            const tree = await _apiFetch(
                `/git/trees/${cfg.branch}?recursive=1`
            );
            const EXT  = ['md','txt','html'];
            const base = cfg.basePath ? cfg.basePath + '/' : '';

            /* .gitkeep가 있는 폴더 = 빈 폴더로 별도 추적 */
            _ghEmptyFolders = {};
            tree.tree.forEach(item => {
                if (item.type !== 'blob') return;
                if (!item.path.endsWith('.gitkeep')) return;
                if (base && !item.path.startsWith(base)) return;
                const rel = base ? item.path.slice(base.length) : item.path;
                const parts = rel.split('/');
                parts.pop(); // .gitkeep 제거
                const folderRel = parts.join('/');
                if (folderRel) _ghEmptyFolders[folderRel] = true;
            });

            allFiles = tree.tree
                .filter(item => {
                    if (item.type !== 'blob') return false;
                    const ext = item.path.split('.').pop().toLowerCase();
                    if (!EXT.includes(ext)) return false;
                    if (base && !item.path.startsWith(base)) return false;
                    return true;
                })
                .map(item => {
                    const rel  = base ? item.path.slice(base.length) : item.path;
                    const parts = rel.split('/');
                    const name = parts.pop();
                    const folder = parts.join('/') || '/';
                    return {
                        name,
                        ext   : name.split('.').pop().toLowerCase(),
                        folder,
                        path  : item.path,   // GitHub full path
                        sha   : item.sha,
                        size  : item.size,
                        date  : null,         // 파일별 마지막 커밋 날짜 (lazy load)
                    };
                });

            filtered = allFiles;

            /* IDB 캐시 갱신 */
            await _ghClear('files');
            const db = await _ghDB();
            await new Promise((res, rej) => {
                const tx = db.transaction('files','readwrite');
                const st = tx.objectStore('files');
                allFiles.forEach(f => st.put(f, f.path));
                tx.oncomplete = res;
                tx.onerror    = ev => rej(ev.target.error);
            });
            await _ghPut('meta','root', { repo: cfg.repo, count: allFiles.length, at: Date.now() });
            /* .gitkeep 빈 폴더 목록도 IDB에 저장 */
            await _ghPut('meta', 'emptyFolders', { folders: Object.keys(_ghEmptyFolders) });

            _setRepoUI(cfg.repo, 'ok');
            _render();
        } catch(e) {
            console.warn('GH.refresh:', e);
            _setRepoUI(cfg.repo, 'err');
            _showListMsg(`⚠ ${e.message}`);
        }
    }

    /* ── GitHub 사이드바 자동 새로고침 ─────────────────────
       연결 시 N초마다 refresh() 호출. ON/OFF·간격은 localStorage 유지. */
    const GH_AR_KEY = 'gh_auto_refresh';
    const GH_AR_INTERVAL_KEY = 'gh_ar_interval';
    function _getGhArInterval() { return Math.max(10, parseInt(localStorage.getItem(GH_AR_INTERVAL_KEY) || '30', 10) || 30); }
    let _ghArEnabled = localStorage.getItem(GH_AR_KEY) !== 'off';
    let _ghArTick = null;
    let _ghArCountdown = 0;

    function _ghArUpdateBtn() {
        const ids = ['gh-ar-btn', 'gh-ar-btn-modal'];
        const onClass = 'on';
        const offClass = 'off';
        ids.forEach(id => {
            const btn = document.getElementById(id);
            if (!btn) return;
            if (btn.classList.contains('gh-ar-btn-circle')) {
                btn.classList.remove(onClass, offClass);
                btn.classList.add(_ghArEnabled ? onClass : offClass);
            } else {
                btn.textContent = _ghArEnabled ? '🔄 ON' : '🔄 OFF';
                btn.style.color = _ghArEnabled ? '#6af7b0' : 'var(--tx3)';
                btn.style.borderColor = _ghArEnabled ? 'rgba(106,247,176,.35)' : 'var(--bd)';
                btn.style.background = _ghArEnabled ? 'rgba(106,247,176,.1)' : 'rgba(255,255,255,.04)';
            }
        });
    }

    function _ghArUpdateCountdown() {
        const ids = ['gh-ar-countdown', 'gh-ar-countdown-modal'];
        const text = _ghArEnabled && _ghArCountdown > 0 ? _ghArCountdown + 's' : '';
        const show = _ghArEnabled && _ghArCountdown > 0;
        ids.forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.textContent = text;
            el.style.display = show ? 'inline' : 'none';
        });
    }

    function _ghStartAutoRefresh() {
        _ghStopAutoRefresh();
        if (!cfg || !_ghArEnabled) return;
        const intervalSec = _getGhArInterval();
        _ghArCountdown = intervalSec;
        _ghArUpdateCountdown();

        _ghArTick = setInterval(() => {
            _ghArCountdown--;
            _ghArUpdateCountdown();
            if (_ghArCountdown <= 0) {
                refresh().catch(() => {});
                _ghArCountdown = _getGhArInterval();
            }
        }, 1000);
    }

    function _ghStopAutoRefresh() {
        if (_ghArTick) { clearInterval(_ghArTick); _ghArTick = null; }
        _ghArCountdown = 0;
        _ghArUpdateCountdown();
    }

    function toggleAutoRefresh() {
        _ghArEnabled = !_ghArEnabled;
        localStorage.setItem(GH_AR_KEY, _ghArEnabled ? 'on' : 'off');
        _ghArUpdateBtn();
        if (_ghArEnabled && cfg) {
            _ghStartAutoRefresh();
            App._toast('🔄 자동새로고침 ON (' + _getGhArInterval() + '초마다 GitHub 폴더)');
        } else {
            _ghStopAutoRefresh();
            App._toast('🔄 자동새로고침 OFF');
        }
    }

    function showArIntervalSetting() {
        const cur = _getGhArInterval();
        const v = prompt('자동 새로고침 간격 (초)\nGitHub 폴더 목록을 이 간격마다 갱신합니다.', String(cur));
        if (v == null) return;
        const num = parseInt(v, 10);
        if (!(num >= 10 && num <= 600)) {
            App._toast('⚠ 10~600 초 사이로 입력하세요');
            return;
        }
        localStorage.setItem(GH_AR_INTERVAL_KEY, String(num));
        if (_ghArEnabled && cfg) _ghStartAutoRefresh();
        App._toast('✅ 간격 ' + num + '초로 저장');
    }


    /* ── 검색 ─────────────────────────────────────────── */
    function search(q) {
        filtered = q
            ? allFiles.filter(f => f.name.toLowerCase().includes(q.toLowerCase())
                               || f.path.toLowerCase().includes(q.toLowerCase()))
            : allFiles;
        _render();
    }

    /* ── 렌더링 ───────────────────────────────────────── */
    function _render() {
        const list = document.getElementById('gh-list');
        if (!list) return;
        list.innerHTML = '';

        if (!cfg) {
            list.innerHTML =
                '<div class="files-empty">' +
                '<div style="font-size:26px;margin-bottom:8px">🐙</div>' +
                '<div style="font-weight:600;margin-bottom:6px">GitHub 저장소 연결</div>' +
                '<div style="color:var(--tx3);font-size:10px;line-height:1.7">' +
                '⚙ 설정 버튼을 눌러<br>Token + 저장소를 입력하세요</div>' +
                '</div>';
            return;
        }
        /* 파일이 없어도 빈 폴더(.gitkeep)가 있으면 렌더링 계속 */
        const hasEmptyFolders = Object.keys(_ghEmptyFolders).length > 0;
        if (!allFiles.length && !hasEmptyFolders) {
            list.innerHTML =
                '<div class="files-empty">' +
                '<div style="color:var(--tx3);font-size:11px">↻ 새로고침 버튼을 눌러<br>파일 목록을 불러오세요</div>' +
                '</div>';
            return;
        }

        const src = filtered;
        if (!src.length && !hasEmptyFolders) {
            list.innerHTML = '<div class="files-empty">검색 결과 없음</div>';
            return;
        }

        /* ── 트리 노드 빌드 ── */
        const root = { name: '', children: {}, files: [] };

        src.forEach(f => {
            const parts = f.path.split('/');
            let node = root;
            for (let i = 0; i < parts.length - 1; i++) {
                const seg = parts[i];
                if (!node.children[seg]) node.children[seg] = { name: seg, children: {}, files: [], _path: parts.slice(0, i+1).join('/') };
                node = node.children[seg];
            }
            node.files.push(f);
        });

        /* .gitkeep 기반 빈 폴더도 트리에 추가 */
        Object.keys(_ghEmptyFolders).sort().forEach(folderRel => {
            const base = cfg.basePath ? cfg.basePath.replace(/\/$/, '') + '/' : '';
            /* cfg.basePath가 있으면 그 아래 경로만 처리, 상위 경로는 스킵 */
            if (base && !folderRel.startsWith(base) && folderRel !== base.replace(/\/$/, '')) return;
            const relPath = base ? folderRel.slice(base.length) : folderRel;
            if (!relPath) return;
            const parts = relPath.split('/').filter(Boolean);
            let node = root;
            for (let i = 0; i < parts.length; i++) {
                const seg = parts[i];
                if (!node.children[seg]) {
                    node.children[seg] = {
                        name: seg, children: {}, files: [],
                        _path: parts.slice(0, i+1).join('/'),
                        _isEmpty: true
                    };
                }
                node = node.children[seg];
            }
        });

        function countFiles(node) {
            let n = node.files.length;
            Object.values(node.children).forEach(c => { n += countFiles(c); });
            return n;
        }

        function renderNode(node, depth, container) {
            const indent = depth * 12;

            Object.keys(node.children).sort().forEach(folderName => {
                const child = node.children[folderName];
                const total = countFiles(child);

                const folderEl = document.createElement('div');
                folderEl.className = 'ft-folder';

                const hdr = document.createElement('div');
                hdr.className = 'ft-folder-hdr';
                hdr.style.paddingLeft = (8 + indent) + 'px';
                const ghIsEmpty = (child._isEmpty && total === 0);
                hdr.innerHTML =
                    `<span class="ft-toggle">${ghIsEmpty ? '—' : '▾'}</span>` +
                    `<span class="ft-folder-icon">📂</span>` +
                    `<span class="ft-folder-name">${_esc(folderName)}</span>` +
                    `<span class="ft-count" style="${ghIsEmpty ? 'opacity:.4' : ''}">${ghIsEmpty ? '빈 폴더' : total}</span>` +
                    `<button class="fg-add-btn" title="이 폴더에 새 파일 만들기" ` +
                    `onclick="event.stopPropagation();GH._createFileInFolder('${_esc(child._path || folderName)}')">＋</button>` +
                    `<button class="folder-del-btn" title="${ghIsEmpty ? '빈 폴더 삭제' : '폴더 삭제 (내부 파일 포함)'}" ` +
                    `data-path="${_esc(child._path || folderName)}" data-empty="${ghIsEmpty}" ` +
                    `onclick="event.stopPropagation();GH.confirmDeleteFolder(this)">🗑</button>`;
                hdr.onclick = () => {
                    if (ghIsEmpty) return;
                    folderEl.classList.toggle('collapsed');
                    hdr.querySelector('.ft-toggle').textContent =
                        folderEl.classList.contains('collapsed') ? '▸' : '▾';
                };
                folderEl.appendChild(hdr);

                const body = document.createElement('div');
                body.className = 'ft-folder-body';
                renderNode(child, depth + 1, body);
                folderEl.appendChild(body);
                container.appendChild(folderEl);
            });

            node.files.forEach(f => {
                const row  = document.createElement('div');
                row.className = 'file-item' + (f.path === activeFile ? ' active' : '');
                row.dataset.ghPath = f.path;
                row.style.paddingLeft = (18 + indent) + 'px';
                const icon = f.ext === 'html' ? '🌐' : f.ext === 'txt' ? '📄' : '📝';
                const ghSizeStr = f.size != null
                    ? (f.size >= 1048576
                        ? (f.size / 1048576).toFixed(1) + 'MB'
                        : f.size >= 1024
                            ? (f.size / 1024).toFixed(1) + 'KB'
                            : f.size + 'B')
                    : '';
                const ghDateStr = f.date
                    ? new Date(f.date).toLocaleDateString('ko', { month:'2-digit', day:'2-digit' })
                    : '';
                const ghMeta = [ghSizeStr, ghDateStr].filter(Boolean).join(' · ');
                const ghMetaContent = ghSizeStr && ghDateStr
                    ? `<span class="file-item-meta-size">${ghSizeStr}</span> · <span class="file-item-meta-date">${ghDateStr}</span>`
                    : ghSizeStr ? `<span class="file-item-meta-size">${ghSizeStr}</span>` : ghDateStr ? `<span class="file-item-meta-date">${ghDateStr}</span>` : '';
                row.innerHTML =
                    `<span class="file-item-icon">${icon}</span>` +
                    `<span class="file-item-name">${_esc(f.name.replace(/\.[^.]+$/, ''))}</span>` +
                    `<span class="file-item-meta" data-gh-meta="${_esc(f.path)}">${ghMetaContent}</span>` +
                    `<button class="file-share-btn" title="md-viewer에 공개 Push" onclick="event.stopPropagation();GH.pushFile(this)">📤</button>` +
                    `<button class="file-move-btn" title="파일 이동" onclick="event.stopPropagation();GH.moveFile(this)">↗</button>` +
                    `<button class="file-del-btn" title="파일 삭제" onclick="event.stopPropagation();GH.confirmDelete(this)">🗑</button>`;
                row.title = f.path + (f.size != null ? '\n크기: ' + ghSizeStr : '') + (ghDateStr ? '\n수정: ' + ghDateStr : '');
                /* 날짜 없으면 lazy fetch */
                if (!f.date) _fetchFileDate(f);
                row._ghFile = f;
                row.onclick = () => _openFile(f);
                /* 터치 환경: 첫 탭=선택(버튼 표시), 두 번째 탭=파일 열기 */
                row.addEventListener('touchstart', function(ev) {
                    if (ev.target.closest('button')) return; // 버튼 직접 탭은 그냥 실행
                    const already = this.classList.contains('touch-sel');
                    // 다른 항목 선택 해제
                    document.querySelectorAll('.file-item.touch-sel').forEach(el => {
                        if (el !== this) el.classList.remove('touch-sel');
                    });
                    if (already) {
                        // 두 번째 탭 → 파일 열기
                        _openFile(f);
                        this.classList.remove('touch-sel');
                    } else {
                        // 첫 번째 탭 → 선택(버튼 표시)
                        this.classList.add('touch-sel');
                        ev.preventDefault(); // 클릭 이벤트 방지 (두 번 실행 방지)
                    }
                }, { passive: false });
                container.appendChild(row);
            });
        }

        renderNode(root, 0, list);
        /* 전체 접기 버튼: 렌더 후 기본은 모두 펼침 → ▽ */
        const foldBtn = document.getElementById('gh-fold-toggle-btn');
        if (foldBtn) foldBtn.textContent = '▽';
    }

    /* ── 전체 폴더 접기/펼치기 토글 (GitHub 트리) ───────── */
    function toggleFoldAll() {
        const list = document.getElementById('gh-list');
        if (!list) return;
        const folders = list.querySelectorAll('.ft-folder');
        if (!folders.length) return;
        const anyExpanded = Array.from(folders).some(f => !f.classList.contains('collapsed'));
        const collapse = anyExpanded;
        folders.forEach(f => {
            const hdr = f.querySelector('.ft-folder-hdr');
            const toggle = hdr && hdr.querySelector('.ft-toggle');
            const isEmpty = toggle && toggle.textContent === '—';
            if (collapse) {
                f.classList.add('collapsed');
                if (toggle && !isEmpty) toggle.textContent = '▸';
            } else {
                f.classList.remove('collapsed');
                if (toggle && !isEmpty) toggle.textContent = '▾';
            }
        });
        const foldBtn = document.getElementById('gh-fold-toggle-btn');
        if (foldBtn) foldBtn.textContent = collapse ? '▾' : '▽';
    }

    /* ── GitHub 파일 삭제 확인 & 실행 ───────────────────── */
    function confirmDelete(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._ghFile;
        if (!f) return;
        DelConfirm.show({
            name : f.name,
            path : f.path,
            type : 'github',
            onConfirm: async (commitMsg) => {
                try {
                    /* SHA 조회 */
                    let sha = null;
                    const cached = _fileContentCache[f.path];
                    if (cached && cached.sha) {
                        sha = cached.sha;
                    } else {
                        const data = await _apiFetch(`/contents/${encodeURIComponent(f.path)}?ref=${cfg.branch}`);
                        sha = data.sha;
                    }
                    /* GitHub DELETE API */
                    await _apiFetch(`/contents/${encodeURIComponent(f.path)}`, {
                        method : 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body   : JSON.stringify({
                            message: commitMsg || `Delete ${f.name}`,
                            sha,
                            branch : cfg.branch || 'main',
                        }),
                    });
                    delete _fileContentCache[f.path];
                    allFiles = allFiles.filter(x => x.path !== f.path);
                    filtered = filtered.filter(x => x.path !== f.path);

                    /* 삭제 후 그 폴더에 파일이 없으면 → 빈 폴더로 표시
                       (GitHub에 .gitkeep이 있으므로 폴더 자체는 존재) */
                    const deletedFolder = f.path.includes('/')
                        ? f.path.split('/').slice(0, -1).join('/')
                        : null;
                    if (deletedFolder) {
                        const stillHasFiles = allFiles.some(x =>
                            x.path.startsWith(deletedFolder + '/') || x.folder === deletedFolder
                        );
                        if (!stillHasFiles) {
                            _ghEmptyFolders[deletedFolder] = true;
                            /* IDB도 갱신 */
                            _ghPut('meta', 'emptyFolders', { folders: Object.keys(_ghEmptyFolders) }).catch(()=>{});
                        }
                    }

                    _render();
                    App._toast(`🗑 ${f.name} 삭제 완료`);
                } catch(e) {
                    alert('삭제 실패: ' + (e.message || e));
                }
            },
        });
    }

    /* ── gh-list에서 해당 path 하이라이트 및 스크롤 (탭 선택 또는 파일 클릭 시) ── */
    function _highlightFileInList(path) {
        const list = document.getElementById('gh-list');
        if (!list) return;
        list.querySelectorAll('.file-item').forEach(el => {
            el.classList.toggle('active', el.dataset.ghPath === path);
        });
        const activeRow = list.querySelector('.file-item.active');
        if (activeRow) activeRow.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }

    /* ── 활성 탭에 맞춰 gh-list 하이라이트 동기화 (탭 선택 시 호출) ── */
    function syncHighlightFromActiveTab() {
        const tab = typeof TM !== 'undefined' ? TM.getActive() : null;
        const path = tab && tab.ghPath ? tab.ghPath : null;
        activeFile = path;
        _highlightFileInList(path);
    }

    /* ── 파일 열기 ────────────────────────────────────── */
    async function _openFile(f) {
        activeFile = f.path;
        _highlightFileInList(f.path);

        /* 세션 캐시 확인 */
        if (_fileContentCache[f.path]) {
            _openInEditor(f, _fileContentCache[f.path].content);
            return;
        }

        /* API에서 내용 가져오기 */
        try {
            _showListMsg(`⟳ ${f.name} 불러오는 중…`);
            const data = await _apiFetch(`/contents/${encodeURIComponent(f.path)}?ref=${cfg.branch}`);
            /* GitHub API는 Base64로 반환 */
            const content = decodeURIComponent(escape(atob(data.content.replace(/\n/g,''))));
            _fileContentCache[f.path] = { content, sha: data.sha };
            /* SHA 업데이트 (저장 시 필요) */
            f.sha = data.sha;
            _render(); // 로딩 메시지 제거
            _openInEditor(f, content);
        } catch(e) {
            _render();
            alert(`파일을 불러올 수 없습니다:\n${e.message}`);
        }
    }

    function _openInEditor(f, rawContent) {
        const name    = f.name.replace(/\.[^.]+$/, '');
        const ft      = f.ext === 'html' ? 'md' : f.ext;
        const content = f.ext === 'html'
            ? (TM._htmlToEditableContent || (x=>x))(rawContent)
            : rawContent;

        const existing = TM.getAll().find(t => t.ghPath === f.path || t.title === name);
        if (existing) { TM.switchTab(existing.id); return; }

        const tab = TM.newTab(name, content, ft);
        tab.ghPath  = f.path;
        tab.ghSha   = f.sha;
        tab.ghBranch = cfg.branch;
        TM.markClean(tab.id);
        TM.renderTabs();
        TM.persist();
    }

    /* ── GitHub에 저장 (PUT) ──────────────────────────── */
    async function saveFile(tabId, commitMsg) {
        if (!cfg) { alert('GitHub 연결이 설정되지 않았습니다'); return false; }
        const tab = TM.getAll().find(t => t.id === tabId);
        if (!tab || !tab.ghPath) { alert('이 파일은 GitHub에서 열지 않았습니다'); return false; }

        const fileContent = document.getElementById('editor').value;
        const b64 = btoa(unescape(encodeURIComponent(fileContent)));
        const msg = commitMsg || `Update ${tab.title}`;

        try {
            /* SHA가 없으면 먼저 API에서 현재 SHA 조회
               (새 파일 생성 직후 SHA 누락 or 다른 기기에서 수정된 경우 대비) */
            if (!tab.ghSha) {
                try {
                    const info = await _apiFetch(
                        `/contents/${tab.ghPath}?ref=${tab.ghBranch || cfg.branch}`
                    );
                    if (info && info.sha) tab.ghSha = info.sha;
                } catch(e2) {
                    /* 파일이 아직 없으면(404) SHA 없이 신규 생성으로 진행 */
                    if (!e2.message.includes('404')) throw e2;
                }
            }

            const body = {
                message: msg,
                content: b64,
                branch : tab.ghBranch || cfg.branch,
            };
            if (tab.ghSha) body.sha = tab.ghSha;

            const res = await _apiFetch(`/contents/${tab.ghPath}`, {
                method : 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify(body),
            });

            /* 새 SHA 저장 */
            tab.ghSha = res.content.sha;
            _fileContentCache[tab.ghPath] = { content: fileContent, sha: res.content.sha };
            TM.markClean(tabId);
            TM.renderTabs();
            return true;
        } catch(e) {
            alert(`GitHub 저장 실패:\n${e.message}`);
            return false;
        }
    }

    /* ── 새 파일 생성 ─────────────────────────────────── */
    async function createFile(path, content, commitMsg) {
        if (!cfg) { alert('GitHub 연결 필요'); return false; }
        const b64 = btoa(unescape(encodeURIComponent(content)));
        try {
            await _apiFetch(`/contents/${encodeURIComponent(path)}`, {
                method : 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({
                    message: commitMsg || `Create ${path}`,
                    content: b64,
                    branch : cfg.branch,
                }),
            });
            await refresh();
            return true;
        } catch(e) {
            alert(`파일 생성 실패:\n${e.message}`);
            return false;
        }
    }

    /* ── UI 헬퍼 ──────────────────────────────────────── */
    function _setRepoUI(repoName, state) {
        const nameEl    = document.getElementById('gh-repo-name');
        const refBtn    = document.getElementById('gh-refresh-btn');
        const cloneBtn  = document.getElementById('gh-clone-btn');
        const linkEl    = document.getElementById('gh-repo-link');
        const quickBtn  = document.getElementById('gh-quick-connect-btn');
        const connected = !!cfg;

        if (nameEl) {
            if (state === 'loading') { nameEl.textContent = '⟳ 로딩 중…'; nameEl.style.color = 'var(--tx3)'; }
            else if (state === 'err') { nameEl.textContent = `⚠ ${repoName}`; nameEl.style.color = '#f76a6a'; }
            else if (connected) {
                nameEl.textContent = cfg.repo.split('/').pop() + (allFiles.length ? ` (${allFiles.length})` : '');
                nameEl.style.color = 'var(--tx2)';
            } else {
                nameEl.textContent = '미연결';
                nameEl.style.color = 'var(--tx3)';
            }
        }
        /* 연결 상태에 따라 버튼 표시/숨김 */
        if (refBtn)   refBtn.style.display   = connected ? '' : 'none';
        if (cloneBtn) cloneBtn.style.display  = connected ? '' : 'none';
                if (quickBtn) quickBtn.style.display  = connected ? 'none' : '';
        const saveBtn = document.getElementById('gh-hdr-save-btn');
        if (saveBtn) {
            if (connected) saveBtn.classList.add('gh-hdr-save-connected');
            else saveBtn.classList.remove('gh-hdr-save-connected');
        }
        if (linkEl && connected) {
            linkEl.href         = 'https://github.com/' + cfg.repo;
            linkEl.style.display = '';
        } else if (linkEl) {
            linkEl.style.display = 'none';
        }
        /* 새파일/새폴더 버튼: 연결 시에만 표시 (sb-stats 한 줄) */
        const ghNewfileBtn = document.getElementById('gh-newfile-btn');
        const ghMkdirBtn = document.getElementById('gh-mkdir-btn');
        if (ghNewfileBtn) ghNewfileBtn.style.display = connected ? '' : 'none';
        if (ghMkdirBtn) ghMkdirBtn.style.display = connected ? '' : 'none';
        if (connected) {
            _ghArUpdateBtn();
            if (_ghArEnabled) _ghStartAutoRefresh();
        } else {
            _ghStopAutoRefresh();
        }
        /* 스테이터스바 자동새로고침 영역: 연결 시에만 표시 */
        const sbArWrap = document.getElementById('statusbar-ar-wrap');
        const sbArSep = document.getElementById('statusbar-ar-sep');
        if (sbArWrap) sbArWrap.style.display = connected ? 'flex' : 'none';
        if (sbArSep) sbArSep.style.display = connected ? '' : 'none';
        /* 연결된 repo URL 배너 업데이트 */
        let urlBanner = document.getElementById('gh-url-banner');
        if (!urlBanner) {
            urlBanner = document.createElement('div');
            urlBanner.id = 'gh-url-banner';
            const ghHdr = document.getElementById('gh-hdr');
            if (ghHdr && ghHdr.parentNode) ghHdr.parentNode.insertBefore(urlBanner, ghHdr.nextSibling);
        }
        if (connected && cfg.repo) {
            const branch = cfg.branch || 'main';
            const pathInfo = cfg.path ? ' / ' + cfg.path : '';
            urlBanner.innerHTML = '<a href="https://github.com/' + cfg.repo + '" target="_blank" title="GitHub 저장소 열기">🔗 github.com/' + cfg.repo + '</a><span class="gh-url-branch">' + branch + pathInfo + '</span>';
            urlBanner.style.display = '';
        } else {
            urlBanner.style.display = 'none';
        }
    
    }

    function _showListMsg(msg) {
        const list = document.getElementById('gh-list');
        if (list) list.innerHTML = `<div class="files-empty" style="padding-top:20px">${_esc(msg)}</div>`;
    }

    function _esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    /* ── 빠른 연결 테스트 (연결 테스트&저장 버튼) ─────────── */
    async function quickConnect() {
        if (!cfg || !cfg.token || !cfg.repo) {
            /* 설정 미완료 → 설정 모달 열기 */
            const ok = confirm(
                'GitHub 연결 설정이 필요합니다.\n\n' +
                '설정 창에서 Token과 저장소를 입력한 후\n' +
                '"연결 테스트 & 저장" 버튼을 눌러주세요.\n\n' +
                '지금 설정 창을 여시겠습니까?'
            );
            if (ok) showSettings();
            return;
        }
        /* 설정 완료 → 즉시 연결 테스트 */
        const btn = document.getElementById('gh-quick-connect-btn');
        if (btn) { btn.textContent = '연결 중…'; btn.disabled = true; }
        try {
            /* 저장소 정보 조회로 연결 확인 */
            const data = await _apiFetch('');   /* /repos/owner/repo */
            App._toast('✓ GitHub 연결 성공: ' + data.full_name);
            /* 파일 목록 로드 */
            await refresh();
        } catch(e) {
            const msg = e.message || '알 수 없는 오류';
            if (msg.includes('401')) {
                alert('❌ 인증 실패\nToken이 올바르지 않습니다.\n설정을 확인하세요.');
            } else if (msg.includes('404')) {
                alert('❌ 저장소 없음\n저장소 주소를 확인하세요: ' + cfg.repo);
            } else {
                alert('❌ 연결 실패: ' + msg);
            }
        } finally {
            if (btn) { btn.textContent = '연결 테스트 & 저장'; btn.disabled = false; }
        }
    }

    function isConnected() { return !!cfg; }

    /* ── 로컬 파일 목록 → GitHub 일괄 push ──────────────
       Git Data API 흐름:
       1. 현재 branch HEAD SHA 취득
       2. 변경/신규 파일 → Blob API로 각각 업로드 (SHA 취득)
       3. Base tree + 새 항목으로 Tree 생성
       4. 새 Commit 생성 (parent = HEAD)
       5. branch ref를 새 commit SHA로 업데이트            */
    async function pushLocalFiles(files, commitMsg) {
        /* files: [{path, content}]  path = GitHub repo 내 경로 */
        if (!cfg) throw new Error('GitHub 설정이 없습니다');
        if (!files.length) return { pushed: 0 };

        /* 1. HEAD commit SHA + base tree SHA */
        const refData  = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
        const headSHA  = refData.object.sha;
        const commitData = await _apiFetch(`/git/commits/${headSHA}`);
        const baseTree = commitData.tree.sha;

        /* 2. 각 파일을 Blob으로 업로드 */
        const treeItems = await Promise.all(files.map(async f => {
            const blob = await _apiFetch('/git/blobs', {
                method : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({
                    content : btoa(unescape(encodeURIComponent(f.content))),
                    encoding: 'base64',
                }),
            });
            return { path: f.path, mode: '100644', type: 'blob', sha: blob.sha };
        }));

        /* 3. 새 Tree 생성 */
        const newTree = await _apiFetch('/git/trees', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({ base_tree: baseTree, tree: treeItems }),
        });

        /* 4. 새 Commit 생성 */
        const newCommit = await _apiFetch('/git/commits', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({
                message: commitMsg,
                tree   : newTree.sha,
                parents: [headSHA],
            }),
        });

        /* 5. branch ref 업데이트 (fast-forward) */
        await _apiFetch(`/git/refs/heads/${cfg.branch}`, {
            method : 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({ sha: newCommit.sha }),
        });

        /* GH 파일 목록 캐시 무효화 → 다음 렌더 시 새로고침 */
        await _ghClear('files');
        allFiles = [];

        return { pushed: files.length, commitSha: newCommit.sha.slice(0,7) };
    }

    /* GitHub 현재 파일 SHA 맵 취득 (변경 감지용) */
    async function getRemoteSHAs() {
        if (!cfg) return {};
        try {
            const tree = await _apiFetch(`/git/trees/${cfg.branch}?recursive=1`);
            const map = {};
            const base = cfg.basePath ? cfg.basePath + '/' : '';
            tree.tree.forEach(item => {
                if (item.type === 'blob') map[item.path] = item.sha;
            });
            return map;
        } catch(e) { return {}; }
    }

    /* ── 빠른 연결 테스트 (연결 테스트&저장 버튼) ─────────── */
    async function quickConnect() {
        if (!cfg || !cfg.token || !cfg.repo) {
            /* 설정 미완료 → 설정 모달 열기 */
            const ok = confirm(
                'GitHub 연결 설정이 필요합니다.\n\n' +
                '설정 창에서 Token과 저장소를 입력한 후\n' +
                '"연결 테스트 & 저장" 버튼을 눌러주세요.\n\n' +
                '지금 설정 창을 여시겠습니까?'
            );
            if (ok) showSettings();
            return;
        }
        /* 설정 완료 → 즉시 연결 테스트 */
        const btn = document.getElementById('gh-quick-connect-btn');
        if (btn) { btn.textContent = '연결 중…'; btn.disabled = true; }
        try {
            /* 저장소 정보 조회로 연결 확인 */
            const data = await _apiFetch('');   /* /repos/owner/repo */
            App._toast('✓ GitHub 연결 성공: ' + data.full_name);
            /* 파일 목록 로드 */
            await refresh();
        } catch(e) {
            const msg = e.message || '알 수 없는 오류';
            if (msg.includes('401')) {
                alert('❌ 인증 실패\nToken이 올바르지 않습니다.\n설정을 확인하세요.');
            } else if (msg.includes('404')) {
                alert('❌ 저장소 없음\n저장소 주소를 확인하세요: ' + cfg.repo);
            } else {
                alert('❌ 연결 실패: ' + msg);
            }
        } finally {
            if (btn) { btn.textContent = '연결 테스트 & 저장'; btn.disabled = false; }
        }
    }

    function isConnected() { return !!cfg; }

    /* ── 저장소 링크 열기 ─────────────────────────────── */
    function openRepoLink() {
        if (!cfg) return;
        window.open(`https://github.com/${cfg.repo}`, '_blank');
    }

    /* ── Clone: 저장소 전체를 IDB 캐시에 다운로드 ────────
       실제 git clone과 동일한 효과.
       이미 restore()/refresh()가 이 역할을 하므로
       refresh()를 호출하고 _baseSHAs를 초기화           */
    async function cloneRepo() {
        if (!cfg) { showSettings(); return; }
        const ok = confirm(
            `저장소 전체를 다운로드합니다.

` +
            `${cfg.repo}  (${cfg.branch} 브랜치)

` +
            `기존 캐시는 교체됩니다. 계속하시겠습니까?`
        );
        if (!ok) return;
        /* baseSHAs 초기화 → 다음 push 때 모든 파일이 new-local로 분류되지 않도록
           clone 직후 원격 SHA를 기준점으로 설정해야 함 → refresh 후 처리        */
        await refresh();
        /* refresh 완료 후 원격 SHA를 기준점으로 저장 → FM에 알림 */
        if (typeof FM !== 'undefined') {
            const remote = await getRemoteSHAs();
            FM._setBaseSHAsFromRemote(remote, cfg.basePath || '');
        }
    }

    /* ── 파일명 변경 커밋 (rename = delete old + create new) ──
       Git Data API로 단일 커밋에 처리:
         기존 경로: sha = null (삭제)
         새 경로: blob SHA (생성)
       이렇게 하면 git log에서 rename으로 인식됨 (유사도 기반)  */
    async function renameAndCommit(oldPath, newPath, content, commitMsg) {
        if (!cfg) throw new Error('GitHub 설정 없음');

        /* HEAD 및 base tree 조회 */
        const refData    = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
        const headSHA    = refData.object.sha;
        const commitData = await _apiFetch(`/git/commits/${headSHA}`);
        const baseTree   = commitData.tree.sha;

        /* 새 파일 Blob 생성 */
        const blob = await _apiFetch('/git/blobs', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({
                content : btoa(unescape(encodeURIComponent(content))),
                encoding: 'base64',
            }),
        });

        /* Tree: 기존 경로 삭제(null) + 새 경로 추가 */
        const treeItems = [
            { path: oldPath, mode: '100644', type: 'blob', sha: null }, // 삭제
            { path: newPath, mode: '100644', type: 'blob', sha: blob.sha }, // 신규
        ];

        const newTree = await _apiFetch('/git/trees', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({ base_tree: baseTree, tree: treeItems }),
        });

        const newCommit = await _apiFetch('/git/commits', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({
                message: commitMsg || `Rename ${oldPath.split('/').pop()} → ${newPath.split('/').pop()}`,
                tree   : newTree.sha,
                parents: [headSHA],
            }),
        });

        await _apiFetch(`/git/refs/heads/${cfg.branch}`, {
            method : 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({ sha: newCommit.sha }),
        });

        /* 캐시 무효화 */
        await _ghClear('files');
        allFiles = [];

        return { commitSha: newCommit.sha.slice(0, 7) };
    }

    /* ── 새 커밋 알람: 앱 시작 시 HEAD 비교 ──────────────
       localStorage에 마지막으로 본 commitSHA 저장
       앱 열 때 현재 HEAD와 비교 → 새 커밋이면 배너 표시  */
    const SEEN_SHA_KEY = 'mdpro_gh_seen_sha';

    async function checkNewCommits() {
        if (!cfg) return;
        try {
            const refData = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
            const currentSHA = refData.object.sha;
            const seenSHA    = localStorage.getItem(SEEN_SHA_KEY + '_' + cfg.repo);

            if (!seenSHA) {
                /* 첫 실행: 현재 SHA를 기준으로 저장 */
                localStorage.setItem(SEEN_SHA_KEY + '_' + cfg.repo, currentSHA);
                return;
            }
            if (seenSHA === currentSHA) return; // 변경 없음

            /* 새 커밋 수 계산 */
            const compareData = await _apiFetch(
                `/compare/${seenSHA}...${currentSHA}`
            );
            const newCount  = compareData.ahead_by || 0;
            const commits   = compareData.commits  || [];
            const lastAuthor = commits.length
                ? commits[commits.length - 1].commit.author.name
                : '알 수 없음';

            _showCommitBanner(newCount, lastAuthor, currentSHA, commits);
        } catch(e) {
            console.warn('GH.checkNewCommits:', e);
        }
    }

    function _showCommitBanner(count, author, sha, commits) {
        const banner  = document.getElementById('gh-new-commits-banner');
        const msgEl   = document.getElementById('gh-new-commits-msg');
        if (!banner || !msgEl) return;
        msgEl.innerHTML =
            `🔔 <b>${count}개</b>의 새 커밋 ` +
            `— 마지막: <b>${_esc(author)}</b> ` +
            `<a href="https://github.com/${cfg.repo}/commits/${cfg.branch}" ` +
            `target="_blank" style="color:var(--ac);text-decoration:none">` +
            `커밋 보기 →</a>`;
        banner.style.display = '';
        banner._currentSHA = sha;
    }

    function dismissCommitBanner() {
        const banner = document.getElementById('gh-new-commits-banner');
        if (!banner) return;
        if (banner._currentSHA && cfg) {
            localStorage.setItem(SEEN_SHA_KEY + '_' + cfg.repo, banner._currentSHA);
        }
        banner.style.display = 'none';
    }

    /* ── 기기 활동 표시 ───────────────────────────────────
       최근 커밋의 committer name에서 기기명 파싱
       커밋 메시지 형식: "Update file [device:MacBook Pro]"
       이 형식으로 저장하면 기기별 활동 추적 가능         */
    async function loadDeviceActivity() {
        if (!cfg) return;
        try {
            const commits = await _apiFetch(`/commits?sha=${cfg.branch}&per_page=10`);
            const deviceSet = new Set();
            commits.forEach(c => {
                const m = c.commit.message.match(/\[device:([^\]]+)\]/);
                if (m) deviceSet.add(m[1]);
            });
            const bar  = document.getElementById('gh-device-bar');
            const info = document.getElementById('gh-device-info');
            if (!bar || !info) return;
            if (deviceSet.size) {
                info.textContent = `최근 기기: ${[...deviceSet].join(', ')}`;
                bar.style.display = '';
            }
        } catch(e) {}
    }

    /* ── _setRepoUI 확장: 링크 버튼 표시 ────────────────── */
    function _setRepoUI(repoName, state) {
        const nameEl   = document.getElementById('gh-repo-name');
        const refBtn   = document.getElementById('gh-refresh-btn');
        const cloneBtn = document.getElementById('gh-clone-btn');
        const linkBtn  = document.getElementById('gh-repo-link');
        const connected = !!cfg;
        if (nameEl) {
            if (state === 'loading') { nameEl.textContent = '⟳ 로딩 중…'; nameEl.style.color = 'var(--tx3)'; }
            else if (state === 'err') { nameEl.textContent = `⚠ ${repoName}`; nameEl.style.color = '#f76a6a'; }
            else if (connected) { nameEl.textContent = repoName + (allFiles.length ? `  (${allFiles.length}개)` : ''); nameEl.style.color = 'var(--tx2)'; }
            else { nameEl.textContent = '미연결'; nameEl.style.color = 'var(--tx3)'; }
        }
        if (refBtn)   refBtn.style.display   = connected ? '' : 'none';
        if (cloneBtn) cloneBtn.style.display  = connected ? '' : 'none';
        const saveBtn = document.getElementById('gh-hdr-save-btn');
        if (saveBtn) {
            if (connected) saveBtn.classList.add('gh-hdr-save-connected');
            else saveBtn.classList.remove('gh-hdr-save-connected');
        }
        if (linkBtn && connected) {
            linkBtn.href = `https://github.com/${cfg.repo}`;
            linkBtn.style.display = '';
        } else if (linkBtn) {
            linkBtn.style.display = 'none';
        }
        /* 새파일/새폴더 버튼: 연결 시에만 표시 (sb-stats 한 줄) */
        const ghNewfileBtn = document.getElementById('gh-newfile-btn');
        const ghMkdirBtn = document.getElementById('gh-mkdir-btn');
        if (ghNewfileBtn) ghNewfileBtn.style.display = connected ? '' : 'none';
        if (ghMkdirBtn) ghMkdirBtn.style.display = connected ? '' : 'none';
        if (connected) {
            _ghArUpdateBtn();
            if (_ghArEnabled) _ghStartAutoRefresh();
        } else {
            _ghStopAutoRefresh();
        }
        const sbArWrap = document.getElementById('statusbar-ar-wrap');
        const sbArSep = document.getElementById('statusbar-ar-sep');
        if (sbArWrap) sbArWrap.style.display = connected ? 'flex' : 'none';
        if (sbArSep) sbArSep.style.display = connected ? '' : 'none';
        const ghCommitBtn = document.getElementById('gh-commit-history-btn');
        if (ghCommitBtn) ghCommitBtn.style.display = connected ? '' : 'none';
    }

    /* ── 커밋 히스토리 ─────────────────────────────────────
       IDB 'mdpro-gh-v1' meta store 에 캐시
       GET /repos/{owner}/{repo}/commits?sha=branch&per_page=60 */
    let _historyCache = [];

    async function loadHistory(forceRefresh) {
        if (!cfg) { alert('GitHub 연결 필요'); return; }
        const repoEl  = document.getElementById('gh-history-repo');
        const listEl  = document.getElementById('gh-history-list');
        if (repoEl) repoEl.textContent = cfg.repo;

        /* IDB 캐시 먼저 확인 */
        if (!forceRefresh) {
            try {
                const cached = await _ghGet('meta', 'gh_hist_' + cfg.repo);
                if (cached && cached.commits && cached.commits.length) {
                    _historyCache = cached.commits;
                    _renderHistory(_historyCache);
                    /* 백그라운드 갱신 */
                    _fetchHistory().catch(() => {});
                    return;
                }
            } catch(e) {}
        }
        if (listEl) listEl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--tx3);font-size:12px">⟳ 로딩 중…</div>';
        await _fetchHistory();
    }

    async function _fetchHistory() {
        const data = await _apiFetch(`/commits?sha=${cfg.branch}&per_page=60`);
        _historyCache = data.map(c => ({
            sha    : c.sha.slice(0, 7),
            fullSha: c.sha,
            msg    : c.commit.message.split('\n')[0],
            author : c.commit.author.name,
            date   : c.commit.author.date,
            device : (c.commit.message.match(/\[device:([^\]]+)\]/) || [])[1] || null,
            url    : c.html_url,
        }));
        await _ghPut('meta', 'gh_hist_' + cfg.repo, { commits: _historyCache, at: Date.now() });
        _renderHistory(_historyCache);
    }

    function refreshHistory() { loadHistory(true); }

    function filterHistory(q) {
        const filtered = q
            ? _historyCache.filter(c =>
                c.msg.toLowerCase().includes(q.toLowerCase()) ||
                c.author.toLowerCase().includes(q.toLowerCase()) ||
                c.sha.includes(q))
            : _historyCache;
        _renderHistory(filtered);
    }

    function _renderHistory(list) {
        const el2    = document.getElementById('gh-history-list');
        const countEl= document.getElementById('gh-history-count');
        if (!el2) return;
        if (countEl) countEl.textContent = `총 ${list.length}개`;
        if (!list.length) {
            el2.innerHTML = '<div style="padding:16px;text-align:center;color:var(--tx3);font-size:12px">커밋이 없습니다</div>';
            return;
        }
        el2.innerHTML = '';
        list.forEach(c => {
            const div = document.createElement('div');
            div.className = 'commit-item';
            const d = new Date(c.date);
            const ds = `${String(d.getMonth()+1).padStart(2,'0')}.${String(d.getDate()).padStart(2,'0')} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
            div.innerHTML =
                `<span class="commit-sha">${_esc(c.sha)}</span>` +
                `<div class="commit-msg">${_esc(c.msg)}` +
                (c.device ? ` <span class="commit-device-badge">📱${_esc(c.device)}</span>` : '') +
                `</div>` +
                `<div class="commit-meta">${_esc(c.author)}<br>${ds}</div>`;
            div.onclick = () => window.open(c.url, '_blank');
            el2.appendChild(div);
        });
    }

    /* ── 빠른 연결 테스트 (연결 테스트&저장 버튼) ─────────── */
    async function quickConnect() {
        if (!cfg || !cfg.token || !cfg.repo) {
            /* 설정 미완료 → 설정 모달 열기 */
            const ok = confirm(
                'GitHub 연결 설정이 필요합니다.\n\n' +
                '설정 창에서 Token과 저장소를 입력한 후\n' +
                '"연결 테스트 & 저장" 버튼을 눌러주세요.\n\n' +
                '지금 설정 창을 여시겠습니까?'
            );
            if (ok) showSettings();
            return;
        }
        /* 설정 완료 → 즉시 연결 테스트 */
        const btn = document.getElementById('gh-quick-connect-btn');
        if (btn) { btn.textContent = '연결 중…'; btn.disabled = true; }
        try {
            /* 저장소 정보 조회로 연결 확인 */
            const data = await _apiFetch('');   /* /repos/owner/repo */
            App._toast('✓ GitHub 연결 성공: ' + data.full_name);
            /* 파일 목록 로드 */
            await refresh();
        } catch(e) {
            const msg = e.message || '알 수 없는 오류';
            if (msg.includes('401')) {
                alert('❌ 인증 실패\nToken이 올바르지 않습니다.\n설정을 확인하세요.');
            } else if (msg.includes('404')) {
                alert('❌ 저장소 없음\n저장소 주소를 확인하세요: ' + cfg.repo);
            } else {
                alert('❌ 연결 실패: ' + msg);
            }
        } finally {
            if (btn) { btn.textContent = '연결 테스트 & 저장'; btn.disabled = false; }
        }
    }

    function isConnected() { return !!cfg; }

    /* ── GitHub에 새 파일 만들기 ──────────────────────── */
    /* ── GitHub 새 파일 만들기 ─────────────────────────
       흐름: 에디터에 빈 파일 열기 → 저장 시 자동 GitHub Push
       (GitHub Contents API는 특정 경로가 없으면 404 반환하므로
        파일 내용을 직접 PUT 하는 방식으로 변경)
    ──────────────────────────────────────────────── */
    async function createNewFile() {
        if (!cfg) { alert('GitHub 연결 필요'); return; }

        /* 현재 저장소 내 폴더 목록 구성 (파일 경로 + 빈 폴더 포함) */
        const folderSet = new Set(['/']);
        allFiles.forEach(f => {
            const parts = f.path.split('/');
            for (let i = 1; i < parts.length; i++) {
                folderSet.add(parts.slice(0, i).join('/'));
            }
        });
        Object.keys(_ghEmptyFolders).forEach(fp => { if (fp) folderSet.add(fp); });
        const folderOptions = [...folderSet].sort().map(p =>
            `<option value="${p}">${p === '/' ? '📁 (루트)' : '📂 ' + p}</option>`
        ).join('');

        /* 모달 */
        const result = await _ghNewItemModal({
            title: '📄 GitHub 새 파일',
            folderOptions,
            namePlaceholder: 'notes.md',
            nameLabel: '파일 이름 (.md 자동 추가)',
            okLabel: '✔ 에디터에서 열기 & Push',
        });
        if (!result) return;

        let fname = result.name.trim();
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe = fname.replace(/[\\:*?"<>|]/g, '_');
        const basePath = cfg.path ? cfg.path.replace(/\/$/, '') + '/' : '';
        const folderPart = result.folder && result.folder !== '/' ? result.folder + '/' : '';
        const filePath = basePath + folderPart + safe;

        /* 에디터에 새 탭으로 열고 ghPath 지정 → 저장 시 자동 Push */
        const title = safe.replace(/\.[^.]+$/, '');
        const initContent = '# ' + title + '\n\n';
        const tab = TM.newTab(title, initContent, 'md');
        tab.ghPath   = filePath;
        tab.ghBranch = cfg.branch || 'main';
        TM.markDirty();
        TM.renderTabs();

        /* 즉시 GitHub에 빈 파일 Push — 응답 SHA를 tab에 저장해야 다음 저장 시 422 방지 */
        try {
            App._toast('⟳ GitHub에 파일 생성 중…');
            const encoded = btoa(unescape(encodeURIComponent(initContent)));
            const res = await _apiFetch(`/contents/${filePath}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: 'Create ' + safe,
                    content: encoded,
                    branch: cfg.branch || 'main',
                }),
            });
            /* ★ SHA 저장 — 없으면 다음 PUT 때 422 "sha wasn't supplied" 오류 */
            if (res && res.content && res.content.sha) {
                tab.ghSha = res.content.sha;
                _fileContentCache[filePath] = { content: initContent, sha: res.content.sha };
            }
            TM.markClean(tab.id);
            TM.renderTabs();
            App._toast('✅ ' + safe + ' 생성 & Push 완료');
            await refresh();
        } catch(e) {
            App._toast('⚠ 파일은 열렸으나 Push 실패: ' + (e.message || e));
        }
    }

    /* ── GitHub 새 폴더 만들기 ───────────────────────────
       Git은 빈 폴더를 추적하지 않으므로
       폴더/.gitkeep 파일을 Push해서 폴더를 생성합니다.
    ──────────────────────────────────────────────── */
    async function createNewFolder() {
        if (!cfg) { alert('GitHub 연결 필요'); return; }

        const folderSet = new Set(['/']);
        allFiles.forEach(f => {
            const parts = f.path.split('/');
            for (let i = 1; i < parts.length; i++) {
                folderSet.add(parts.slice(0, i).join('/'));
            }
        });
        Object.keys(_ghEmptyFolders).forEach(fp => { if (fp) folderSet.add(fp); });
        const folderOptions = [...folderSet].sort().map(p =>
            `<option value="${p}">${p === '/' ? '📁 (루트)' : '📂 ' + p}</option>`
        ).join('');

        const result = await _ghNewItemModal({
            title: '📁 GitHub 새 폴더',
            folderOptions,
            namePlaceholder: '새폴더',
            nameLabel: '폴더 이름',
            okLabel: '✔ 생성 & Push',
            isFolder: true,
        });
        if (!result) return;

        const safe = result.name.trim().replace(/[/\\:*?"<>|]/g, '_');
        const basePath = cfg.path ? cfg.path.replace(/\/$/, '') + '/' : '';
        const folderPart = result.folder && result.folder !== '/' ? result.folder + '/' : '';
        const keepPath = basePath + folderPart + safe + '/.gitkeep';

        try {
            App._toast('⟳ GitHub에 폴더 생성 중…');
            await _apiFetch(`/contents/${keepPath}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: 'Create folder ' + safe,
                    content: btoa(''),
                    branch: cfg.branch || 'main',
                }),
            });
            App._toast('✅ ' + safe + ' 폴더 생성 & Push 완료');
            await refresh();
        } catch(e) {
            alert('폴더 생성 실패: ' + (e.message || e));
        }
    }

    /* ── GitHub 새 파일/폴더 생성 공용 모달 ─────────────── */
    function _ghNewItemModal({ title, folderOptions, namePlaceholder, nameLabel, okLabel, isFolder }) {
        return new Promise(resolve => {
            const existing = document.getElementById('gh-newitem-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'gh-newitem-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:340px;max-width:460px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">${title}</span>
                    <button id="gni-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">위치 (폴더)</label>
                    <select id="gni-folder" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions}
                    </select>
                </div>
                <div style="margin-bottom:${isFolder ? 8 : 16}px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">${nameLabel}</label>
                    <input id="gni-name" type="text" placeholder="${namePlaceholder}"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                ${!isFolder ? `
                <div style="margin-bottom:16px;padding:9px 12px;background:rgba(124,106,247,.08);border:1px solid rgba(124,106,247,.25);border-radius:7px;font-size:11px;color:var(--tx2);line-height:1.7">
                    💡 파일이 에디터에 열리고 <b>GitHub에 즉시 Push</b>됩니다.<br>
                    이후 수정 내용은 <b>저장(💾) → GitHub 커밋</b>으로 반영하세요.
                </div>` : `
                <div style="margin-bottom:16px;padding:9px 12px;background:rgba(124,106,247,.08);border:1px solid rgba(124,106,247,.25);border-radius:7px;font-size:11px;color:var(--tx2);line-height:1.7">
                    💡 Git은 빈 폴더를 저장할 수 없어 <b>.gitkeep</b> 파일이 함께 Push됩니다.
                </div>`}
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="gni-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="gni-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">${okLabel}</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const nameInput = document.getElementById('gni-name');
            setTimeout(() => { nameInput.focus(); }, 50);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('gni-close').onclick = () => close(null);
            document.getElementById('gni-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('gni-ok').onclick = () => {
                const n = nameInput.value.trim();
                if (!n) { nameInput.focus(); return; }
                close({ folder: document.getElementById('gni-folder').value, name: n });
            };
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('gni-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });
    }

    /* ── 파일별 마지막 커밋 날짜 lazy fetch ─────────────── */
    const _dateFetchQueue = new Set();
    async function _fetchFileDate(f) {
        if (_dateFetchQueue.has(f.path)) return;
        _dateFetchQueue.add(f.path);
        try {
            const commits = await _apiFetch(
                `/commits?path=${encodeURIComponent(f.path)}&sha=${cfg.branch || 'main'}&per_page=1`
            );
            if (commits && commits.length > 0) {
                f.date = commits[0].commit.author.date;
                /* DOM 업데이트 — 해당 파일의 meta span만 */
                const span = document.querySelector(`.file-item-meta[data-gh-meta="${CSS.escape(f.path)}"]`);
                if (span) {
                    const ghSizeStr = f.size != null
                        ? (f.size >= 1048576
                            ? (f.size / 1048576).toFixed(1) + 'MB'
                            : f.size >= 1024
                                ? (f.size / 1024).toFixed(1) + 'KB'
                                : f.size + 'B')
                        : '';
                    const ghDateStr = new Date(f.date).toLocaleDateString('ko', { month:'2-digit', day:'2-digit' });
                    span.innerHTML = ghSizeStr && ghDateStr
                        ? `<span class="file-item-meta-size">${ghSizeStr}</span> · <span class="file-item-meta-date">${ghDateStr}</span>`
                        : ghSizeStr ? `<span class="file-item-meta-size">${ghSizeStr}</span>` : ghDateStr ? `<span class="file-item-meta-date">${ghDateStr}</span>` : '';
                    const row = span.closest('.file-item');
                    if (row) row.title = f.path + (ghSizeStr ? '\n크기: ' + ghSizeStr : '') + '\n수정: ' + ghDateStr;
                }
            }
        } catch(e) { /* silent fail */ }
        _dateFetchQueue.delete(f.path);
    }

    /* ── md-viewer로 파일 Push (PVShare 위임) ── */
    function pushFile(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._ghFile;
        if (!f) return;
        /* 파일 내용 읽어서 PVShare로 전달 */
        const cached = _fileContentCache[f.path];
        if (cached && cached.content) {
            PVShare.quickPush({ name: f.name, content: cached.content });
        } else {
            /* 캐시 없으면 API로 가져옴 */
            btn.textContent = '⟳';
            _apiFetch(`/contents/${encodeURIComponent(f.path)}?ref=${cfg.branch}`)
                .then(data => {
                    const content = decodeURIComponent(escape(atob(data.content.replace(/\n/g,''))));
                    _fileContentCache[f.path] = { content, sha: data.sha };
                    btn.textContent = '📤';
                    PVShare.quickPush({ name: f.name, content });
                })
                .catch(e => { btn.textContent = '📤'; alert('파일 읽기 실패: ' + e.message); });
        }
    }

    /* ── GitHub 폴더 삭제 ──────────────────────────────────
       전략: Git Trees API로 해당 폴더 내 모든 blob을 null SHA로 삭제 커밋
       빈 폴더(.gitkeep)는 .gitkeep 파일 삭제로 처리              */
    async function confirmDeleteFolder(btn) {
        const folderPath = btn.dataset.path;
        const ghIsEmpty  = btn.dataset.empty === 'true';
        if (!folderPath || !cfg) return;

        const basePath = cfg.path ? cfg.path.replace(/\/$/, '') + '/' : '';
        const fullFolder = basePath + folderPath;

        /* 폴더 내 파일 목록 */
        const filesInFolder = allFiles.filter(f =>
            f.path === folderPath ||
            f.path.startsWith(folderPath + '/')
        );
        const fileCount = filesInFolder.length;

        /* 확인 모달 */
        const result = await _showGhFolderDeleteModal(folderPath, ghIsEmpty, fileCount);
        if (!result) return;

        const commitMsg = result.commitMsg || `Delete folder ${folderPath.split('/').pop()}`;

        try {
            App._toast('⟳ GitHub에서 폴더 삭제 중…');

            if (ghIsEmpty && fileCount === 0) {
                /* 빈 폴더: .gitkeep 파일만 삭제 */
                const keepPath = fullFolder + '/.gitkeep';
                try {
                    const data = await _apiFetch(`/contents/${encodeURIComponent(keepPath)}?ref=${cfg.branch}`);
                    await _apiFetch(`/contents/${encodeURIComponent(keepPath)}`, {
                        method : 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body   : JSON.stringify({
                            message: commitMsg,
                            sha    : data.sha,
                            branch : cfg.branch || 'main',
                        }),
                    });
                } catch(e2) { /* .gitkeep이 없어도 무시 */ }
                delete _ghEmptyFolders[folderPath];
                _ghPut('meta', 'emptyFolders', { folders: Object.keys(_ghEmptyFolders) }).catch(()=>{});
            } else {
                /* 비어있지 않은 폴더: Git Trees API로 일괄 삭제 */
                const refData    = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
                const headSHA    = refData.object.sha;
                const commitData = await _apiFetch(`/git/commits/${headSHA}`);
                const baseTree   = commitData.tree.sha;

                /* 삭제할 경로 목록 (SHA=null) */
                const treeItems = filesInFolder.map(f => ({
                    path: f.path,
                    mode: '100644',
                    type: 'blob',
                    sha : null,
                }));

                /* .gitkeep도 존재할 수 있으면 추가 */
                treeItems.push({
                    path: fullFolder + '/.gitkeep',
                    mode: '100644', type: 'blob', sha: null,
                });

                const newTree = await _apiFetch('/git/trees', {
                    method : 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body   : JSON.stringify({ base_tree: baseTree, tree: treeItems }),
                });
                const newCommit = await _apiFetch('/git/commits', {
                    method : 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body   : JSON.stringify({
                        message: commitMsg,
                        tree   : newTree.sha,
                        parents: [headSHA],
                    }),
                });
                await _apiFetch(`/git/refs/heads/${cfg.branch}`, {
                    method : 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body   : JSON.stringify({ sha: newCommit.sha }),
                });

                /* 메모리에서 제거 */
                filesInFolder.forEach(f => {
                    delete _fileContentCache[f.path];
                });
                allFiles  = allFiles.filter(f =>
                    f.path !== folderPath && !f.path.startsWith(folderPath + '/')
                );
                filtered  = filtered.filter(f =>
                    f.path !== folderPath && !f.path.startsWith(folderPath + '/')
                );
                delete _ghEmptyFolders[folderPath];
                _ghPut('meta', 'emptyFolders', { folders: Object.keys(_ghEmptyFolders) }).catch(()=>{});
            }

            _render();
            App._toast(`🗑 "${folderPath}" 폴더 삭제 완료`);
            /* 백그라운드 재스캔 */
            refresh().catch(()=>{});
        } catch(e) {
            alert('폴더 삭제 실패: ' + (e.message || e));
        }
    }

    /* ── GitHub 폴더 삭제 확인 모달 ── */
    function _showGhFolderDeleteModal(folderPath, isEmpty, fileCount) {
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9100;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const folderName = folderPath.split('/').pop();
            const warnHtml = isEmpty
                ? `<div style="font-size:11px;color:#6af7b0;margin-top:6px">✅ 빈 폴더입니다. .gitkeep 파일이 삭제됩니다.</div>`
                : `<div style="font-size:11px;color:#f7a06a;margin-top:6px;line-height:1.7">
                    ⚠ 이 폴더 안의 <b style="color:#ff8080">${fileCount}개 파일</b>이 모두 GitHub에서 삭제됩니다.<br>
                    삭제 후 복구하려면 Git 히스토리를 사용해야 합니다.
                   </div>`;

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:2px solid rgba(247,106,106,.4);border-radius:12px;padding:20px 22px;min-width:320px;max-width:440px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;gap:9px;margin-bottom:14px">
                    <span style="font-size:20px">🗑</span>
                    <span style="font-size:14px;font-weight:700;color:#f76a6a">🐙 GitHub 폴더 삭제</span>
                </div>
                <div style="background:rgba(247,106,106,.08);border:1px solid rgba(247,106,106,.3);border-radius:8px;padding:12px 14px;margin-bottom:12px">
                    <div style="font-size:11px;color:var(--tx3);margin-bottom:4px">삭제할 폴더</div>
                    <div style="font-size:14px;font-weight:700;color:#f76a6a">${_esc(folderName)}</div>
                    <div style="font-size:10px;color:var(--tx3);font-family:var(--fm)">${_esc(folderPath)}</div>
                    ${warnHtml}
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">커밋 메시지</label>
                    <input id="gfdel-msg" type="text" value="Delete folder ${_esc(folderName)}"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="gfdel-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="gfdel-ok" style="padding:6px 18px;border-radius:6px;border:none;background:rgba(247,106,106,.2);border:1px solid rgba(247,106,106,.5);color:#f76a6a;font-size:12px;font-weight:700;cursor:pointer">🗑 삭제 확인</button>
                </div>`;
            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('gfdel-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('gfdel-ok').onclick = () => {
                const msg = document.getElementById('gfdel-msg').value.trim();
                close({ commitMsg: msg || `Delete folder ${folderName}` });
            };
            const inp = document.getElementById('gfdel-msg');
            inp.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('gfdel-ok').click();
                if (e.key === 'Escape') close(null);
            });
            setTimeout(() => { inp.focus(); inp.select(); }, 50);
        });
    }

    /* ── GitHub 파일 이동 ─────────────────────────────────
       Git Trees API: 기존 경로 blob(null) + 새 경로 blob(sha) 단일 커밋  */
    async function moveFile(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._ghFile;
        if (!f) return;

        /* 이동 가능 폴더 목록 (현재 폴더 제외) */
        const currentFolder = f.path.includes('/')
            ? f.path.split('/').slice(0, -1).join('/')
            : '/';

        const folderSet = new Set(['/']);
        allFiles.forEach(ff => {
            const parts = ff.path.split('/');
            for (let i = 1; i < parts.length; i++) {
                folderSet.add(parts.slice(0, i).join('/'));
            }
        });
        Object.keys(_ghEmptyFolders).forEach(fp => { if (fp) folderSet.add(fp); });

        const folderOptions = [...folderSet].sort()
            .filter(p => p !== currentFolder)
            .map(p => ({ label: p === '/' ? '📁 (루트)' : '📂 ' + p, value: p }));

        const result = await _showGhMoveModal(f.name, folderOptions);
        if (!result) return;

        const { destFolder, commitMsg } = result;
        const basePath   = cfg.path ? cfg.path.replace(/\/$/, '') + '/' : '';
        const oldPath    = f.path;
        const newRelDir  = destFolder === '/' ? '' : destFolder + '/';
        const newPath    = basePath + newRelDir + f.name;

        if (newPath === oldPath) { App._toast('같은 폴더입니다'); return; }

        try {
            App._toast('⟳ GitHub에서 파일 이동 중…');

            /* 원본 파일 내용+SHA 취득 */
            let content, sha;
            const cached = _fileContentCache[oldPath];
            if (cached && cached.sha) {
                sha     = cached.sha;
                content = cached.content;
            } else {
                const data = await _apiFetch(`/contents/${encodeURIComponent(oldPath)}?ref=${cfg.branch}`);
                sha     = data.sha;
                content = decodeURIComponent(escape(atob(data.content.replace(/\n/g, ''))));
            }

            /* Git Trees API: 기존 경로 삭제(null) + 새 경로 추가 */
            const refData    = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
            const headSHA    = refData.object.sha;
            const commitData = await _apiFetch(`/git/commits/${headSHA}`);
            const baseTree   = commitData.tree.sha;

            const blob = await _apiFetch('/git/blobs', {
                method : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({
                    content : btoa(unescape(encodeURIComponent(content))),
                    encoding: 'base64',
                }),
            });

            const newTree = await _apiFetch('/git/trees', {
                method : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({
                    base_tree: baseTree,
                    tree: [
                        { path: oldPath, mode: '100644', type: 'blob', sha: null },
                        { path: newPath, mode: '100644', type: 'blob', sha: blob.sha },
                    ],
                }),
            });
            const newCommit = await _apiFetch('/git/commits', {
                method : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({
                    message: commitMsg || `Move ${f.name} → ${destFolder === '/' ? '루트' : destFolder}`,
                    tree   : newTree.sha,
                    parents: [headSHA],
                }),
            });
            await _apiFetch(`/git/refs/heads/${cfg.branch}`, {
                method : 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({ sha: newCommit.sha }),
            });

            /* 캐시 갱신 */
            delete _fileContentCache[oldPath];
            _fileContentCache[newPath] = { content, sha: blob.sha };

            /* 탭 경로 업데이트 */
            const tab = TM.getAll().find(t => t.ghPath === oldPath);
            if (tab) {
                tab.ghPath = newPath;
                tab.ghSha  = blob.sha;
                TM.renderTabs();
            }

            App._toast(`✅ "${f.name}" → "${destFolder === '/' ? '루트' : destFolder}" 이동 완료`);
            await refresh();
        } catch(e) {
            alert('파일 이동 실패: ' + (e.message || e));
        }
    }

    /* ── GitHub 파일 이동 모달 ── */
    function _showGhMoveModal(fileName, folderOptions) {
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9100;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';
            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:440px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📦 GitHub 파일 이동</span>
                    <button id="gmov-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="font-size:12px;color:var(--tx2);margin-bottom:12px;padding:8px 10px;background:var(--bg3);border-radius:6px">
                    📝 <b>${_esc(fileName)}</b>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">이동할 폴더 선택</label>
                    <select id="gmov-dest" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions.map(o => `<option value="${o.value}">${o.label}</option>`).join('')}
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">커밋 메시지</label>
                    <input id="gmov-msg" type="text" value="Move ${_esc(fileName)}"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="gmov-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="gmov-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 이동 & Push</button>
                </div>`;
            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('gmov-close').onclick  = () => close(null);
            document.getElementById('gmov-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('gmov-ok').onclick = () => {
                close({
                    destFolder: document.getElementById('gmov-dest').value,
                    commitMsg : document.getElementById('gmov-msg').value.trim(),
                });
            };
        });
    }

    /* ── GitHub 폴더별 새 파일 만들기 (폴더 + 버튼에서 호출) ── */
    async function _createFileInFolder(folderPath) {
        if (!cfg) { alert('GitHub 연결 필요'); return; }

        const folderSet = new Set(['/']);
        allFiles.forEach(f => {
            const parts = f.path.split('/');
            for (let i = 1; i < parts.length; i++) {
                folderSet.add(parts.slice(0, i).join('/'));
            }
        });
        Object.keys(_ghEmptyFolders).forEach(fp => { if (fp) folderSet.add(fp); });
        const folderOptions = [...folderSet].sort().map(p =>
            `<option value="${p}" ${p === folderPath ? 'selected' : ''}>${p === '/' ? '📁 (루트)' : '📂 ' + p}</option>`
        ).join('');

        const result = await _ghNewItemModal({
            title: '📄 GitHub 새 파일',
            folderOptions,
            namePlaceholder: 'notes.md',
            nameLabel: '파일 이름 (.md 자동 추가)',
            okLabel: '✔ 에디터에서 열기 & Push',
        });
        if (!result) return;

        let fname = result.name.trim();
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe = fname.replace(/[\\:*?"<>|]/g, '_');
        const basePath = cfg.path ? cfg.path.replace(/\/$/, '') + '/' : '';
        const folderPart = result.folder && result.folder !== '/' ? result.folder + '/' : '';
        const filePath = basePath + folderPart + safe;

        const title = safe.replace(/\.[^.]+$/, '');
        const initContent = '# ' + title + '\n\n';
        const tab = TM.newTab(title, initContent, 'md');
        tab.ghPath   = filePath;
        tab.ghBranch = cfg.branch || 'main';
        TM.markDirty();
        TM.renderTabs();

        try {
            App._toast('⟳ GitHub에 파일 생성 중…');
            const encoded = btoa(unescape(encodeURIComponent(initContent)));
            const res = await _apiFetch(`/contents/${filePath}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: 'Create ' + safe,
                    content: encoded,
                    branch: cfg.branch || 'main',
                }),
            });
            if (res && res.content && res.content.sha) {
                tab.ghSha = res.content.sha;
                _fileContentCache[filePath] = { content: initContent, sha: res.content.sha };
            }
            TM.markClean(tab.id);
            TM.renderTabs();
            App._toast('✅ ' + safe + ' 생성 & Push 완료');
            await refresh();
        } catch(e) {
            App._toast('⚠ 파일은 열렸으나 Push 실패: ' + (e.message || e));
        }
    }

    return {
        restore, refresh, search, showSettings, hideSettings, saveSettings, handleHdrSaveClick,
        reloadCfg: () => { cfg = _loadCfg(); },
        saveFile, createFile, pushLocalFiles, getRemoteSHAs,
        openRepoLink, cloneRepo, renameAndCommit,
        checkNewCommits, dismissCommitBanner, loadDeviceActivity,
        loadHistory, refreshHistory, filterHistory,
        quickConnect, isConnected, _render,
        createNewFile, createNewFolder, _createFileInFolder,
        confirmDelete, confirmDeleteFolder, moveFile, pushFile,
        toggleFoldAll, toggleAutoRefresh, showArIntervalSetting,
        syncHighlightFromActiveTab,
        get cfg() { return cfg; },
    };
})();


const FM = (() => {
    /* ── IDB ───────────────────────────────────────────── */
    const DB_NAME = 'mdpro-fm-v3';
    const DB_VER  = 1;
    let _db       = null;
    let _subHandles    = {};  /* path → FileSystemDirectoryHandle */
    let _currentSubDir = null; /* 현재 탐색 중인 하위 폴더 경로 */

    function _getDB() {
        if (_db) return Promise.resolve(_db);
        return new Promise((res, rej) => {
            const req = indexedDB.open(DB_NAME, DB_VER);
            req.onupgradeneeded = ev => {
                const db = ev.target.result;
                if (!db.objectStoreNames.contains('meta'))  db.createObjectStore('meta');
                if (!db.objectStoreNames.contains('files')) db.createObjectStore('files');
            };
            req.onsuccess = ev => { _db = ev.target.result; res(_db); };
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    /* IDB 단일 키 읽기 */
    async function _idbGet(store, key) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store, 'readonly').objectStore(store).get(key);
            req.onsuccess = ev => res(ev.target.result ?? null);
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    /* IDB 전체 키·값 읽기 */
    async function _idbAll(store) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const results = [];
            const req = db.transaction(store, 'readonly').objectStore(store).openCursor();
            req.onsuccess = ev => {
                const cur = ev.target.result;
                if (cur) { results.push(cur.value); cur.continue(); }
                else res(results);
            };
            req.onerror = ev => rej(ev.target.error);
        });
    }

    /* IDB 쓰기 */
    async function _idbPut(store, key, val) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store, 'readwrite').objectStore(store).put(val, key);
            req.onsuccess = () => res();
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    /* IDB 전체 삭제 */
    async function _idbClearStore(store) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store, 'readwrite').objectStore(store).clear();
            req.onsuccess = () => res();
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    async function _idbDel(store, key) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store, 'readwrite').objectStore(store).delete(key);
            req.onsuccess = () => res();
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    /* ── 상태 ─────────────────────────────────────────── */
    const hasAPI   = () => 'showDirectoryPicker' in window;
    let dirHandle  = null;   // FileSystemDirectoryHandle (세션 중에만 유효)
    let allFiles   = [];     // 현재 표시 중인 파일 목록
    let filtered   = [];
    let activeFile = null;
    let folderName = '';     // 폴더 이름 (표시용)
    let _searchQuery = '';   // 검색어 (search input)
    const FM_SHOW_HIDDEN_KEY = 'fm_show_hidden';
    let showHiddenFiles = localStorage.getItem(FM_SHOW_HIDDEN_KEY) === 'on';  /* 디폴트: 숨김 */

    function _isPathHidden(path) {
        return path.split('/').some(seg => seg.startsWith('.'));
    }
    function _applyFilters() {
        let base = showHiddenFiles ? allFiles : allFiles.filter(f => !_isPathHidden(f.path));
        filtered = _searchQuery
            ? base.filter(f => f.name.toLowerCase().includes(_searchQuery.toLowerCase()))
            : base;
    }

    /* ── 앱 시작: IDB 캐시에서 즉시 복원 ──────────────
       핸들 없이도 캐시된 목록/내용으로 파일 탭 채움     */
    async function restore() {
        try {
            showHiddenFiles = localStorage.getItem(FM_SHOW_HIDDEN_KEY) === 'on';
            const meta = await _idbGet('meta', 'root');
            if (!meta) return;
            folderName = meta.folderName;
            const cached = await _idbAll('files');
            if (!cached.length) return;
            allFiles   = cached;
            _applyFilters();
            /* DOM이 완전히 준비된 후 UI 업데이트 */
            setTimeout(() => {
                _setFolderUI(folderName, false);
                _render();
            }, 0);
        } catch (e) {
            console.warn('FM.restore:', e);
        }
    }

    /* ── 폴더 선택 ─────────────────────────────────────── */
    async function selectFolder() {
        if (!hasAPI()) { _noAPIFallback(); return; }
        try {
            const h = await window.showDirectoryPicker({ mode: 'readwrite' });
            dirHandle = h;
            folderName = h.name;
            _setFolderUI(folderName, 'syncing');
            await _syncFromHandle();                // 파일 읽기 + IDB 캐시 저장
            _setFolderUI(folderName, true);
        } catch (e) {
            if (e.name !== 'AbortError') console.warn('FM.selectFolder:', e);
        }
    }

    /* ── 실제 파일 시스템 → IDB 전체 동기화 ─────────────
       dirHandle이 활성(permission granted)일 때만 호출   */
    async function _syncFromHandle() {
        if (!dirHandle) return;
        const fresh = [];
        _emptyFolders = {};  /* 빈 폴더 목록 초기화 */
        await _scanDir(dirHandle, '', 0, fresh);
        allFiles = fresh;
        _applyFilters();
        /* IDB 캐시 저장 */
        await _idbClearStore('files');
        const db = await _getDB();
        await new Promise((res, rej) => {
            const tx = db.transaction('files', 'readwrite');
            const st = tx.objectStore('files');
            fresh.forEach(f => st.put(f, f.path));
            tx.oncomplete = res;
            tx.onerror    = ev => rej(ev.target.error);
        });
        await _idbPut('meta', 'root', {
            folderName,
            fileCount: fresh.length,
            syncedAt: Date.now()
        });
        _render();
    }

    /* 빈 폴더도 추적 (폴더경로 → true) */
    let _emptyFolders = {};

    /* ── 디렉터리 재귀 스캔 ────────────────────────────── */
    async function _scanDir(handle, prefix, depth, out) {
        if (depth > 4) return;
        let hasChildren = false;
        for await (const entry of handle.values()) {
            hasChildren = true;
            if (entry.kind === 'directory') {
                const subPath = prefix ? `${prefix}/${entry.name}` : entry.name;
                _subHandles[subPath] = entry;   /* 하위 폴더 핸들 저장 */
                await _scanDir(entry, subPath, depth + 1, out);
            } else if (entry.kind === 'file') {
                const ext = entry.name.split('.').pop().toLowerCase();
                if (!['md','txt','html'].includes(ext)) continue;
                try {
                    const file    = await entry.getFile();
                    const content = await file.text();
                    out.push({
                        name    : entry.name,
                        ext,
                        folder  : prefix || '/',
                        path    : prefix ? `${prefix}/${entry.name}` : entry.name,
                        content,
                        modified: file.lastModified,
                    });
                } catch(e) { /* 읽기 실패 파일 스킵 */ }
            }
        }
        /* 이 폴더에 md/txt/html 파일이 없고 하위도 없으면 빈 폴더로 기록 */
        if (prefix) {
            const hasFiles = out.some(f => f.folder === prefix || f.path.startsWith(prefix + '/'));
            if (!hasFiles) _emptyFolders[prefix] = true;
        }
    }

    /* ── 새로고침: 폴더 재연결 or 캐시 재로드 ─────────── */
    async function refresh() {
        /* dirHandle이 있으면 실시간 동기화 시도 */
        if (dirHandle) {
            try {
                const perm = await dirHandle.queryPermission({ mode: 'read' });
                if (perm === 'granted') {
                    _setFolderUI(folderName, 'syncing');
                    await _syncFromHandle();
                    _setFolderUI(folderName, true);
                    return;
                }
            } catch(e) {}
        }
        /* 권한 없음 → 폴더 선택 다이얼로그 */
        await selectFolder();
    }

    /* ── 폴더 변경 ──────────────────────────────────────── */
    async function changeFolder() {
        dirHandle  = null;
        allFiles   = [];
        filtered   = [];
        folderName = '';
        _searchQuery = '';
        const searchInput = document.getElementById('files-search-input');
        if (searchInput) searchInput.value = '';
        await _idbClearStore('files');
        await _idbClearStore('meta');
        _render();
        await selectFolder();
    }

    /* ── UI 헤더 상태 표시 ────────────────────────────── */
    function _setFolderUI(name, state) {
        /* state: true(연결됨) | false(캐시,오프라인) | 'syncing' */
        const nameEl  = document.getElementById('files-folder-name');
        const selBtn  = document.getElementById('files-folder-btn');
        const refBtn  = document.getElementById('files-refresh-btn');
        const syncBar = document.getElementById('fm-sync-bar');
        if (syncBar) syncBar.style.display = (name && state !== 'syncing') ? '' : 'none';

        if (nameEl) {
            if (state === 'syncing') {
                nameEl.textContent = `⟳ 동기화 중…`;
                nameEl.style.color = 'var(--tx3)';
            } else if (state === true) {
                nameEl.textContent = `${name}  (${allFiles.length}개)`;
                nameEl.style.color = 'var(--tx2)';
            } else {
                /* 캐시 모드 */
                nameEl.innerHTML =
                    `<span style="color:var(--tx3);font-size:9px">📦 캐시</span> ${_esc(name)}`;
                nameEl.style.color = 'var(--tx3)';
            }
        }
        if (selBtn) {
            selBtn.textContent = (state !== false) ? '↺ 변경' : '🔄 재연결';
            selBtn.onclick     = (state !== false) ? changeFolder : refresh;
            selBtn.title       = (state === false)
                ? '폴더를 다시 선택하여 최신 파일을 동기화합니다'
                : '다른 폴더로 변경';
        }
        if (refBtn) refBtn.style.display = (state === true) ? '' : 'none';
        const openBtn = document.getElementById('files-open-btn');
        const foldBtn = document.getElementById('files-fold-toggle-btn');
        const hiddenBtn = document.getElementById('files-hidden-toggle-btn');
        if (openBtn) openBtn.style.display = (state === true && name) ? '' : 'none';
        if (foldBtn) foldBtn.style.display = (state === true && name) ? '' : 'none';
        if (hiddenBtn) {
            hiddenBtn.style.display = (state === true && name) ? '' : 'none';
            hiddenBtn.title = showHiddenFiles ? '숨김 파일 숨기기 (.git 등)' : '숨김 파일 표시 (.git 등)';
            hiddenBtn.classList.toggle('active', showHiddenFiles);
        }
    }

    /* ── 검색 ─────────────────────────────────────────── */
    function search(q) {
        _searchQuery = (q && q.trim()) ? q.trim() : '';
        _applyFilters();
        _render();
    }

    /* ── 숨김 파일 표시 토글 ───────────────────────────── */
    function toggleShowHidden() {
        showHiddenFiles = !showHiddenFiles;
        localStorage.setItem(FM_SHOW_HIDDEN_KEY, showHiddenFiles ? 'on' : 'off');
        _applyFilters();
        _setFolderUI(folderName, !!dirHandle);
        _render();
    }

    /* ── 전체 폴더 접기/펼치기 토글 ───────────────────── */
    function toggleFoldAll() {
        const list = document.getElementById('files-list');
        if (!list) return;
        const folders = list.querySelectorAll('.ft-folder');
        if (!folders.length) return;
        const anyExpanded = Array.from(folders).some(f => !f.classList.contains('collapsed'));
        const collapse = anyExpanded;
        folders.forEach(f => {
            const hdr = f.querySelector('.ft-folder-hdr');
            const toggle = hdr && hdr.querySelector('.ft-toggle');
            const isEmpty = toggle && toggle.textContent === '—';
            if (collapse) {
                f.classList.add('collapsed');
                if (toggle && !isEmpty) toggle.textContent = '▸';
            } else {
                f.classList.remove('collapsed');
                if (toggle && !isEmpty) toggle.textContent = '▾';
            }
        });
        const foldBtn = document.getElementById('files-fold-toggle-btn');
        if (foldBtn) foldBtn.textContent = collapse ? '▾' : '▽';
    }

    /* ── 파일 목록 렌더링 (트리 구조) ─────────────────── */
    function _render() {
        const list = document.getElementById('files-list');
        if (!list) return;
        list.innerHTML = '';

        if (!allFiles.length) {
            list.innerHTML =
                '<div class="files-empty">' +
                '<div style="font-size:28px;margin-bottom:8px">📁</div>' +
                '<div style="font-weight:600;margin-bottom:6px">폴더를 선택하세요</div>' +
                '<div style="color:var(--tx3);font-size:10px;line-height:1.7">.md / .txt / .html 파일<br>하위 폴더까지 트리로 탐색<br>내용이 캐시되어 재시작 후에도<br>즉시 열 수 있습니다</div>' +
                '</div>';
            return;
        }

        const src = filtered;
        if (!src.length) {
            list.innerHTML = '<div class="files-empty">검색 결과 없음</div>';
            return;
        }

        /* ── 트리 노드 빌드 ── */
        /* node: { name, children:{}, files:[] }  */
        const root = { name: '', children: {}, files: [] };

        src.forEach(f => {
            const parts = f.path.split('/');
            let node = root;
            for (let i = 0; i < parts.length - 1; i++) {
                const seg = parts[i];
                if (!node.children[seg]) node.children[seg] = { name: seg, children: {}, files: [] };
                node = node.children[seg];
            }
            node.files.push(f);
        });

        /* 빈 폴더(_emptyFolders)도 트리에 추가 (숨김 경로 제외) */
        const emptyFoldersToAdd = showHiddenFiles
            ? Object.keys(_emptyFolders)
            : Object.keys(_emptyFolders).filter(p => !_isPathHidden(p));
        emptyFoldersToAdd.sort().forEach(folderPath => {
            const parts = folderPath.split('/');
            let node = root;
            for (let i = 0; i < parts.length; i++) {
                const seg = parts[i];
                if (!node.children[seg]) node.children[seg] = { name: seg, children: {}, files: [], _fullPath: parts.slice(0, i+1).join('/') };
                node = node.children[seg];
            }
        });

        /* 트리 노드를 DOM으로 렌더 */
        function renderNode(node, depth, container) {
            const indent = depth * 12;

            /* 하위 폴더 먼저 (알파벳 순) */
            Object.keys(node.children).sort().forEach(folderName => {
                const child = node.children[folderName];
                /* _fullPath 보장 — 트리 빌드 시 누락된 경우 부모 경로로 계산 */
                if (!child._fullPath) {
                    child._fullPath = node._fullPath
                        ? node._fullPath + '/' + folderName
                        : folderName;
                }
                const totalFiles = countFiles(child);
                const isEmpty = totalFiles === 0;

                const folderEl = document.createElement('div');
                folderEl.className = 'ft-folder';

                const hdr = document.createElement('div');
                hdr.className = 'ft-folder-hdr';
                hdr.style.paddingLeft = (8 + indent) + 'px';
                hdr.innerHTML =
                    `<span class="ft-toggle">${isEmpty ? '—' : '▾'}</span>` +
                    `<span class="ft-folder-icon">📂</span>` +
                    `<span class="ft-folder-name">${_esc(folderName)}</span>` +
                    `<span class="ft-count" style="${isEmpty ? 'opacity:.4' : ''}">${isEmpty ? '빈 폴더' : totalFiles}</span>` +
                    `<button class="fg-add-btn" title="이 폴더에 새 파일 만들기" ` +
                    `onclick="event.stopPropagation();FM.createFileInFolder('${_esc(child._fullPath)}')">＋</button>` +
                    `<button class="folder-del-btn" title="${isEmpty ? '빈 폴더 삭제' : '폴더 삭제 (내부 파일 포함)'}" ` +
                    `data-path="${_esc(child._fullPath)}" data-empty="${isEmpty}" ` +
                    `onclick="event.stopPropagation();FM.confirmDeleteFolder(this)">🗑</button>`;
                hdr.onclick = () => {
                    folderEl.classList.toggle('collapsed');
                    hdr.querySelector('.ft-toggle').textContent =
                        folderEl.classList.contains('collapsed') ? '▸' : '▾';
                };
                folderEl.appendChild(hdr);

                const body = document.createElement('div');
                body.className = 'ft-folder-body';
                renderNode(child, depth + 1, body);
                folderEl.appendChild(body);
                container.appendChild(folderEl);
            });

            /* 파일 */
            node.files.sort((a, b) => (b.modified||0) - (a.modified||0)).forEach(f => {
                const row = document.createElement('div');
                const isAct = f.path === activeFile || f.name === activeFile;
                row.className = 'file-item' + (isAct ? ' active' : '');
                row.style.paddingLeft = (18 + indent) + 'px';
                const icon = f.ext === 'html' ? '🌐' : f.ext === 'txt' ? '📄' : '📝';
                const modStr = f.modified
                    ? new Date(f.modified).toLocaleDateString('ko', { month:'2-digit', day:'2-digit' })
                    : '';
                const sizeStr = f.size != null
                    ? (f.size >= 1048576
                        ? (f.size / 1048576).toFixed(1) + 'MB'
                        : f.size >= 1024
                            ? (f.size / 1024).toFixed(1) + 'KB'
                            : f.size + 'B')
                    : '';
                const metaStr = [sizeStr, modStr].filter(Boolean).join(' · ');
                const metaContent = sizeStr && modStr
                    ? `<span class="file-item-meta-size">${sizeStr}</span> · <span class="file-item-meta-date">${modStr}</span>`
                    : sizeStr ? `<span class="file-item-meta-size">${sizeStr}</span>` : modStr ? `<span class="file-item-meta-date">${modStr}</span>` : '';
                row.innerHTML =
                    `<span class="file-item-icon">${icon}</span>` +
                    `<span class="file-item-name">${_esc(f.name.replace(/\.[^.]+$/, ''))}</span>` +
                    `<span class="file-item-meta">${metaContent}</span>` +
                    `<button class="file-share-btn" title="mdliveData(GitHub)에 Push" onclick="event.stopPropagation();FM.pushToGH(this)" style="font-size:9px;padding:1px 4px">🐙</button>` +
                    `<button class="file-share-btn" title="md-viewer에 Push (공유)" onclick="event.stopPropagation();FM.pushToViewer(this)" style="font-size:9px;padding:1px 4px;color:#58c8f8">📤</button>` +
                    `<button class="file-move-btn" title="파일 이동" onclick="event.stopPropagation();FM.moveFile(this)">↗</button>` +
                    `<button class="file-del-btn" title="파일 삭제" onclick="event.stopPropagation();FM.confirmDelete(this)">🗑</button>`;
                row.title = f.path + (f.size != null ? '\n크기: ' + sizeStr : '') + (f.modified ? '\n수정: ' + new Date(f.modified).toLocaleString('ko') : '');
                row._fmFile = f;
                row.onclick = () => _openCached(f);
                container.appendChild(row);
            });
        }

        function countFiles(node) {
            let n = node.files.length;
            Object.values(node.children).forEach(c => { n += countFiles(c); });
            return n;
        }

        /* 루트 파일 + 폴더 트리 렌더 */
        renderNode(root, 0, list);
        /* 전체 접기 버튼: 렌더 후 기본은 모두 펼침 → ▽ */
        const foldBtn = document.getElementById('files-fold-toggle-btn');
        if (foldBtn) foldBtn.textContent = '▽';
    }

    /* ── 파일 열기 (캐시된 내용 사용 → 즉시 열림) ────── */
    function _openCached(f) {
        activeFile = f.name;
        document.querySelectorAll('.file-item').forEach(el =>
            el.classList.toggle('active', el.title.startsWith(f.path)));

        const name    = f.name.replace(/\.[^.]+$/, '');
        const ft      = f.ext === 'html' ? 'md' : f.ext;
        const content = f.ext === 'html'
            ? (TM._htmlToEditableContent || (x => x))(f.content)
            : f.content;

        /* 이미 열린 탭이면 전환 */
        const existing = TM.getAll().find(t => t.filePath === f.path || t.title === name);
        if (existing) { TM.switchTab(existing.id); return; }

        /* 새 탭으로 열기 */
        const tab = TM.newTab(name, content, ft);
        tab.filePath = f.path;
        TM.markClean(tab.id);
        TM.renderTabs();
        TM.persist();
    }

    /* ── 폴백 (API 미지원) ────────────────────────────── */
    function _noAPIFallback() {
        alert('폴더 선택 API는 Chrome/Edge에서만 지원됩니다.\n\n탭 바의 📂 열기 버튼으로 파일을 직접 여세요.');
    }

    function _esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    /* ══════════════════════════════════════════════════════
       로컬 ↔ GitHub 동기화  (안전 설계)

       SHA 추적 구조:
         _baseSHAs  = { ghPath → sha }
                      마지막 pull/push 완료 시점의 원격 SHA
                      → "내 기준점" : 이후 변경 감지의 기준

       상태 분류 (파일별):
         same      : localSHA === remoteSHA  (변경 없음)
         local     : localSHA ≠ baseSHA, remoteSHA === baseSHA  (내가 변경)
         remote    : localSHA === baseSHA, remoteSHA ≠ baseSHA  (원격 변경)
         conflict  : 둘 다 baseSHA와 다름  (충돌)
         new-local : baseSHA 없고 원격도 없음  (내 신규)
         new-remote: baseSHA 없고 로컬도 없음  (원격 신규)

       push 안전 규칙:
         remote 또는 conflict 상태 파일이 하나라도 있으면 push 차단
         → "pull 먼저 실행하세요" 안내

       pull 동작:
         remote/conflict 파일의 GitHub 내용을 IDB 캐시에 반영
         conflict 파일은 사용자 확인 후 교체
         pull 완료 후 _baseSHAs를 원격 최신 SHA로 갱신
    ══════════════════════════════════════════════════════ */

    /* IDB에 기준 SHA 맵 저장/복원 */
    const BASE_SHA_KEY = 'fm_base_shas';
    let _baseSHAs = {};  // ghPath → sha  (마지막 sync 기준점)

    async function _loadBaseSHAs() {
        try {
            const db = await (async () => {
                return new Promise((res, rej) => {
                    const r = indexedDB.open('mdpro-fm-v3', 1);
                    r.onsuccess = e => res(e.target.result);
                    r.onerror   = e => rej(e.target.error);
                });
            })();
            const val = await new Promise((res, rej) => {
                const r = db.transaction('meta','readonly').objectStore('meta').get(BASE_SHA_KEY);
                r.onsuccess = e => res(e.target.result ?? {});
                r.onerror   = e => rej(e.target.error);
            });
            _baseSHAs = val || {};
        } catch(e) { _baseSHAs = {}; }
    }

    async function _saveBaseSHAs() {
        try {
            const db = await (async () => {
                return new Promise((res, rej) => {
                    const r = indexedDB.open('mdpro-fm-v3', 1);
                    r.onsuccess = e => res(e.target.result);
                    r.onerror   = e => rej(e.target.error);
                });
            })();
            await new Promise((res, rej) => {
                const r = db.transaction('meta','readwrite').objectStore('meta').put(_baseSHAs, BASE_SHA_KEY);
                r.onsuccess = () => res();
                r.onerror   = e => rej(e.target.error);
            });
        } catch(e) {}
    }

    /* ── blob SHA 계산 (git hash-object 호환) ─────────── */
    async function _blobSHA(content) {
        const enc  = new TextEncoder();
        const data = enc.encode(content);
        const hdr  = enc.encode('blob ' + data.byteLength);
        const buf  = new Uint8Array(hdr.length + 1 + data.length);
        buf.set(hdr, 0);
        buf[hdr.length] = 0;   /* NUL byte */
        buf.set(data, hdr.length + 1);
        const hashBuf = await crypto.subtle.digest('SHA-1', buf);
        return Array.from(new Uint8Array(hashBuf))
            .map(b => b.toString(16).padStart(2,'0')).join('');
    }

    /* ── 파일 상태 분류 ───────────────────────────────── */
    async function _classifyFiles(remoteSHAs) {
        if (!GH.isConnected()) return { files: [], hasConflict: false, hasRemote: false };
        const ghCfg = GH.cfg;
        const base  = ghCfg && ghCfg.basePath
            ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';

        const results = await Promise.all(allFiles.map(async f => {
            const ghPath   = base + f.path;
            const localSHA = await _blobSHA(f.content);
            const remoteSHA = remoteSHAs[ghPath] || null;
            const baseSHA   = _baseSHAs[ghPath]  || null;

            let status;
            if (!baseSHA && !remoteSHA) status = 'new-local';
            else if (!baseSHA && remoteSHA) {
                status = (localSHA === remoteSHA) ? 'same' : 'conflict';
            } else if (localSHA === remoteSHA)    status = 'same';
            else if (localSHA === baseSHA)         status = 'remote';   // 내가 안 바꿈, 원격만 바뀜
            else if (remoteSHA === baseSHA)        status = 'local';    // 내가 바꿈, 원격은 안 바뀜
            else                                   status = 'conflict'; // 둘 다 바뀜

            return { ...f, ghPath, localSHA, remoteSHA, baseSHA, status };
        }));

        /* 원격에만 있는 신규 파일 (로컬 캐시에 없음) */
        const localPaths = new Set(results.map(f => f.ghPath));
        Object.keys(remoteSHAs).forEach(ghPath => {
            if (!localPaths.has(ghPath)) {
                const base2 = ghCfg && ghCfg.basePath
                    ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
                if (!base2 || ghPath.startsWith(base2)) {
                    const name   = ghPath.split('/').pop();
                    const ext    = name.split('.').pop().toLowerCase();
                    if (['md','txt','html'].includes(ext)) {
                        const relPath = base2 ? ghPath.slice(base2.length) : ghPath;
                        const parts   = relPath.split('/');
                        const fname   = parts.pop();
                        results.push({
                            name: fname, ext, folder: parts.join('/') || '/',
                            path: relPath, ghPath,
                            localSHA: null, remoteSHA: remoteSHAs[ghPath],
                            baseSHA: _baseSHAs[ghPath] || null,
                            status: 'new-remote', content: null,
                        });
                    }
                }
            }
        });

        const hasConflict = results.some(f => f.status === 'conflict');
        const hasRemote   = results.some(f => f.status === 'remote' || f.status === 'new-remote');
        return { files: results, hasConflict, hasRemote };
    }

    /* ── UI 헬퍼 ──────────────────────────────────────── */
    function _syncStatus(cls, msg) {
        const el2 = document.getElementById('fm-sync-status');
        if (!el2) return;
        el2.className = cls;
        el2.textContent = msg;
    }
    function _setBusy(busy) {
        const pullBtn = document.getElementById('fm-pull-btn');
        const pushBtn = document.getElementById('fm-sync-btn');
        const pullIco = document.getElementById('fm-pull-icon');
        const pushIco = document.getElementById('fm-sync-icon');
        if (pullBtn) pullBtn.disabled = busy;
        if (pushBtn) pushBtn.disabled = busy;
        if (pullIco) pullIco.classList.toggle('icon-spin', busy);
        if (pushIco) pushIco.classList.toggle('icon-spin', busy);
    }

    /* ── PULL: GitHub → 로컬 캐시 ────────────────────────
       1. 원격 파일 SHA 맵 조회
       2. remote / new-remote / conflict 파일 분류
       3. conflict 파일: 사용자에게 "원격으로 덮어쓸까?" 확인
       4. 대상 파일 GitHub에서 내용 다운로드
       5. IDB 캐시 갱신 + allFiles 업데이트
       6. _baseSHAs를 현재 원격 SHA로 갱신 (기준점 이동)
       7. 이미 열린 탭에 "갱신됨" 알림                   */
    /* ── Clone URL 복사 (로컬 폴더용) ── */
    function cloneFromGitHub() {
        if (!GH.isConnected()) {
            alert('GitHub 연결이 설정되지 않았습니다.\n먼저 🐙 GitHub 탭에서 연결 설정을 완료하세요.');
            return;
        }
        const ghCfg = GH.cfg;
        const cloneUrl = `https://github.com/${ghCfg.repo}.git`;
        /* 클립보드 복사 + 안내 */
        navigator.clipboard.writeText(cloneUrl).then(() => {
            App._toast(`📋 Clone URL 복사됨: ${cloneUrl}`);
            /* 간단한 안내 모달 */
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9500;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
            ov.innerHTML = `
            <div style="background:var(--bg2);border:1px solid rgba(160,144,255,.35);border-radius:12px;padding:20px 22px;max-width:440px;width:100%;box-shadow:0 12px 50px rgba(0,0,0,.7)">
              <div style="font-size:13px;font-weight:700;color:#a090ff;margin-bottom:10px">📋 Clone URL 복사됨</div>
              <div style="font-size:11px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
                터미널에서 아래 명령으로 로컬에 Clone하세요:
              </div>
              <div style="background:var(--bg3);border:1px solid var(--bd);border-radius:6px;padding:9px 12px;font-family:var(--fm);font-size:11px;color:#a090ff;margin-bottom:14px;word-break:break-all">
                git clone ${cloneUrl}
              </div>
              <div style="font-size:10.5px;color:var(--tx3);margin-bottom:14px;line-height:1.6">
                Clone 후 <b style="color:var(--tx2)">로컬 폴더 열기</b>로 해당 폴더를 선택하면<br>
                Pull / Push로 GitHub와 동기화할 수 있습니다.
              </div>
              <div style="display:flex;justify-content:flex-end">
                <button id="clone-info-close" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">닫기</button>
              </div>
            </div>`;
            document.body.appendChild(ov);
            document.getElementById('clone-info-close').onclick = () => ov.remove();
            ov.onclick = e => { if (e.target === ov) ov.remove(); };
        }).catch(() => {
            prompt('아래 URL을 복사해 git clone 하세요:', cloneUrl);
        });
    }

    async function pullFromGitHub() {
        if (!GH.isConnected()) {
            alert('GitHub 연결이 설정되지 않았습니다.\n먼저 🐙 GitHub 탭에서 연결 설정을 완료하세요.');
            return;
        }
        _setBusy(true);
        _syncStatus('ing', '⟳ 원격 상태 확인 중…');
        try {
            await _loadBaseSHAs();
            const remoteSHAs = await GH.getRemoteSHAs();
            const { files, hasConflict, hasRemote } = await _classifyFiles(remoteSHAs);

            const toFetch = files.filter(f =>
                f.status === 'remote' || f.status === 'new-remote');
            const conflicts = files.filter(f => f.status === 'conflict');

            /* 충돌 파일 처리 */
            let pullConflicts = [];
            if (conflicts.length) {
                const names = conflicts.map(f => `  • ${f.name}`).join('\n');
                const ok = confirm(
                    `⚠ 충돌 파일 ${conflicts.length}개:\n${names}\n\n` +
                    `로컬과 원격 모두 변경되었습니다.\n` +
                    `원격 내용으로 덮어쓰시겠습니까?\n\n` +
                    `(취소: 충돌 파일은 그대로 유지)`
                );
                if (ok) pullConflicts = conflicts;
            }

            const allToPull = [...toFetch, ...pullConflicts];

            if (!allToPull.length && !hasRemote) {
                _syncStatus('ok', '✓ 이미 최신 상태입니다');
                _setBusy(false);
                return;
            }

            _syncStatus('ing', `⟳ ${allToPull.length}개 파일 다운로드 중…`);

            /* GitHub에서 내용 다운로드 */
            const ghCfg = GH.cfg;
            let pulled = 0;
            for (const f of allToPull) {
                try {
                    const data = await fetch(
                        `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(f.ghPath)}?ref=${ghCfg.branch}`,
                        { headers: {
                            'Authorization': `token ${ghCfg.token}`,
                            'Accept': 'application/vnd.github.v3+json',
                        }}
                    ).then(r => r.json());

                    const content = decodeURIComponent(
                        escape(atob(data.content.replace(/\n/g, '')))
                    );

                    /* IDB 캐시 + allFiles 갱신 */
                    const idx = allFiles.findIndex(af => af.path === f.path);
                    const updated = {
                        name    : f.name,
                        ext     : f.ext,
                        folder  : f.folder,
                        path    : f.path,
                        content,
                        modified: Date.now(),
                    };
                    if (idx >= 0) allFiles[idx] = updated;
                    else          allFiles.push(updated);

                    /* IDB에 저장 */
                    const db = await (async () => new Promise((res, rej) => {
                        const r = indexedDB.open('mdpro-fm-v3', 1);
                        r.onsuccess = e => res(e.target.result);
                        r.onerror   = e => rej(e.target.error);
                    }))();
                    await new Promise((res, rej) => {
                        const r = db.transaction('files','readwrite')
                            .objectStore('files').put(updated, updated.path);
                        r.onsuccess = () => res();
                        r.onerror   = e => rej(e.target.error);
                    });

                    /* 이미 열린 탭에 갱신 알림 */
                    _notifyOpenTab(f.name.replace(/\.[^.]+$/, ''), content, f.path);

                    pulled++;
                } catch(e2) {
                    console.warn('pull failed for', f.path, e2);
                }
            }

            /* _baseSHAs 갱신 (기준점 이동) */
            files.forEach(f => {
                if (f.remoteSHA) _baseSHAs[f.ghPath] = f.remoteSHA;
            });
            await _saveBaseSHAs();

            filtered = allFiles;
            _render();
            _syncStatus('ok', `✓ ${pulled}개 pull 완료`);

        } catch(e) {
            console.error('FM.pullFromGitHub:', e);
            _syncStatus('err', `✗ ${e.message}`);
        } finally {
            _setBusy(false);
        }
    }

    /* pull 후 이미 열린 탭에 알림 */
    function _notifyOpenTab(title, newContent, filePath) {
        const tab = TM.getAll().find(t =>
            t.filePath === filePath || t.title === title);
        if (!tab) return;
        /* 탭에 갱신 뱃지 표시 */
        tab._updatedContent = newContent;
        const titleEl = document.querySelector(`.tab[data-id="${tab.id}"] .tab-title`);
        if (titleEl && !titleEl.querySelector('.tab-updated-badge')) {
            titleEl.insertAdjacentHTML('afterend',
                '<span class="tab-updated-badge" title="원격에서 갱신됨 — 클릭하여 적용">NEW</span>');
        }
        /* 현재 활성 탭이면 toast 알림 */
        if (TM.getActive() && TM.getActive().id === tab.id) {
            App._toast(`↓ "${title}" — 원격에서 갱신됨. 탭의 NEW 배지를 클릭하면 적용됩니다.`);
        }
    }

    /* ── PUSH: 로컬 캐시 → GitHub ────────────────────────
       안전 규칙:
         ① 원격에 변경이 있으면 push 차단 → pull 먼저
         ② 충돌이 있으면 push 차단 → pull 후 해결
         ③ 통과 시 local + new-local 파일만 push
         ④ push 완료 후 _baseSHAs 갱신                   */
    async function syncToGitHub() {
        if (!allFiles.length) {
            alert('먼저 로컬 폴더를 선택하고 파일을 불러오세요.');
            return;
        }
        if (!GH.isConnected()) {
            const go = confirm('GitHub 연결이 설정되지 않았습니다.\n설정 화면을 여시겠습니까?');
            if (go) { SB.switchTab('files'); SB.switchSource('github'); GH.showSettings(); }
            return;
        }

        _setBusy(true);
        _syncStatus('ing', '⟳ 원격 상태 확인 중…');

        try {
            await _loadBaseSHAs();
            const remoteSHAs = await GH.getRemoteSHAs();
            const { files, hasConflict, hasRemote } = await _classifyFiles(remoteSHAs);

            /* ① 원격 변경 / 충돌 차단 */
            if (hasConflict) {
                const names = files.filter(f => f.status === 'conflict')
                    .map(f => `  🔴 ${f.name}`).join('\n');
                _syncStatus('err', `✗ 충돌 ${files.filter(f=>f.status==='conflict').length}개 — pull 후 해결하세요`);
                alert(`Push 차단: 충돌 파일이 있습니다.\n${names}\n\n먼저 Pull을 실행하여 충돌을 해결하세요.`);
                _setBusy(false);
                return;
            }
            if (hasRemote) {
                const names = files.filter(f => f.status === 'remote' || f.status === 'new-remote')
                    .map(f => `  🔵 ${f.name}`).join('\n');
                _syncStatus('warn', `⚠ 원격 변경 있음 — pull 먼저 실행하세요`);
                alert(`Push 차단: 원격에서 변경된 파일이 있습니다.\n${names}\n\n먼저 Pull을 실행하여 최신 내용을 가져오세요.`);
                _setBusy(false);
                return;
            }

            /* ② push 대상: local + new-local 만 */
            const toPush = files.filter(f =>
                f.status === 'local' || f.status === 'new-local');

            if (!toPush.length) {
                _syncStatus('ok', '✓ 변경사항 없음 — GitHub와 동일합니다');
                _setBusy(false);
                return;
            }

            /* ③ 커밋 메시지 */
            const summary = toPush.length <= 3
                ? toPush.map(f => f.name).join(', ')
                : `${toPush.length}개 파일`;
            const msg = prompt(
                `Push할 파일 ${toPush.length}개:\n` +
                toPush.map(f => `  ${f.status === 'new-local' ? '➕' : '✏'} ${f.name}`).join('\n') +
                '\n\n커밋 메시지:',
                `Update ${summary}`
            );
            if (msg === null) { _setBusy(false); _syncStatus('', ''); return; }

            _syncStatus('ing', `⟳ ${toPush.length}개 파일 push 중…`);

            /* ④ Git Data API로 일괄 push */
            const result = await GH.pushLocalFiles(
                toPush.map(f => ({ path: f.ghPath, content: f.content })),
                msg || `Update ${summary}`
            );

            /* ⑤ _baseSHAs 갱신 */
            const newRemote = await GH.getRemoteSHAs();
            toPush.forEach(f => {
                if (newRemote[f.ghPath]) _baseSHAs[f.ghPath] = newRemote[f.ghPath];
            });
            await _saveBaseSHAs();

            _syncStatus('ok',
                `✓ ${result.pushed}개 push 완료  #${result.commitSha}`);
            App._toast(`✓ GitHub push 완료 — ${result.pushed}개 파일 (#${result.commitSha})`);
            _render();

        } catch(e) {
            console.error('FM.syncToGitHub:', e);
            _syncStatus('err', `✗ ${e.message}`);
        } finally {
            _setBusy(false);
        }
    }

    /* clone 완료 후 GH가 호출 → 원격 SHA를 기준점으로 설정 */
    function _setBaseSHAsFromRemote(remoteSHAs, basePath) {
        const base = basePath ? basePath.replace(/\/$/, '') + '/' : '';
        Object.keys(remoteSHAs).forEach(ghPath => {
            _baseSHAs[ghPath] = remoteSHAs[ghPath];
        });
        _saveBaseSHAs();
    }

    /* ── 특정 폴더에 파일 만들기 (폴더 그룹 헤더 + 클릭) ───── */
    async function createFileInFolder(folderPath) {
        _currentSubDir = folderPath === '/' ? null : folderPath;
        await createLocalFile();
        _currentSubDir = null;
    }

    /* ── 새 폴더 만들기 ─────────────────────────────────── */
    async function createFolder() {
        if (!dirHandle) { alert('먼저 폴더를 선택하세요.'); return; }

        /* 부모 폴더 선택 UI */
        const parentOptions = [{ label: '📁 (루트)', value: '' }];
        Object.keys(_subHandles).sort().forEach(p => {
            const depth = p.split('/').length - 1;
            parentOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center';
        const box = document.createElement('div');
        box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.5)';
        box.innerHTML = `
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                <span style="font-size:14px;font-weight:700;color:var(--txh)">📁 새 폴더 만들기</span>
                <button id="fm-ndir-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
            </div>
            <div style="margin-bottom:12px">
                <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">위치 (부모 폴더)</label>
                <select id="fm-ndir-parent" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer">
                    ${parentOptions.map(o => '<option value="' + o.value + '"' + (defaultParent !== undefined && o.value === defaultParent ? ' selected' : '') + '>' + o.label + '</option>').join('')}
                </select>
            </div>
            <div style="margin-bottom:16px">
                <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">폴더 이름</label>
                <input id="fm-ndir-name" type="text" value="새폴더"
                    style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box">
                <div id="fm-ndir-err" style="display:none;margin-top:5px;font-size:11px;color:#f76a6a">⚠ 폴더 이름에 앞뒤 공백이 있습니다. 공백을 제거해주세요.</div>
            </div>
            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="fm-ndir-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                <button id="fm-ndir-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 생성</button>
            </div>`;
        ov.appendChild(box);
        document.body.appendChild(ov);

        const nameInput = document.getElementById('fm-ndir-name');
        const parentSel = document.getElementById('fm-ndir-parent');
        setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);

        const result = await new Promise(resolve => {
            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('fm-ndir-close').onclick = () => close(null);
            document.getElementById('fm-ndir-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('fm-ndir-ok').onclick = () => {
                const raw = nameInput.value;
                const trimmed = raw.trim();
                const errEl = document.getElementById('fm-ndir-err');
                if (!trimmed) { nameInput.focus(); return; }
                if (raw !== trimmed) {
                    /* 앞뒤 공백 있음 → 에러 표시, 입력란 테두리 강조 */
                    errEl.style.display = 'block';
                    nameInput.style.borderColor = '#f76a6a';
                    nameInput.focus();
                    nameInput.setSelectionRange(0, raw.length);
                    return;
                }
                errEl.style.display = 'none';
                nameInput.style.borderColor = '';
                close({ parentVal: parentSel.value, name: trimmed });
            };
            nameInput.addEventListener('input', () => {
                /* 입력 중 에러 해소 시 실시간으로 숨김 */
                const errEl = document.getElementById('fm-ndir-err');
                if (nameInput.value === nameInput.value.trim()) {
                    errEl.style.display = 'none';
                    nameInput.style.borderColor = '';
                }
            });
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('fm-ndir-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });

        if (!result) return;

        const safe = result.name.replace(/[/\\:*?"<>|]/g, '_');
        const parentHandle = result.parentVal
            ? (_subHandles[result.parentVal] || dirHandle)
            : dirHandle;

        try {
            const perm = await dirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { alert('쓰기 권한이 거부되었습니다.'); return; }
            const newHandle = await parentHandle.getDirectoryHandle(safe, { create: true });
            const where = result.parentVal ? result.parentVal + '/' + safe : safe;
            /* 새 폴더 핸들 즉시 등록 + 빈 폴더로 표시 */
            _subHandles[where] = newHandle;
            _emptyFolders[where] = true;
            App._toast('📁 "' + where + '" 폴더 생성됨');
            _render();  /* 즉시 UI 반영 */
            /* 백그라운드로 전체 재스캔 */
            _subHandles = {};
            _emptyFolders = {};
            await _syncFromHandle();
        } catch(e) {
            if (e.name === 'NotAllowedError') {
                if (confirm('쓰기 권한이 필요합니다. 폴더를 다시 선택하시겠습니까?')) selectFolder();
            } else { alert('폴더 생성 실패: ' + e.message); }
        }
    }

    /* ── 현재 폴더에 새 파일 만들기 (폴더 선택 UI 포함) ── */
    async function createLocalFile() {
        if (!dirHandle) { alert('먼저 폴더를 선택하세요.'); return; }
        /* 선택 가능한 폴더 목록: 루트 + _subHandles의 모든 폴더 */
        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        Object.keys(_subHandles).sort().forEach(p => {
            const depth = p.split('/').length - 1;
            folderOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });
        /* 빈 폴더도 포함 */
        Object.keys(_emptyFolders).sort().forEach(p => {
            if (!_subHandles[p]) {
                const depth = p.split('/').length - 1;
                folderOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
            }
        });

        /* 폴더 선택 모달 표시 */
        const chosen = await _showNewFileModal(folderOptions);
        if (!chosen) return;  /* 취소 */

        const { folderVal, filename } = chosen;
        let fname = filename.trim();
        if (!fname) return;
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe = fname.replace(/[/\\:*?"<>|]/g, '_');

        const targetHandle = folderVal
            ? (_subHandles[folderVal] || await (async () => {
                /* _subHandles에 없으면 dirHandle에서 직접 경로 탐색 */
                try {
                    const parts = folderVal.split('/');
                    let h = dirHandle;
                    for (const p of parts) { h = await h.getDirectoryHandle(p); }
                    _subHandles[folderVal] = h;
                    return h;
                } catch(e2) { return null; }
            })())
            : dirHandle;
        if (!targetHandle) { alert('폴더 핸들을 찾을 수 없습니다. 새로고침 후 다시 시도하세요.'); return; }

        try {
            const perm = await dirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { alert('쓰기 권한이 거부되었습니다.'); return; }
            const fh = await targetHandle.getFileHandle(safe, { create: true });
            const wr = await fh.createWritable();
            await wr.write('');
            await wr.close();
            const where = folderVal ? folderVal + '/' + safe : safe;
            App._toast('📄 "' + where + '" 생성됨');
            const title = safe.replace(/\.[^.]+$/, '');
            const tab = TM.newTab(title, '', 'md');
            tab.filePath    = where;
            tab._fileHandle = fh;
            TM.markClean(tab.id);
            TM.renderTabs();
            _emptyFolders = {};
            _subHandles = {};
            await _syncFromHandle();
        } catch(e) {
            if (e.name === 'NotAllowedError') {
                if (confirm('쓰기 권한이 필요합니다. 폴더를 다시 선택하시겠습니까?')) selectFolder();
            } else { alert('파일 생성 실패: ' + e.message); }
        }
    }

    /* ── 새 파일 만들기 모달 (폴더 선택 + 파일명 입력) ─── */
    function _showNewFileModal(folderOptions) {
        return new Promise(resolve => {
            /* 기존 모달 제거 */
            const existing = document.getElementById('fm-newfile-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'fm-newfile-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:340px;max-width:460px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.5)';

            const selOptions = folderOptions.map(o =>
                `<option value="${o.value}">${o.label}</option>`
            ).join('');

            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📄 새 파일 만들기</span>
                    <button id="fm-nf-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">저장 폴더 선택</label>
                    <select id="fm-nf-folder" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer">
                        ${selOptions}
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">파일 이름 <span style="opacity:.6">(.md 자동 추가)</span></label>
                    <input id="fm-nf-name" type="text" value="Untitled"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box"
                        placeholder="파일명을 입력하세요">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="fm-nf-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="fm-nf-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 생성</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const nameInput = document.getElementById('fm-nf-name');
            const folderSel = document.getElementById('fm-nf-folder');
            setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);

            /* 현재 선택된 서브폴더가 있으면 기본값으로 */
            if (_currentSubDir) {
                const opt = [...folderSel.options].find(o => o.value === _currentSubDir);
                if (opt) folderSel.value = _currentSubDir;
            }

            const close = (result) => { ov.remove(); resolve(result); };

            document.getElementById('fm-nf-close').onclick = () => close(null);
            document.getElementById('fm-nf-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('fm-nf-ok').onclick = () => {
                const fn = nameInput.value.trim();
                if (!fn) { nameInput.focus(); return; }
                close({ folderVal: folderSel.value, filename: fn });
            };
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('fm-nf-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });
    }

    /* ── 로컬 파일 삭제 확인 & 실행 ────────────────────── */
    function confirmDelete(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._fmFile;
        if (!f) return;
        DelConfirm.show({
            name : f.name,
            path : f.path,
            type : 'local',
            onConfirm: async () => {
                try {
                    /* File System Access API: 부모 폴더 핸들에서 removeEntry */
                    const parentPath = (f.folder && f.folder !== '/') ? f.folder : '';

                    /* 1) 캐시에서 먼저 탐색
                       2) 없으면 dirHandle에서 경로 세그먼트를 따라 직접 탐색 (공백 포함 경로 대응) */
                    let parentHandle = parentPath ? _subHandles[parentPath] : dirHandle;
                    if (parentPath && !parentHandle) {
                        try {
                            let h = dirHandle;
                            for (const seg of parentPath.split('/')) {
                                h = await h.getDirectoryHandle(seg);
                            }
                            parentHandle = h;
                            _subHandles[parentPath] = h; /* 캐시 등록 */
                        } catch(e2) { parentHandle = null; }
                    }

                    if (!parentHandle) throw new Error('폴더 핸들 없음 — 폴더를 다시 선택해주세요');

                    /* 쓰기 권한 요청 */
                    const perm = await dirHandle.requestPermission({ mode: 'readwrite' });
                    if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

                    /* 실제 파일 삭제 */
                    await parentHandle.removeEntry(f.name);

                    /* IDB 캐시에서도 제거 */
                    await _idbDel('files', f.path);
                    allFiles = allFiles.filter(x => x.path !== f.path);
                    _applyFilters();

                    /* 열려 있는 탭이면 닫기 */
                    const tab = TM.getAll().find(t => t.filePath === f.path || t.title === f.name.replace(/\.[^.]+$/, ''));
                    if (tab) TM.closeTab(tab.id);

                    _render();
                    App._toast(`🗑 ${f.name} 삭제 완료`);
                } catch(e) {
                    alert('삭제 실패: ' + (e.message || e));
                }
            },
        });
    }

    /* ── 로컬 파일 → mdliveData(GitHub) Push ── */
    async function pushToGH(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._fmFile;
        if (!f) return;
        if (!GH.isConnected()) { alert('GitHub(mdliveData) 연결 설정이 필요합니다'); return; }

        /* f.content는 _scanDir에서 이미 로드됨 */
        const content = f.content;
        if (content === undefined || content === null) {
            alert('파일 내용을 불러올 수 없습니다. 폴더를 새로고침 후 다시 시도하세요.');
            return;
        }

        btn.textContent = '⟳'; btn.disabled = true;
        try {
            const ghCfg  = GH.cfg;
            const base   = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
            const path   = base + f.name;
            /* 기존 파일 SHA 조회 (없으면 신규 생성) */
            let sha = null;
            try {
                const info = await fetch(
                    `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(path)}?ref=${ghCfg.branch}`,
                    { headers: { 'Authorization': `token ${ghCfg.token}`, 'Accept': 'application/vnd.github.v3+json' } }
                ).then(r => r.ok ? r.json() : null);
                if (info?.sha) sha = info.sha;
            } catch(e) {}

            const b64  = btoa(unescape(encodeURIComponent(content)));
            const body = { message: `Upload: ${f.name}`, content: b64, branch: ghCfg.branch };
            if (sha) body.sha = sha;

            const res = await fetch(
                `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(path)}`,
                {
                    method : 'PUT',
                    headers: {
                        'Authorization': `token ${ghCfg.token}`,
                        'Accept': 'application/vnd.github.v3+json',
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(body),
                }
            );
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(`GitHub ${res.status}: ${err.message || res.statusText}`);
            }
            btn.textContent = '🐙'; btn.disabled = false;
            App._toast(`🐙 mdliveData Push 완료: ${f.name}`);
            GH._render();
        } catch(e) {
            btn.textContent = '🐙'; btn.disabled = false;
            alert('push 실패: ' + e.message);
        }
    }

    /* ── 로컬 파일 → md-viewer Push ── */
    async function pushToViewer(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._fmFile;
        if (!f) return;

        /* f.content는 _scanDir에서 이미 로드됨 */
        const content = f.content;
        if (content === undefined || content === null) {
            alert('파일 내용을 불러올 수 없습니다. 폴더를 새로고침 후 다시 시도하세요.');
            return;
        }

        btn.textContent = '⟳'; btn.disabled = true;
        try {
            btn.textContent = '📤'; btn.disabled = false;
            await PVShare.quickPush({ name: f.name, content });
        } catch(e) {
            btn.textContent = '📤'; btn.disabled = false;
            alert('push 실패: ' + e.message);
        }
    }

    /* ── 로컬 폴더 삭제 ────────────────────────────────── */
    async function confirmDeleteFolder(btn) {
        const folderPath = btn.dataset.path;
        const isEmpty    = btn.dataset.empty === 'true';
        if (!folderPath || !dirHandle) return;

        /* 폴더 핸들 확인 — 없으면 부모에서 재탐색 */
        let fHandle = _subHandles[folderPath];
        if (!fHandle) {
            /* 부모 핸들에서 직접 탐색 시도 */
            try {
                const parts2 = folderPath.split('/');
                const leafName = parts2.pop();
                const parentPath2 = parts2.join('/');
                const parentH = parentPath2 ? (_subHandles[parentPath2] || dirHandle) : dirHandle;
                if (parentH) fHandle = await parentH.getDirectoryHandle(leafName);
                if (fHandle) _subHandles[folderPath] = fHandle;
            } catch(e2) { /* silent */ }
        }
        if (!fHandle) {
            alert('폴더 핸들을 찾을 수 없습니다. 새로고침(↻) 후 다시 시도하세요.');
            return;
        }

        /* 확인 모달 */
        const filesInFolder = allFiles.filter(f =>
            f.folder === folderPath || f.path.startsWith(folderPath + '/')
        );
        const fileCount = filesInFolder.length;

        const confirmed = await _showFolderDeleteModal(folderPath, isEmpty, fileCount);
        if (!confirmed) return;

        try {
            const perm = await dirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

            /* 부모 핸들 찾기 */
            const parts = folderPath.split('/');
            const folderName = parts.pop();
            const parentPath = parts.join('/');
            const parentHandle = parentPath ? (_subHandles[parentPath] || dirHandle) : dirHandle;

            if (!parentHandle) throw new Error('부모 폴더 핸들 없음');

            /* 재귀 삭제 (recursive: true) — Chrome 91+ 지원 */
            await parentHandle.removeEntry(folderName, { recursive: true });

            /* 메모리·IDB에서 제거 */
            const removed = allFiles.filter(f =>
                f.folder === folderPath || f.path.startsWith(folderPath + '/')
            );
            for (const f of removed) {
                await _idbDel('files', f.path);
                /* 열려있는 탭도 닫기 */
                const tab = TM.getAll().find(t => t.filePath === f.path);
                if (tab) TM.closeTab(tab.id);
            }
            allFiles  = allFiles.filter(f => f.folder !== folderPath && !f.path.startsWith(folderPath + '/'));
            _applyFilters();
            delete _subHandles[folderPath];
            delete _emptyFolders[folderPath];

            App._toast(`🗑 "${folderPath}" 폴더 삭제 완료`);
            _render();
        } catch(e) {
            alert('폴더 삭제 실패: ' + (e.message || e));
        }
    }

    function _showFolderDeleteModal(folderPath, isEmpty, fileCount) {
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9100;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const folderName = folderPath.split('/').pop();
            const warnHtml = isEmpty
                ? `<div style="font-size:11px;color:#6af7b0;margin-top:6px">✅ 빈 폴더입니다. 안전하게 삭제됩니다.</div>`
                : `<div style="font-size:11px;color:#f7a06a;margin-top:6px;line-height:1.7">
                    ⚠ 이 폴더 안의 <b style="color:#ff8080">${fileCount}개 파일</b>이 모두 영구 삭제됩니다.<br>
                    삭제된 파일은 복구할 수 없습니다.
                   </div>`;

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:2px solid rgba(247,106,106,.4);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;gap:9px;margin-bottom:14px">
                    <span style="font-size:20px">🗑</span>
                    <span style="font-size:14px;font-weight:700;color:#f76a6a">폴더 삭제</span>
                </div>
                <div style="background:rgba(247,106,106,.08);border:1px solid rgba(247,106,106,.3);border-radius:8px;padding:12px 14px;margin-bottom:14px">
                    <div style="font-size:11px;color:var(--tx3);margin-bottom:4px">삭제할 폴더</div>
                    <div style="font-size:14px;font-weight:700;color:#f76a6a">${_esc(folderName)}</div>
                    <div style="font-size:10px;color:var(--tx3);font-family:var(--fm)">${_esc(folderPath)}</div>
                    ${warnHtml}
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="fdel-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="fdel-ok" style="padding:6px 18px;border-radius:6px;border:none;background:rgba(247,106,106,.2);border:1px solid rgba(247,106,106,.5);color:#f76a6a;font-size:12px;font-weight:700;cursor:pointer">🗑 삭제 확인</button>
                </div>`;
            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('fdel-cancel').onclick = () => close(false);
            ov.onclick = (e) => { if (e.target === ov) close(false); };
            document.getElementById('fdel-ok').onclick = () => close(true);
        });
    }

    /* ── 로컬 파일 이동 ────────────────────────────────── */
    async function moveFile(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._fmFile;
        if (!f) return;

        /* 이동 가능한 폴더 목록 (현재 폴더 제외) */
        const currentFolder = f.folder || '/';
        const folderOptions = [{ label: '📁 (루트)', value: '/' }];
        Object.keys(_subHandles).sort().forEach(p => {
            if (p !== currentFolder) {
                const depth = p.split('/').length - 1;
                folderOptions.push({
                    label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')',
                    value: p
                });
            }
        });
        Object.keys(_emptyFolders).sort().forEach(p => {
            if (p !== currentFolder && !_subHandles[p]) {
                const depth = p.split('/').length - 1;
                folderOptions.push({
                    label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')',
                    value: p
                });
            }
        });

        const destFolder = await _showMoveModal(f.name, folderOptions);
        if (destFolder === null) return;  /* 취소 */

        const destPath = destFolder === '/' ? f.name : destFolder + '/' + f.name;
        if (destPath === f.path) { App._toast('같은 폴더입니다'); return; }

        try {
            const perm = await dirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

            /* 원본 파일 읽기 */
            const srcParentPath = f.folder === '/' ? '' : f.folder;
            const srcParentHandle = srcParentPath ? (_subHandles[srcParentPath] || dirHandle) : dirHandle;
            const srcFileHandle = await srcParentHandle.getFileHandle(f.name);
            const srcFile = await srcFileHandle.getFile();
            const srcContent = await srcFile.text();

            /* 대상 폴더에 파일 쓰기 */
            const destFolderPath = destFolder === '/' ? '' : destFolder;
            const destHandle = destFolderPath ? (_subHandles[destFolderPath] || dirHandle) : dirHandle;
            const newFH = await destHandle.getFileHandle(f.name, { create: true });
            const wr = await newFH.createWritable();
            await wr.write(srcContent);
            await wr.close();

            /* 원본 삭제 */
            await srcParentHandle.removeEntry(f.name);

            /* 탭의 filePath 업데이트 */
            const tab = TM.getAll().find(t => t.filePath === f.path);
            if (tab) {
                tab.filePath = destPath;
                tab._fileHandle = newFH;
                TM.renderTabs();
            }

            /* IDB 갱신 */
            await _idbDel('files', f.path);
            _subHandles = {};
            _emptyFolders = {};
            await _syncFromHandle();
            App._toast(`✅ "${f.name}" → "${destFolder === '/' ? '루트' : destFolder}" 이동 완료`);
        } catch(e) {
            alert('파일 이동 실패: ' + (e.message || e));
        }
    }

    function _showMoveModal(fileName, folderOptions) {
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9100;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';
            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📦 파일 이동</span>
                    <button id="fmov-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="font-size:12px;color:var(--tx2);margin-bottom:12px;padding:8px 10px;background:var(--bg3);border-radius:6px">
                    📝 <b>${_esc(fileName)}</b>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">이동할 폴더 선택</label>
                    <select id="fmov-dest" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions.map(o => `<option value="${o.value}">${o.label}</option>`).join('')}
                    </select>
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="fmov-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="fmov-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 이동</button>
                </div>`;
            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('fmov-close').onclick = () => close(null);
            document.getElementById('fmov-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('fmov-ok').onclick = () => {
                close(document.getElementById('fmov-dest').value);
            };
        });
    }

    /* ── 로컬 폴더를 탐색기에서 열기 (FM 스코프) ──
       브라우저 정책으로 직접 열 수 없으면 모달로 주소 표시 + 자동 복사 */
    const FOPEN_SAVE_KEY = 'fm_custom_folder_path_';
    function openInExplorer() {
        if (!dirHandle) { App._toast('⚠ 폴더를 먼저 선택하세요'); return; }
        const defaultPath = folderName;
        const savedPath = localStorage.getItem(FOPEN_SAVE_KEY + defaultPath);
        const initialValue = (savedPath && savedPath.trim()) ? savedPath : defaultPath;
        const ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;inset:0;z-index:9100;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';
        ov.innerHTML = `
            <div style="background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:440px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📂 폴더 열기 안내</span>
                    <button id="fopen-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="font-size:11px;color:var(--tx3);margin-bottom:12px;line-height:1.6">
                    브라우저 보안 정책으로 해당 폴더를 직접 열 수 없습니다.<br>
                    아래 폴더 주소를 수정·저장하거나 복사하여 탐색기 주소창에 붙여넣으세요.
                </div>
                <input type="text" id="fopen-path" style="width:100%;box-sizing:border-box;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;padding:10px 12px;font-size:12px;font-family:monospace;color:var(--tx2);margin-bottom:14px;outline:none">
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="fopen-save" style="padding:6px 14px;border-radius:6px;border:1px solid rgba(88,200,248,.4);background:rgba(88,200,248,.15);color:#58c8f8;font-size:12px;cursor:pointer">💾 저장</button>
                    <button id="fopen-copy" style="padding:6px 14px;border-radius:6px;border:1px solid rgba(106,247,176,.4);background:rgba(106,247,176,.15);color:#6af7b0;font-size:12px;cursor:pointer">📋 복사</button>
                    <button id="fopen-ok" style="padding:6px 14px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">닫기</button>
                </div>
            </div>`;
        document.body.appendChild(ov);
        const pathInput = document.getElementById('fopen-path');
        if (pathInput) pathInput.value = initialValue;
        const getValue = () => (pathInput && pathInput.value) ? pathInput.value.trim() : defaultPath;
        const doCopy = () => {
            const val = getValue();
            navigator.clipboard.writeText(val).then(() => {
                App._toast('📋 폴더 주소가 복사되었습니다');
            }).catch(() => {
                const ta = document.createElement('textarea');
                ta.value = val;
                ta.style.cssText = 'position:fixed;left:-9999px';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                ta.remove();
                App._toast('📋 폴더 주소가 복사되었습니다');
            });
        };
        const doSave = () => {
            const val = getValue();
            if (val) {
                localStorage.setItem(FOPEN_SAVE_KEY + defaultPath, val);
                App._toast('💾 저장되었습니다');
            }
        };
        doCopy();  /* 창 열림과 동시에 자동 복사 */
        document.getElementById('fopen-close').onclick = () => ov.remove();
        document.getElementById('fopen-ok').onclick = () => ov.remove();
        document.getElementById('fopen-save').onclick = () => doSave();
        document.getElementById('fopen-copy').onclick = () => doCopy();
        ov.onclick = (e) => { if (e.target === ov) ov.remove(); };
    }

    return { restore, selectFolder, changeFolder, refresh, search, openInExplorer, toggleFoldAll, toggleShowHidden,
             syncToGitHub, pullFromGitHub, cloneFromGitHub, createFolder, createLocalFile, createFileInFolder,
             confirmDelete, confirmDeleteFolder, moveFile, pushToGH, pushToViewer,
             getFiles: () => allFiles,
             getFolderName: () => folderName,
             _setBaseSHAsFromRemote, _render };
})();


const CM = (() => {
    const KEY = 'mdpro_refs'; let refs = []; let sep = 'blank';// blank|line
    const MANUAL_REF_LOG_KEY = 'mdpro_manual_ref_log';

    function load() { try { refs = JSON.parse(localStorage.getItem(KEY) || '[]') } catch (e) { refs = [] } }
    function save() { try { localStorage.setItem(KEY, JSON.stringify(refs)) } catch (e) { } }
    function loadManual() { try { return JSON.parse(localStorage.getItem(MANUAL_REF_LOG_KEY) || '[]') } catch (e) { return [] } }
    function saveManual(arr) { try { localStorage.setItem(MANUAL_REF_LOG_KEY, JSON.stringify(arr)) } catch (e) { } }

    function setSep(s) {
        sep = s;
        el('sep-blank-btn').classList.toggle('active', s === 'blank');
        el('sep-line-btn').classList.toggle('active', s === 'line');
        const descs = { blank: '현재: 빈 줄로 구분 — 항목 사이에 빈 줄 하나를 넣어 구분하세요.', line: '현재: 엔터(줄바꿈)로 구분 — 각 줄이 하나의 참고문헌으로 처리됩니다.' };
        el('sep-desc').textContent = descs[s];
    }

    /* APA parser */
    function parseAPA(line) {
        line = line.trim(); if (!line || line.length < 10) return null;
        const ym = line.match(/\((\d{4}[a-z]?)\)/); const year = ym ? ym[1] : '?';
        let ap = ym ? line.substring(0, line.indexOf(ym[0])).trim().replace(/,\s*$/, '') : line.split('.')[0];
        const names = ap.split(/,\s*&\s*|;\s*|,\s*(?=[A-Z가-힣])/).map(s => s.trim().split(',')[0].trim()).filter(Boolean);
        let key = names.length === 1 ? `${names[0]}, ${year}` : names.length === 2 ? `${names[0]} & ${names[1]}, ${year}` : `${names[0]} et al., ${year}`;
        return { key, year, author: names[0] || 'Unknown', full: line, id: Date.now() + Math.random(), mla: '', chicago: '' };
    }

    function parse() {
        const raw = el('cite-raw').value; if (!raw.trim()) return;
        let lines;
        if (sep === 'blank') {
            // Split by one or more blank lines
            lines = raw.split(/\n[ \t]*\n+/).map(block =>
                block.split('\n').map(l => l.trim()).filter(Boolean).join(' ')
            ).map(l => l.replace(/^\d+[\.\)]\s*/, '')).filter(l => l.length > 10);
        } else {
            // Each non-empty line is one reference
            lines = raw.split('\n').map(l => l.replace(/^\d+[\.\)]\s*/, '').trim()).filter(l => l.length > 10);
        }
        let added = 0;
        lines.forEach(l => { const p = parseAPA(l); if (p && !refs.find(r => r.full === p.full)) { p.mla = toMLA(p); p.chicago = toChicago(p); refs.push(p); added++ } });
        save();
        el('cite-msg').textContent = added ? `✓ ${added}건 추가됨 (총 ${refs.length}건)` : lines.length ? '이미 존재하거나 파싱 실패' : '빈 줄이 없습니다 — 구분 방식을 확인하세요';
        setTimeout(() => el('cite-msg').textContent = '', 4000);
        renderLib(); renderList('');
    }

    function loadFile(ev) {
        const file = ev.target.files[0]; if (!file) return;
        const reader = new FileReader();
        reader.onload = e => { el('cite-raw').value = e.target.result; };
        reader.readAsText(file, 'utf-8');
        ev.target.value = '';
    }

    /* Style converters (heuristic) */
    function toMLA(ref) {
        // APA: Author, A. A., & Author, B. B. (Year). Title. Journal, Vol(No), pp. DOI
        const m = ref.full.match(/^(.+?)\.\s*\((\d{4}[a-z]?)\)\.\s*(.+?)\.\s*([^,]+),\s*(\d+)\((\d+)\),\s*([\d–\-]+)/);
        if (m) { const [, authors, year, title, journal, vol, no, pp] = m; return `${expandAuthors(authors)} "${capTitle(title.trim())}" ${journal}, vol. ${vol}, no. ${no}, ${year}, pp. ${pp}.` }
        // fallback — use ref.year (not local year which is out of scope here)
        const fy = ref.year || '?';
        const titlePart = ref.full.replace(/\(.*?\)\./, '').replace(/^[^.]+\.\s*/, '').trim();
        return `${ref.author}. "${titlePart}" ${fy}.`;
    }

    function toChicago(ref) {
        const m = ref.full.match(/^(.+?)\.\s*\((\d{4}[a-z]?)\)\.\s*(.+?)\.\s*([^,]+),\s*(\d+)\((\d+)\),\s*([\d–\-]+)/);
        if (m) { const [, authors, year, title, journal, vol, no, pp] = m; return `${expandAuthors(authors)} ${year}. "${capTitle(title.trim())}" ${journal} ${vol} (${no}): ${pp}.` }
        return `${ref.author}. ${ref.year}. "${ref.full}."`;
    }

    function toVancouver(ref) {
        const m = ref.full.match(/^(.+?)\.\s*\((\d{4}[a-z]?)\)\.\s*(.+?)\.\s*([^,]+),\s*(\d+)\((\d+)\),\s*([\d–\-]+)/);
        if (m) { const [, authors, year, title, journal, vol, no, pp] = m; const au = authors.split(/,\s*&\s*|;\s*/).map(s => s.trim()).join(', '); return `${au}. ${title.trim()}. ${journal}. ${year};${vol}(${no}):${pp}.` }
        return ref.full;
    }

    function expandAuthors(s) { return s.replace(/\s*&\s*/g, ', and ').replace(/,\s*et\s+al\./, 'et al.') }
    function capTitle(t) { return t.replace(/\b(\w)/g, (m, c, i) => i === 0 || '.:!?'.includes(t[i - 1]) ? c.toUpperCase() : m) }

    function convertByStyle(ref, style) {
        if (style === 'mla') return ref.mla || toMLA(ref);
        if (style === 'chicago') return ref.chicago || toChicago(ref);
        if (style === 'vancouver') return toVancouver(ref);
        return ref.full;// APA
    }

    function convertStyle() {
        const from = el('from-style').value, to = el('to-style').value;
        const raw = el('conv-input').value.trim();
        if (!raw) { el('conv-output').value = '입력 내용이 없습니다.'; return }
        const p = parseAPA(raw); if (!p) { el('conv-output').value = '파싱 실패 — APA 형식을 확인하세요.'; return }
        p.mla = toMLA(p); p.chicago = toChicago(p);
        el('conv-output').value = convertByStyle(p, to);
        const labels = { apa: 'APA 7', mla: 'MLA 9', chicago: 'Chicago (Author-Date)', vancouver: 'Vancouver' };
        el('conv-label').textContent = `→ ${labels[to]}`;
    }
    function copyConverted() { const v = el('conv-output').value; if (v) navigator.clipboard.writeText(v).then(() => { }).catch(() => { }) }
    function insertConverted() { const v = el('conv-output').value; if (!v) return; const ed = el('editor'), pos = ed.selectionEnd; ins(ed, pos, pos, '\n' + v + '\n'); App.hideModal('cite-modal') }

    /* List rendering */
    function renderList(q) {
        const area = el('cite-list-area');
        const flt = refs.filter(r => !q || r.full.toLowerCase().includes(q.toLowerCase()) || r.key.toLowerCase().includes(q.toLowerCase()));
        if (!flt.length) { area.innerHTML = '<div class="cite-empty">해당 문헌 없음. 추가 탭에서 먼저 입력하세요.</div>'; return }
        area.innerHTML = flt.map(r => `<div class="cite-entry" onclick="CM.toggle('cb_${r.id}')"><input type="checkbox" id="cb_${r.id}" data-id="${r.id}" onchange="CM.upd()" onclick="event.stopPropagation()"><div class="cite-body"><div class="cite-key">${r.key}</div><div class="cite-full" title="${r.full}">${r.full}</div></div></div>`).join('');
        upd();
    }

    function filter() { renderList(el('cite-search').value) }
    function toggle(id) { const cb = el(id); if (cb) { cb.checked = !cb.checked; upd() } }
    function getSel() { return Array.from(document.querySelectorAll('#cite-list-area input:checked')).map(cb => refs.find(r => String(r.id) === cb.dataset.id)).filter(Boolean) }
    function upd() {
        const n = getSel().length;
        el('cite-sc').textContent = `${n}개 선택됨`;
        el('cite-ins-btn').style.display = n > 0 ? '' : 'none';
    }
    function selAll() { document.querySelectorAll('#cite-list-area input[type=checkbox]').forEach(cb => cb.checked = true); upd() }
    function clrSel() { document.querySelectorAll('#cite-list-area input[type=checkbox]').forEach(cb => cb.checked = false); upd() }

    function _addToManualList(entries) {
        const manual = loadManual();
        const seen = new Set(manual.map(r => r.full));
        entries.forEach(r => {
            if (!seen.has(r.full)) {
                seen.add(r.full);
                manual.push({ ...r, id: r.id || Date.now() + Math.random() });
            }
        });
        saveManual(manual);
    }
    function insert() {
        const sel = getSel(); if (!sel.length) return;
        const style = el('cite-style').value; const ed = el('editor'); const pos = ed.selectionStart;
        let text = '';
        if (style === 'inline') text = '(' + sel.map(r => r.key).join('; ') + ')';
        else if (style === 'narrative') text = sel.map(r => `${r.author}(${r.year})`).join('; ');
        else if (style === 'multi') text = '(' + sel.map(r => `${r.author}, ${r.year}`).join('; ') + ')';
        else if (style === 'footnote') {
            let it = '', dt = '\n';
            sel.forEach((r, i) => { const n = Math.floor((ed.value.match(/\[\^\d+\]/g) || []).length / 2) + i + 1; it += `[^${n}]`; dt += `[^${n}]: ${r.full}\n` });
            ed.value = ed.value.substring(0, pos) + it + ed.value.substring(pos) + dt;
            _addToManualList(sel);
            App.render(); US.snap(); App.hideModal('cite-modal'); return;
        }
        ed.value = ed.value.substring(0, pos) + text + ed.value.substring(pos);
        ed.setSelectionRange(pos + text.length, pos + text.length);
        _addToManualList(sel);
        App.render(); US.snap(); App.hideModal('cite-modal');
    }

    function renderLib() {
        el('lib-cnt').textContent = refs.length;
        if (!refs.length) { el('lib-list').innerHTML = '<div class="cite-empty">저장된 참고문헌이 없습니다.</div>'; return }
        el('lib-list').innerHTML = refs.map((r, i) => `<div class="lib-item"><span class="lib-key">${r.key}</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px" title="${r.full}">${r.full}</span><span style="font-size:10px;color:var(--tx3);flex-shrink:0;margin:0 4px">${r.mla ? 'MLA✓' : ''}</span><button class="btn-ic" style="color:var(--er);font-size:12px;flex-shrink:0" onclick="CM.del(${i})">✕</button></div>`).join('');
    }

    function del(i) { refs.splice(i, 1); save(); renderLib(); renderList(el('cite-search')?.value || '') }
    function clearAll() { if (!confirm('모든 참고문헌을 삭제하시겠습니까?')) return; refs = []; save(); renderLib(); renderList('') }

    function insertRefSection() {
        const ed = el('editor'); const pos = ed.selectionEnd;
        const list = refs.map((r, i) => `${i + 1}. ${r.full}`).join('\n');
        const block = `\n\n<div class="ref-block">\n\n**참고문헌**\n\n${list}\n\n</div>\n`;
        ed.value = ed.value.substring(0, pos) + block + ed.value.substring(pos); App.render(); US.snap(); App.hideModal('cite-modal');
    }

    function downloadLibTxt() {
        let content = `# 참고문헌 목록 (${new Date().toLocaleDateString()})\n\n`;
        content += `## APA 7\n\n`; refs.forEach((r, i) => { content += `${i + 1}. ${r.full}\n` });
        content += `\n## MLA 9\n\n`; refs.forEach((r, i) => { content += `${i + 1}. ${r.mla || toMLA(r)}\n` });
        content += `\n## Chicago (Author-Date)\n\n`; refs.forEach((r, i) => { content += `${i + 1}. ${r.chicago || toChicago(r)}\n` });
        dlBlob(content, 'references.txt', 'text/plain;charset=utf-8');
    }

    /** APA 7 → Markdown (references.md): 학술지/볼륨 기울임, 문장형 대문자, en dash, DOI만, 빈 줄 구분 */
    function toAPA7MD(ref) {
        const line = (ref.full || '').replace(/\*/g, '').trim();
        const ym = line.match(/\((\d{4}[a-z]?)\)/);
        const year = ym ? ym[1] : '';
        const doiMatch = line.match(/(?:https:\/\/doi\.org\/|doi:)\s*([^\s.,]+)/i);
        const doi = doiMatch ? 'https://doi.org/' + doiMatch[1].replace(/^https:\/\/doi\.org\//i, '') : '';
        const beforeDoi = doi ? line.substring(0, line.search(/(?:https:\/\/doi\.org\/|doi:)/i)).trim() : line;
        const main = beforeDoi.replace(/\*/g, '').trim();
        const authorPart = main.substring(0, main.indexOf('(')).trim().replace(/\.\s*$/, '');
        const afterYear = main.substring(main.indexOf(')') + 1).trim();
        const titleMatch = afterYear.match(/^\.?\s*(.+?)\s*\.\s*(.+)$/);
        const title = titleMatch ? titleMatch[1].trim() : afterYear;
        const tail = titleMatch ? titleMatch[2].trim() : '';
        const journalMatch = tail.match(/^([^,]+),\s*(\d+)\s*\(\s*(\d+)\s*\)\s*,\s*(?:pp\.\s*)?([\d\s–\-]+)/);
        let journal = '', vol = '', issue = '', pages = '';
        if (journalMatch) {
            journal = journalMatch[1].trim();
            vol = journalMatch[2];
            issue = journalMatch[3];
            pages = journalMatch[4].replace(/\s*[-–]\s*/, '–').trim();
        } else {
            const simple = tail.match(/^([^,]+),\s*(\d+)\s*\(\s*(\d+)\s*\)/);
            if (simple) {
                journal = simple[1].trim();
                vol = simple[2];
                issue = simple[3];
            } else {
                journal = tail;
            }
        }
        const sentenceCase = (s) => {
            if (!s || /[가-힣]/.test(s)) return s;
            return s.toLowerCase().replace(/(^\s*\w|\.\s*\w|!\s*\w|\?\s*\w)/g, m => m.toUpperCase());
        };
        const outTitle = sentenceCase(title);
        const outJournal = journal ? `*${journal}*` : '';
        const outVol = vol ? `*${vol}*` : '';
        const outIssue = issue ? `(${issue})` : '';
        const pagePart = pages ? `, ${pages}` : '';
        const doiPart = doi ? `. ${doi}` : '';
        return `${authorPart}. (${year}). ${outTitle}. ${outJournal}${outJournal && (outVol || outIssue) ? ', ' : ''}${outVol}${outIssue}${pagePart}.${doiPart}`;
    }

    function downloadLibMd() {
        const sorted = [...refs].sort((a, b) => {
            const sa = (a.author || a.key || '').toLowerCase();
            const sb = (b.author || b.key || '').toLowerCase();
            return sa.localeCompare(sb);
        });
        const lines = sorted.map(r => toAPA7MD(r)).filter(Boolean);
        const content = '# References\n\n' + lines.join('\n\n') + '\n';
        dlBlob(content, 'references.md', 'text/markdown;charset=utf-8');
    }

    function loadLibFromMd() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.md,text/markdown,text/plain';
        input.onchange = (ev) => {
            const file = ev.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                const text = (e.target.result || '').trim();
                const blocks = text.split(/\n\s*\n+/).map(s => s.replace(/\*/g, '').trim()).filter(s => s.length > 10 && !/^#\s*References?\s*$/i.test(s));
                let added = 0;
                blocks.forEach(block => {
                    const p = parseAPA(block);
                    if (p && !refs.find(r => r.full === p.full)) {
                        p.mla = toMLA(p);
                        p.chicago = toChicago(p);
                        refs.push(p);
                        added++;
                    }
                });
                save();
                renderLib();
                renderList(el('cite-search')?.value || '');
                if (added > 0 && typeof App !== 'undefined' && App._toast) App._toast(`✓ ${added}건 불러옴 (총 ${refs.length}건)`);
            };
            reader.readAsText(file, 'utf-8');
            input.value = '';
        };
        input.click();
    }

    function downloadLib() {
        downloadLibTxt();
    }

    function openLibInNewWindow() {
        if (!refs.length) {
            if (typeof App !== 'undefined' && App._toast) App._toast('저장된 참고문헌이 없습니다.');
            return;
        }
        const sorted = [...refs].sort((a, b) => {
            const sa = (a.author || a.key || '').toLowerCase();
            const sb = (b.author || b.key || '').toLowerCase();
            return sa.localeCompare(sb);
        });
        const lines = sorted.map(r => toAPA7MD(r)).filter(Boolean);
        const md = '# References\n\n' + lines.join('\n\n') + '\n';
        let html;
        try {
            html = typeof mdRender === 'function' ? mdRender(md, true) : (typeof marked !== 'undefined' ? marked.parse(md) : md.replace(/\n/g, '<br>'));
        } catch (e) {
            html = '<p style="color:var(--er)">' + (e.message || '렌더 오류') + '</p>';
        }
        html = (html || '').replace(/<\/script>/gi, '<\\/script>');
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        const w = window.open('', '_blank', 'width=800,height=700,scrollbars=yes,resizable=yes');
        if (!w) {
            alert('팝업이 차단되었을 수 있습니다.');
            return;
        }
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>참고문헌 목록</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;background:var(--bg3);flex-wrap:wrap">' +
            '<button type="button" onclick="var p=document.getElementById(\'lib-pv-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.min(24,s+2)+\'px\';var L=document.getElementById(\'lib-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx);font-size:12px">확대</button>' +
            '<button type="button" onclick="var p=document.getElementById(\'lib-pv-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.max(10,s-2)+\'px\';var L=document.getElementById(\'lib-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx);font-size:12px">축소</button>' +
            '<span id="lib-zoom-label" style="font-size:11px;color:var(--tx3);min-width:40px">100%</span>' +
            '<button type="button" onclick="var ta=document.getElementById(\'lib-pv-md-src\');if(ta){navigator.clipboard.writeText(ta.value).then(function(){var t=document.getElementById(\'lib-copy-msg\');if(t){t.textContent=\'✓ 양식 포함 복사됨\';setTimeout(function(){t.textContent=\'\';},2000)}})}" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx);font-size:12px">양식포함복사</button>' +
            '<span id="lib-copy-msg" style="font-size:11px;color:var(--ok)"></span>' +
            '</div>' +
            '<textarea id="lib-pv-md-src" style="display:none"></textarea>' +
            '<div id="lib-pv-content" style="flex:1;min-height:0;overflow:auto;padding:20px;font-size:13px;line-height:1.7">' +
            '<div class="preview-page" style="max-width:720px;margin:0 auto">' + html + '</div></div></body></html>'
        );
        w.document.close();
        const ta = w.document.getElementById('lib-pv-md-src');
        if (ta) ta.value = md;
    }

    function renderManualList() {
        const manual = loadManual();
        const cntEl = document.getElementById('manual-cnt');
        const listEl = document.getElementById('manual-ref-log');
        if (!listEl) return;
        if (cntEl) cntEl.textContent = manual.length;
        if (!manual.length) { listEl.innerHTML = '<div class="cite-empty">인용 삽입 시 선택된 항목이 여기에 추가됩니다.</div>'; return; }
        listEl.innerHTML = manual.map((r, i) => `<div class="lib-item"><span class="lib-key">${r.key}</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px" title="${r.full}">${r.full}</span><span style="font-size:10px;color:var(--tx3);flex-shrink:0;margin:0 4px">${r.mla ? 'MLA✓' : ''}</span><button class="btn-ic" style="color:var(--er);font-size:12px;flex-shrink:0" onclick="CM.delManual(${i})">✕</button></div>`).join('');
    }
    function delManual(i) { const m = loadManual(); m.splice(i, 1); saveManual(m); renderManualList(); }
    function clearManual() { if (!confirm('수동참고문헌 목록을 모두 삭제하시겠습니까?')) return; saveManual([]); renderManualList(); }
    function insertRefSectionFromManual() {
        const manual = loadManual(); if (!manual.length) { App._toast('수동참고문헌이 없습니다.'); return; }
        const ed = el('editor'); const pos = ed.selectionEnd;
        const list = manual.map((r, i) => `${i + 1}. ${r.full}`).join('\n');
        const block = `\n\n<div class="ref-block">\n\n**참고문헌**\n\n${list}\n\n</div>\n`;
        ed.value = ed.value.substring(0, pos) + block + ed.value.substring(pos); App.render(); US.snap(); App.hideModal('cite-modal');
    }
    function downloadManual() {
        const manual = loadManual(); if (!manual.length) { App._toast('수동참고문헌이 없습니다.'); return; }
        let content = `# 수동참고문헌 목록 (${new Date().toLocaleDateString()})\n\n`;
        content += `## APA 7\n\n`; manual.forEach((r, i) => { content += `${i + 1}. ${r.full}\n` });
        content += `\n## MLA 9\n\n`; manual.forEach((r, i) => { content += `${i + 1}. ${r.mla || toMLA(r)}\n` });
        content += `\n## Chicago (Author-Date)\n\n`; manual.forEach((r, i) => { content += `${i + 1}. ${r.chicago || toChicago(r)}\n` });
        dlBlob(content, 'manual-references.txt', 'text/plain;charset=utf-8');
    }
    function tab(name) {
        const names = ['add', 'cite', 'convert', 'lib', 'manual', 'search', 'ai-search'];
        document.querySelectorAll('#cite-modal .tr-tab').forEach(t => t.classList.toggle('active', t.getAttribute('data-tab') === name));
        names.forEach(n => { const p = el(`cp-${n}`); if (p) p.classList.toggle('active', n === name); });
        const footer = document.getElementById('cite-ai-search-footer');
        const insBtn = el('cite-ins-btn');
        if (name === 'ai-search') {
            if (footer) footer.style.display = 'flex';
            if (insBtn) insBtn.style.display = 'none';
            if (typeof DeepResearch !== 'undefined') DeepResearch.applyCiteAiSearchPreset();
            setTimeout(() => { el('cite-ai-prompt')?.focus(); if (typeof CiteAiSearchHistory !== 'undefined') CiteAiSearchHistory.renderList(); }, 80);
        } else {
            if (footer) footer.style.display = 'none';
            if (insBtn) insBtn.style.display = '';
        }
        if (name === 'cite') { renderList(el('cite-search')?.value || ''); if (insBtn) insBtn.style.display = 'none'; }
        if (name === 'lib') renderLib();
        if (name === 'manual') renderManualList();
        if (name === 'search') { RefSearch.syncAiPromptVisibility(); setTimeout(() => el('ref-q')?.focus(), 80); }
    }

    // RefSearch 에서 단일 APA 문자열을 직접 추가하는 공개 메서드
    function addRaw(apaStr) {
        apaStr = apaStr.trim(); if (!apaStr) return;
        const p = parseAPA(apaStr);
        if (p && !refs.find(r => r.full === p.full)) { p.mla = toMLA(p); p.chicago = toChicago(p); refs.push(p); save(); renderLib(); }
    }

    function open() { load(); renderList(''); renderLib(); el('cite-ins-btn').style.display = 'none' }

    return { load, setSep, parse, loadFile, filter, toggle, getSel, upd, selAll, clrSel, insert, del, clearAll, insertRefSection, downloadLib, downloadLibTxt, downloadLibMd, loadLibFromMd, openLibInNewWindow, renderManualList, delManual, clearManual, insertRefSectionFromManual, downloadManual, convertStyle, copyConverted, insertConverted, tab, open, addRaw };
})();

/* 참고문헌 모달 최대화 (앱 내 전체화면) */
const CiteModal = {
    toggleMaximize() {
        const box = document.getElementById('cite-modal-box');
        const btn = document.getElementById('cite-modal-maximize-btn');
        if (!box) return;
        const on = box.classList.toggle('cite-modal-maximized');
        if (btn) { btn.title = on ? '원래 크기' : '최대화'; btn.textContent = on ? '⤢' : '⛶'; }
    }
};

/* ═══════════════════════════════════════════════════════════
   CiteAISearch — cite-modal 전용 AI 참고문헌 검색 (Gemini)
═══════════════════════════════════════════════════════════ */
const CiteAISearch = (() => {
    async function callGemini(prompt) {
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) throw new Error('AI API 키를 설정에서 입력·저장해 주세요.');
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${encodeURIComponent(key)}`;
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { temperature: 0.3, maxOutputTokens: 4096 }
            }),
            signal: AbortSignal.timeout(60000)
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            throw new Error(err.error?.message || `HTTP ${r.status}`);
        }
        const d = await r.json();
        const parts = d.candidates?.[0]?.content?.parts || [];
        return parts.map(p => (p.text || '').trim()).filter(Boolean).join('\n').trim();
    }

    function run() {
        const inp = document.getElementById('cite-ai-prompt');
        const status = document.getElementById('cite-ai-status');
        const resultBox = document.getElementById('cite-ai-result');
        const placeholder = document.getElementById('cite-ai-placeholder');
        if (!inp || !resultBox) return;
        const q = (inp.value || '').trim();
        if (!q) {
            if (status) status.textContent = '검색할 주제를 입력하세요.';
            return;
        }
        const prompt = `List 5 to 10 academic references in APA 7 format for the following topic. Output only the reference list, one reference per line. No numbering, no extra explanation.\n\nTopic: ${q}`;
        if (status) status.textContent = '🔄 AI 검색 중...';
        if (placeholder) placeholder.style.display = 'none';
        resultBox.innerHTML = '<div class="cite-empty" style="padding:16px">⏳ 생성 중...</div>';
        callGemini(prompt).then(text => {
            const lines = text.split(/\n/).map(s => s.trim()).filter(s => s.length > 5);
            if (status) status.textContent = lines.length ? `✅ ${lines.length}건 제안` : '제안된 참고문헌이 없습니다.';
            if (lines.length === 0) {
                resultBox.innerHTML = '<div class="cite-empty" id="cite-ai-placeholder">제안된 참고문헌이 없습니다. 프롬프트를 바꿔 다시 시도하세요.</div>';
                return;
            }
            resultBox.innerHTML = lines.map((line, i) => {
                const escaped = line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
                return `<div class="ref-card" style="margin-bottom:8px">
  <div class="ref-card-apa" style="font-size:12px">${escaped}</div>
  <div class="ref-card-btns" style="margin-top:4px">
    <button type="button" class="btn btn-p btn-sm" onclick="CiteAISearch.addLine(${i})">+ 참고문헌에 추가</button>
  </div>
</div>`;
            }).join('');
            resultBox._lines = lines;
        }).catch(e => {
            if (status) status.textContent = `❌ ${e.message}`;
            resultBox.innerHTML = `<div class="cite-empty" id="cite-ai-placeholder">오류: ${e.message}</div>`;
        });
    }

    function addLine(i) {
        const box = document.getElementById('cite-ai-result');
        const line = box._lines?.[i];
        if (!line || typeof CM === 'undefined') return;
        CM.addRaw(line);
        const btns = box.querySelectorAll('.ref-card')[i]?.querySelectorAll('button');
        if (btns?.[0]) { btns[0].textContent = '✔ 추가됨'; btns[0].disabled = true; btns[0].style.opacity = '.6'; }
    }

    return { run, addLine };
})();

/* AI 검색 결과 히스토리 — Deep Research AI 검색 결과 저장, cite-modal에서 목록 표시 */
const CiteAiSearchHistory = (() => {
    const STORAGE_KEY = 'mdpro_cite_ai_search_history';
    const LIST_EL_ID = 'cite-ai-history-list';

    function getList() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch (e) { return []; }
    }
    function setList(arr) {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(arr)); } catch (e) {}
    }
    function saveCurrent() {
        const out = document.getElementById('dr-output');
        const q = document.getElementById('dr-ai-prompt');
        if (!out) return;
        const result = (out.value || '').trim();
        if (!result) return;
        const title = (q && q.value) ? q.value.trim().slice(0, 50) : ('AI검색 ' + new Date().toLocaleString('ko-KR'));
        const list = getList();
        const item = { id: 'aih-' + Date.now(), title, result, createdAt: Date.now() };
        list.unshift(item);
        setList(list.slice(0, 100));
        renderList();
    }
    function saveCurrentFromCiteModal() {
        const out = document.getElementById('cite-ai-out');
        const q = document.getElementById('cite-ai-prompt');
        if (!out) return;
        const result = (out.value || '').trim();
        if (!result) return;
        const title = (q && q.value) ? q.value.trim().slice(0, 50) : ('AI검색 ' + new Date().toLocaleString('ko-KR'));
        const list = getList();
        const item = { id: 'aih-' + Date.now(), title, result, createdAt: Date.now() };
        list.unshift(item);
        setList(list.slice(0, 100));
        renderList();
    }
    function loadItem(id) {
        const list = getList();
        const item = list.find(x => x.id === id);
        if (!item) return;
        const citeModal = document.getElementById('cite-modal');
        const cpAiSearch = document.getElementById('cp-ai-search');
        const isCiteAiSearchActive = citeModal && citeModal.classList.contains('vis') && cpAiSearch && cpAiSearch.classList.contains('active');
        if (isCiteAiSearchActive) {
            const out = document.getElementById('cite-ai-out');
            if (out) out.value = item.result;
            return;
        }
        if (typeof DeepResearch !== 'undefined') {
            DeepResearch.show();
            DeepResearch.switchTab('ai-search');
            const out = document.getElementById('dr-output');
            if (out) out.value = item.result;
        }
    }
    function deleteItem(id) {
        setList(getList().filter(x => x.id !== id));
        renderList();
    }
    function clearAll() {
        setList([]);
        renderList();
    }
    function renderList() {
        const el = document.getElementById(LIST_EL_ID);
        if (!el) return;
        const list = getList();
        if (!list.length) {
            el.innerHTML = '<div class="cite-empty" style="font-size:11px;color:var(--tx3);padding:12px">' + (el.getAttribute('data-empty') || '저장된 항목이 없습니다.') + '</div>';
            return;
        }
        el.innerHTML = list.map(item => {
            const d = new Date(item.createdAt);
            const dateStr = d.toLocaleDateString('ko-KR') + ' ' + d.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' });
            const titleEsc = (item.title || '제목 없음').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return '<div class="ref-card" style="margin-bottom:6px;padding:6px 8px;"><div style="font-size:11px;color:var(--tx);margin-bottom:4px">' + titleEsc + '</div><div style="font-size:10px;color:var(--tx3);margin-bottom:4px">' + dateStr + '</div><div style="display:flex;gap:4px"><button type="button" class="btn btn-p btn-sm" style="font-size:10px" onclick="CiteAiSearchHistory.loadItem(\'' + item.id + '\')">불러오기</button><button type="button" class="btn btn-g btn-sm" style="font-size:10px" onclick="CiteAiSearchHistory.deleteItem(\'' + item.id + '\')">삭제</button></div></div>';
        }).join('');
    }
    return { getList, saveCurrent, saveCurrentFromCiteModal, loadItem, deleteItem, clearAll, renderList };
})();

/* ═══════════════════════════════════════════════════════════
   CAPTION MANAGER
═══════════════════════════════════════════════════════════ */
const CAP = (() => {
    let type = 'table'; let selOpt = 0;

    const tableOpts = [
        { label: '&lt;표 N&gt;', template: (n, d) => `<표${n}> ${d}` },
        { label: '표 N.', template: (n, d) => `표 ${n}. ${d}` },
        { label: '&lt;Table N&gt;', template: (n, d) => `<Table ${n}> ${d}` },
        { label: 'Table N.', template: (n, d) => `Table ${n}. ${d}` },
    ];
    const figOpts = [
        { label: '[그림 N]', template: (n, d) => `[그림 ${n}] ${d}` },
        { label: '그림 N.', template: (n, d) => `그림 ${n}. ${d}` },
        { label: '[Fig N]', template: (n, d) => `[Fig ${n}] ${d}` },
        { label: 'Fig N.', template: (n, d) => `Fig ${n}. ${d}` },
        { label: '[Figure N]', template: (n, d) => `[Figure ${n}] ${d}` },
        { label: 'Figure N.', template: (n, d) => `Figure ${n}. ${d}` },
    ];

    function show(t) {
        type = t; selOpt = 0;
        el('cap-title').textContent = t === 'table' ? '표 캡션 삽입' : '그림 캡션 삽입';
        const opts = t === 'table' ? tableOpts : figOpts;
        el('cap-opts').innerHTML = opts.map((o, i) => `<span class="cap-opt${i === 0 ? ' sel' : ''}" onclick="CAP.selOpt(${i})">${o.label}</span>`).join('');
        el('cap-num').value = '1'; el('cap-desc').value = '';
        updatePreview();
        el('caption-modal').classList.add('vis');
    }

    function selOptFn(i) {
        selOpt = i;
        document.querySelectorAll('#cap-opts .cap-opt').forEach((o, j) => o.classList.toggle('sel', j === i));
        updatePreview();
    }

    function updatePreview() {
        const opts = type === 'table' ? tableOpts : figOpts;
        const n = el('cap-num').value || '1';
        const d = el('cap-desc').value || '(캡션 내용)';
        el('cap-preview').textContent = opts[selOpt].template(n, d);
    }

    function insert() {
        const opts = type === 'table' ? tableOpts : figOpts;
        const n = el('cap-num').value || '1';
        const d = el('cap-desc').value || '내용';
        const caption = opts[selOpt].template(n, d);
        const ed = el('editor'); const pos = ed.selectionEnd;
        const cssClass = type === 'table' ? 'tbl-caption' : 'fig-caption';
        const md = `\n<span class="${cssClass}">${caption}</span>\n`;
        ins(ed, pos, pos, md);
        App.hideModal('caption-modal');
    }

    return { show, selOpt: selOptFn, updatePreview, insert };
})();

/* ═══════════════════════════════════════════════════════════
   PAPER TEMPLATES
═══════════════════════════════════════════════════════════ */
const TMPLS = [
    {
        name: '학위논문 (사회과학·교육학·심리학)', icon: '🎓', desc: '국문초록, Abstract, 6장 구조', content: `# 논문 제목

---

## 국문초록

핵심어: 

---

## Abstract

Keywords: 

---

## 목차

---

## 표 목차

---

## 그림 목차

---

# 제1장 서론

## 1. 연구의 필요성

## 2. 연구 목적

## 3. 연구 문제

1. 
2. 

## 4. 연구 가설

## 5. 용어의 정의

## 6. 연구의 제한점

<div class="page-break"></div>

# 제2장 이론적 배경

## 1. 핵심 이론

## 2. 선행연구 고찰

## 3. 연구모형 설정

<div class="page-break"></div>

# 제3장 연구방법

## 1. 연구대상

## 2. 연구도구

## 3. 자료수집 절차

## 4. 분석방법

## 5. 연구모형 분석전략

<div class="page-break"></div>

# 제4장 연구결과

## 1. 기술통계

## 2. 측정모형 검증

## 3. 구조모형 분석

## 4. 추가 분석

<div class="page-break"></div>

# 제5장 논의

## 1. 결과 해석

## 2. 이론적 시사점

## 3. 실천적 시사점

<div class="page-break"></div>

# 제6장 결론

## 1. 연구 요약

## 2. 정책적 제언

## 3. 후속연구 제안

<div class="page-break"></div>

# 참고문헌

<div class="ref-block">

</div>

---

# 부록
`},
    {
        name: 'SSCI / KCI 학술지', icon: '📰', desc: '국제학술지 표준 IMRaD 구조', content: `# 논문 제목

**Authors:** 

**Journal:** 

**Received:** | **Accepted:** | **Published:** 

---

## Abstract

**Keywords:** 

---

# 1. Introduction

## 1.1 Background

## 1.2 Research Gap

## 1.3 Research Purpose

<div class="page-break"></div>

# 2. Literature Review

<div class="page-break"></div>

# 3. Theoretical Framework and Hypotheses

**H1:** 

**H2:** 

<div class="page-break"></div>

# 4. Method

## 4.1 Participants

## 4.2 Measures

## 4.3 Procedure

## 4.4 Data Analysis

<div class="page-break"></div>

# 5. Results

<div class="page-break"></div>

# 6. Discussion

## 6.1 Theoretical Implications

## 6.2 Practical Implications

## 6.3 Limitations and Future Research

<div class="page-break"></div>

# 7. Conclusion

<div class="page-break"></div>

# References

<div class="ref-block">

</div>
`},
    {
        name: '단일 연구 논문 (실증)', icon: '🔬', desc: '서론-방법-결과-논의 4단 구조', content: `# 논문 제목

**저자:** 

---

## 요약

**주요어:** 

---

# 1. 서론

<div class="page-break"></div>

# 2. 이론적 배경 및 가설 설정

## 2.1 이론적 배경

## 2.2 연구 가설

**가설 1:** 

**가설 2:** 

<div class="page-break"></div>

# 3. 연구방법

## 3.1 연구대상

## 3.2 측정도구

## 3.3 분석방법

<div class="page-break"></div>

# 4. 연구결과

## 4.1 기술통계

## 4.2 가설 검증

<div class="page-break"></div>

# 5. 논의 및 결론

## 5.1 논의

## 5.2 결론

## 5.3 연구의 한계

# 참고문헌

<div class="ref-block">

</div>
`},
    {
        name: '다중 연구 (Study 1 / Study 2)', icon: '📊', desc: '복수 연구 포함 실증 논문 구조', content: `# 논문 제목

**Authors:** 

---

## Abstract

**Keywords:** 

---

# 1. Introduction

<div class="page-break"></div>

# 2. Study 1

## 2.1 Method

### 2.1.1 Participants

### 2.1.2 Measures

### 2.1.3 Procedure

## 2.2 Results

## 2.3 Discussion

<div class="page-break"></div>

# 3. Study 2

## 3.1 Method

### 3.1.1 Participants

### 3.1.2 Measures

### 3.1.3 Procedure

## 3.2 Results

## 3.3 Discussion

<div class="page-break"></div>

# 4. General Discussion

## 4.1 Theoretical Contributions

## 4.2 Practical Implications

## 4.3 Limitations and Future Research

# References

<div class="ref-block">

</div>
`},
    {
        name: '메타분석 논문', icon: '📈', desc: '체계적 문헌 검토 및 메타분석', content: `# 논문 제목: A Meta-Analysis

**Authors:** 

---

## Abstract

**Keywords:** 

---

# 1. Introduction

## 1.1 Theoretical Background

## 1.2 Purpose of Meta-Analysis

<div class="page-break"></div>

# 2. Literature Search Strategy

## 2.1 Search Databases

## 2.2 Search Keywords

## 2.3 Search Period

<div class="page-break"></div>

# 3. Inclusion Criteria

## 3.1 Inclusion Criteria

## 3.2 Exclusion Criteria

## 3.3 PRISMA Flow Diagram

<div class="page-break"></div>

# 4. Coding Procedure

## 4.1 Variables Coded

## 4.2 Coder Agreement

<div class="page-break"></div>

# 5. Statistical Analysis

## 5.1 Effect Size Calculation

## 5.2 Heterogeneity Test

## 5.3 Moderator Analysis

<div class="page-break"></div>

# 6. Results

## 6.1 Overall Effect Size

## 6.2 Moderator Effects

<div class="page-break"></div>

# 7. Publication Bias Test

## 7.1 Funnel Plot

## 7.2 Egger's Test

<div class="page-break"></div>

# 8. Discussion

## 8.1 Interpretation of Effect Sizes

## 8.2 Practical Implications

## 8.3 Limitations

# References

<div class="ref-block">

</div>

---

# Appendix

## Appendix A: List of Included Studies
`},
];

/* ═══════════════════════════════════════════════════════════
   ACADEMIC SEARCH (Google Scholar, RISS, KCI, DBpia, IEEE 등)
═══════════════════════════════════════════════════════════ */
const Scholar = (() => {
    const RK = 'mdpro_scholar_recent';
    let recent = [];
    let currentTab = 'google';

    const APA_GUIDE_MD = `# 📘 APA 7판 참고문헌 작성 가이드 (학술연구자용 정리본)

본 문서는 학술논문 작성 시 참고문헌을 **APA 7판(American Psychological Association, 7th ed.)** 기준에 따라 정확하게 작성하기 위한 규칙을 정리한 연구자용 가이드이다.
한국어 논문과 영어 논문이 혼재된 경우에도 동일한 원칙이 적용되며, 언어에 따른 세부 차이만 존재한다.

---

# 1️⃣ APA 7판의 기본 원칙

APA 7판 참고문헌 작성의 핵심 원칙은 다음과 같다.

1. 모든 참고문헌은 저자 성 기준 알파벳순으로 배열한다.
2. 한글 논문과 영문 논문을 구분하지 않고 동일한 규칙을 적용한다.
3. 학술지명과 권(volume)은 반드시 이탤릭체로 표기한다.
4. 논문 제목은 문장형(sentence case)으로 작성한다.
5. DOI가 있는 경우 반드시 https://doi.org/ 형식으로 표기한다.
6. 각 참고문헌 사이에는 한 줄 공백을 둔다.

---

# 2️⃣ 학술지 논문의 기본 형식

## 🔹 기본 구조

저자. (연도). 논문 제목. *학술지명, 권*(호), 페이지. DOI

---

# 3️⃣ 저자 표기 규칙

## ① 한국어 저자

- 성과 이름을 그대로 작성한다.
- 이니셜로 변환하지 않는다.
- 쉼표로 저자를 구분한다.

예시
전희원, 김영화.

---

## ② 영어 저자

- 성, 이름 이니셜 순으로 표기한다.
- 이름은 이니셜로 축약한다.
- 저자가 20명 이하이면 모두 표기한다.
- 21명 이상이면 19명까지 표기 후 … 마지막 저자를 표기한다.

예시
Henrich, W. L., Smith, J. A., & Brown, R. T.

---

# 4️⃣ 연도 표기

- 반드시 괄호 안에 작성한다.
- 괄호 뒤에는 마침표를 찍는다.

형식
(2007).

---

# 5️⃣ 논문 제목 작성 규칙

## ① 한국어 논문 제목

- 원문 그대로 작성한다.
- 따옴표를 사용하지 않는다.
- 별도 대소문자 변경을 하지 않는다.

## ② 영어 논문 제목

- 문장형(sentence case) 적용
- 첫 단어와 고유명사만 대문자로 작성한다.
- 나머지는 소문자로 작성한다.

예시
Analgesics and the kidney: Summary and recommendations to the scientific advisory board of the National Kidney Foundation.

---

# 6️⃣ 학술지명 및 권·호 표기

## 🔹 이탤릭 적용 대상

- 학술지명
- 권(volume)

## 🔹 일반체 유지

- 호(issue)
- 페이지

예시
*American Journal of Kidney Diseases, 27*(1), 162–165.

또는

*관광연구, 22*(2), 285–307.

---

# 7️⃣ 페이지 표기

- 시작 페이지와 끝 페이지 사이에는 en dash(–) 사용
- 하이픈(-)이 아니라 en dash 사용

예시
285–307.

---

# 8️⃣ DOI 표기

- 반드시 URL 형식 사용
- doi: 또는 DOI: 사용하지 않음
- http:// 대신 https:// 사용

형식
https://doi.org/10.xxxxx

---

# 9️⃣ 한국어 논문과 영어 논문의 차이 요약

| 구분 | 한국어 논문 | 영어 논문 |
|------|-------------|-----------|
| 저자명 | 한글 원형 유지 | 성 + 이니셜 |
| 제목 | 원문 유지 | sentence case |
| 학술지명 | 원문 유지 | Title Case |
| 이탤릭 | 적용 | 적용 |
| DOI | 동일 | 동일 |

---

# 🔟 예시 정리

전희원, 김영화. (2007). 호텔종사원의 집단응집력과 자긍심이 조직몰입, 직무만족 및 직무성과에 미치는 영향. *관광연구, 22*(2), 285–307.

HEE, K. S., Lim, R. J., 이은희. (2019). 중소병원 간호사의 간호근무환경과 조직몰입 간의 관계: 수간호사 신뢰의 조절효과. *Asia-Pacific Journal of Multimedia Services Convergent with Art, Humanities and Sociology, 9*(9), 437–449. https://doi.org/10.35873/ajmahs.2019.9.9.038

Henrich, W. L., et al. (1996). Analgesics and the kidney: Summary and recommendations to the scientific advisory board of the National Kidney Foundation from an ad hoc committee of the National Kidney Foundation. *American Journal of Kidney Diseases, 27*(1), 162–165. https://doi.org/10.1016/s0272-6386(96)90046-3

---

# 📌 최종 정리

APA 7판은 언어에 따라 다른 형식을 요구하는 것이 아니다.
동일한 구조 안에서 저자 표기 방식과 제목 대소문자 규칙만 언어 특성에 맞게 달라질 뿐이다.
한국어 학술지 역시 반드시 이탤릭을 적용하는 것이 원칙이다.

---

본 문서는 연구자용 참고문헌 작성 표준 안내서로 활용할 수 있다.
`;

    /** localStorage에서 최근 검색어 목록(RK) 복원. 없거나 오류 시 빈 배열 */
    function load() { try { recent = JSON.parse(localStorage.getItem(RK) || '[]') } catch (e) { recent = [] } }

    /** 현재 선택된 탭(Google/Yonsei/RISS/KCI/DBpia/IEEE/ScienceDirect)에 맞춰 UI 전환 및 해당 검색 패널 포커스 */
    function tab(name) {
        currentTab = name;
        document.querySelectorAll('#scholar-modal .tab-row .tab').forEach(t => t.classList.remove('active'));
        const tabEl = document.querySelector(`#scholar-modal .tab-row .tab:nth-child(${['google','yonsei','sciencedirect','riss','kci','dbpia','ieee'].indexOf(name)+1})`);
        if (tabEl) tabEl.classList.add('active');
        document.querySelectorAll('#scholar-modal .tp').forEach(p => p.classList.remove('active'));
        const panel = document.getElementById('scholar-panel-' + name);
        if (panel) panel.classList.add('active');
        setTimeout(() => {
            const inp = document.querySelector('#scholar-panel-' + name + ' input[type=text]');
            if (inp) inp.focus();
        }, 50);
    }

    /** Scholar 검색 모달 표시, 최근 검색어 렌더, 현재 탭으로 초기화 후 검색 입력란에 포커스 */
    function show() {
        load(); renderRecent(); el('scholar-modal').classList.add('vis');
        tab(currentTab);
        setTimeout(() => {
            const inp = document.querySelector('#scholar-panel-' + currentTab + ' input[type=text]');
            if (inp) inp.focus();
        }, 80);
    }

    /** 현재 탭에 해당하는 검색어 입력란의 값을 반환 (Google/Yonsei/RISS 등 탭별 입력소스) */
    function getQ() {
        switch (currentTab) {
            case 'google': return el('scholar-q')?.value?.trim() || '';
            case 'yonsei': return el('scholar-yonsei-q')?.value?.trim() || '';
            case 'riss': return el('scholar-riss-q')?.value?.trim() || '';
            case 'dbpia': return el('scholar-dbpia-q')?.value?.trim() || '';
            case 'ieee': return el('scholar-ieee-q')?.value?.trim() || '';
            case 'sciencedirect': return el('scholar-sd-qs')?.value?.trim() || el('scholar-sd-authors')?.value?.trim() || el('scholar-sd-pub')?.value?.trim() || '';
            case 'kci': return el('scholar-kci-main')?.value?.trim() || el('scholar-kci-author')?.value?.trim() || el('scholar-kci-journal')?.value?.trim() || el('scholar-kci-publisher')?.value?.trim() || '';
            default: return '';
        }
    }

    /** 현재 탭의 검색 조건으로 외부 검색 사이트 URL 생성 (Google Scholar, RISS, KCI, DBpia, IEEE 등). KCI는 blob URL(자동제출 폼) 반환 */
    function buildUrl() {
        const enc = (s) => encodeURIComponent((s || '').trim());
        switch (currentTab) {
            case 'google': {
                const q = el('scholar-q').value.trim();
                if (!q) return null;
                const params = new URLSearchParams();
                params.set('q', q);
                params.set('hl', (el('scholar-lang')?.value || 'ko') === 'ko' ? 'ko' : 'en');
                const year = el('scholar-year')?.value;
                if (year) params.set('as_ylo', year);
                if (el('scholar-review')?.checked) params.set('as_rr', '1');
                return `https://scholar.google.com/scholar?${params.toString()}`;
            }
            case 'yonsei': {
                const q = el('scholar-yonsei-q').value.trim();
                if (!q) return null;
                return `https://library.yonsei.ac.kr/searchTotal?q=${enc(q)}`;
            }
            case 'sciencedirect': {
                const qs = el('scholar-sd-qs').value.trim();
                const authors = el('scholar-sd-authors').value.trim();
                const pub = el('scholar-sd-pub').value.trim();
                if (!qs && !authors && !pub) return null;
                const params = new URLSearchParams();
                if (qs) params.set('qs', qs);
                if (authors) params.set('authors', authors);
                if (pub) params.set('pub', pub);
                return `https://www.sciencedirect.com/search?${params.toString()}`;
            }
            case 'riss': {
                const q = el('scholar-riss-q').value.trim();
                if (!q) return null;
                return `https://www.riss.kr/search/Search.do?query=${enc(q)}`;
            }
            case 'kci': {
                const main = el('scholar-kci-main').value.trim();
                const author = el('scholar-kci-author').value.trim();
                const journal = el('scholar-kci-journal').value.trim();
                const publisher = el('scholar-kci-publisher').value.trim();
                if (!main && !author && !journal && !publisher) return null;
                // KCI input: #mainSearchKeyword, #search_top ul li:nth-child(2)=저자, (3)=간행지, (4)=발행기관
                // 폼 자동제출로 main.kci에 전달 (mainSearchKeyword 등 파라미터명 시도)
                const esc = (s) => String(s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>KCI 검색</title></head><body>
<form id="kciForm" action="https://www.kci.go.kr/kciportal/main.kci" method="GET">
<input type="hidden" name="mainSearchKeyword" value="${esc(main)}">
<input type="hidden" name="searchAuthor" value="${esc(author)}">
<input type="hidden" name="searchJournal" value="${esc(journal)}">
<input type="hidden" name="searchPublisher" value="${esc(publisher)}">
</form>
<script>document.getElementById('kciForm').submit();</script>
<p style="font-family:sans-serif;padding:20px">KCI 검색 페이지로 이동 중...</p>
</body></html>`;
                const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
                return URL.createObjectURL(blob);
            }
            case 'dbpia': {
                const q = el('scholar-dbpia-q').value.trim();
                if (!q) return null;
                return `https://www.dbpia.co.kr/search/topSearch?query=${enc(q)}`;
            }
            case 'ieee': {
                const q = el('scholar-ieee-q').value.trim();
                if (!q) return null;
                return `https://ieeexplore.ieee.org/search/searchresult.jsp?queryText=${enc(q)}`;
            }
            default: return null;
        }
    }

    /** buildUrl()로 만든 URL로 새 창을 열어 검색 실행. Google Scholar일 때는 검색어를 최근 검색 목록에 추가 */
    function search() {
        const url = buildUrl();
        if (!url) {
            const inp = document.querySelector('#scholar-panel-' + currentTab + ' input[type=text]');
            if (inp) inp.focus();
            App._toast?.('검색어를 입력하세요.');
            return;
        }
        if (currentTab === 'kci') {
            const main = el('scholar-kci-main')?.value?.trim() || '';
            if (main) navigator.clipboard.writeText(main).catch(() => {});
            window.open(url, 'scholar_search_' + currentTab, 'width=1100,height=800,left=100,top=80,resizable=yes,scrollbars=yes');
            if (url.startsWith('blob:')) setTimeout(() => URL.revokeObjectURL(url), 5000);
        } else {
            window.open(url, 'scholar_search_' + currentTab, 'width=1100,height=800,left=100,top=80,resizable=yes,scrollbars=yes');
        }

        const q = getQ();
        if (q && currentTab === 'google') {
            recent = recent.filter(r => r !== q); recent.unshift(q); recent = recent.slice(0, 8);
            try { localStorage.setItem(RK, JSON.stringify(recent)) } catch (e) { }
            renderRecent();
        }
    }

    /** 최근 검색어 목록(recent)을 #scholar-recent 영역에 칩 형태로 렌더. 클릭 시 useRecent 호출, ✕ 시 removeRecent */
    function renderRecent() {
        const wrap = el('scholar-recent-wrap');
        const div = el('scholar-recent');
        if (!wrap || !div) return;
        wrap.style.display = 'block';
        if (!recent.length) {
            div.innerHTML = '<span style="font-size:11px;color:var(--tx3)">최근 검색어가 없습니다. Google Scholar 등에서 검색하면 여기에 표시됩니다.</span>';
            return;
        }
        const escapeHtml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        const escapeJs = (s) => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n');
        div.innerHTML = recent.map((r, i) => {
            const esc = escapeJs(r);
            const safe = escapeHtml(r);
            return `<span style="display:inline-flex;align-items:center;gap:3px;background:var(--bg5);border:1px solid var(--bd);border-radius:var(--r);padding:2px 6px 2px 8px;font-size:11px;color:var(--tx2)"><span style="cursor:pointer" onclick="Scholar.useRecent('${esc}')">🕐 ${safe}</span><button type="button" onclick="event.stopPropagation();Scholar.removeRecent(${i})" style="background:none;border:none;cursor:pointer;padding:0 2px;font-size:12px;color:var(--tx3);line-height:1" title="이 검색어 지우기">✕</button></span>`;
        }).join('');
    }

    /** 최근 검색어 목록에서 지정 인덱스 항목 제거 후 localStorage 저장 및 renderRecent 갱신 */
    function removeRecent(index) {
        if (index < 0 || index >= recent.length) return;
        recent.splice(index, 1);
        try { localStorage.setItem(RK, JSON.stringify(recent)) } catch (e) { }
        renderRecent();
    }

    /** 최근 검색어(q)를 모든 탭의 검색 입력란에 동일하게 넣고 search() 실행 (한 번에 동일 검색어로 검색) */
    function useRecent(q) {
        el('scholar-q').value = q;
        el('scholar-yonsei-q').value = q;
        el('scholar-riss-q').value = q;
        el('scholar-dbpia-q').value = q;
        el('scholar-ieee-q').value = q;
        el('scholar-sd-qs').value = q;
        el('scholar-kci-main').value = q;
        search();
    }

    /** 모든 검색 입력란 및 최근 검색 목록 초기화, localStorage의 최근 검색어 삭제 후 현재 탭 입력란에 포커스 */
    function clear() {
        el('scholar-q').value = '';
        el('scholar-yonsei-q').value = '';
        el('scholar-riss-q').value = '';
        el('scholar-dbpia-q').value = '';
        el('scholar-ieee-q').value = '';
        el('scholar-sd-qs').value = '';
        el('scholar-sd-authors').value = '';
        el('scholar-sd-pub').value = '';
        el('scholar-kci-main').value = '';
        el('scholar-kci-author').value = '';
        el('scholar-kci-journal').value = '';
        el('scholar-kci-publisher').value = '';
        recent = [];
        try { localStorage.removeItem(RK) } catch (e) { }
        renderRecent();
        const inp = document.querySelector('#scholar-panel-' + currentTab + ' input[type=text]');
        if (inp) inp.focus();
    }

    /** APA 7판 참고문헌 작성 가이드(APA_GUIDE_MD)를 마크다운 렌더 후 새 창에 표시. 확대/축소 버튼 제공 */
    function openApaGuide() {
        let html;
        try {
            html = typeof mdRender === 'function' ? mdRender(APA_GUIDE_MD, true) : (typeof marked !== 'undefined' ? marked.parse(APA_GUIDE_MD) : APA_GUIDE_MD.replace(/\n/g, '<br>'));
        } catch (e) {
            html = '<p style="color:var(--er)">' + (e.message || '렌더 오류') + '</p>';
        }
        html = (html || '').replace(/<\/script>/gi, '<\\/script>');
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        const w = window.open('', '_blank', 'width=800,height=700,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>APA 7판 참고문헌 작성 가이드</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;background:var(--bg3);flex-wrap:wrap">' +
            '<button type="button" onclick="var p=document.getElementById(\'apa-guide-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.min(24,s+2)+\'px\';var L=document.getElementById(\'apa-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx);font-size:12px">확대</button>' +
            '<button type="button" onclick="var p=document.getElementById(\'apa-guide-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.max(10,s-2)+\'px\';var L=document.getElementById(\'apa-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx);font-size:12px">축소</button>' +
            '<span id="apa-zoom-label" style="font-size:11px;color:var(--tx3);min-width:40px">100%</span>' +
            '</div>' +
            '<div id="apa-guide-content" style="flex:1;min-height:0;overflow:auto;padding:20px;font-size:13px;line-height:1.7">' +
            '<div class="preview-page" style="max-width:720px;margin:0 auto">' + html + '</div></div></body></html>'
        );
        w.document.close();
    }

    return { show, search, useRecent, removeRecent, clear, tab, openApaGuide };
})();

/* ═══════════════════════════════════════════════════════════
   AI PPT — ScholarSlide 연동 (MD 내용 → 슬라이드 변환)
   흐름: 에디터 텍스트 클립보드 복사 → ScholarSlide 새 창 열기
         → postMessage 전송 시도 (사이트 지원 시 자동 붙여넣기)
         → 안내 토스트 표시
═══════════════════════════════════════════════════════════ */
const AiPPT = (() => {
    const SITE     = 'https://shoutjoy.github.io/sholarslide/';
    const ORIGIN   = 'https://shoutjoy.github.io'; // postMessage targetOrigin (경로 제외)
    const WIN_NAME = 'scholarslide_ppt';
    const WIN_OPTS = 'width=1280,height=900,left=80,top=60,resizable=yes,scrollbars=yes';
    let _win = null;
    let _pendingText = null;  // 창 로드 완료 전 대기 텍스트

    /* ── postMessage 전송 (targetOrigin = '*' 로 크로스도메인 보장) ── */
    function _send(text) {
        if (!_win || _win.closed) return false;
        try {
            _win.postMessage({ type: 'mdpro_text', text }, '*');
            return true;
        } catch (e) { return false; }
    }

    /* ── 다중 타이밍 재시도 (로드 속도 차이 대응) ── */
    function _scheduleRetry(text) {
        [200, 600, 1200, 2200, 3500].forEach(ms => {
            setTimeout(() => {
                if (_pendingText === text) _send(text);
            }, ms);
        });
    }

    async function open() {
        /* 1. 에디터 내용 가져오기 */
        const edEl = document.getElementById('editor');
        const text = edEl ? edEl.value.trim() : '';
        if (!text) { App._toast('⚠ 에디터에 내용이 없습니다'); return; }

        _pendingText = text;

        /* 2. 클립보드 복사 (fallback 포함) */
        let copied = false;
        try {
            await navigator.clipboard.writeText(text);
            copied = true;
        } catch (e) {
            try {
                const ta = document.createElement('textarea');
                ta.value = text;
                ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                copied = true;
            } catch (e2) {}
        }

        /* 3. 창 열기 또는 재사용 */
        const isReuse = _win && !_win.closed;
        if (isReuse) {
            _win.focus();
            /* 재사용 창: 즉시 + 재시도 전송 */
            _send(text);
            _scheduleRetry(text);
        } else {
            _win = window.open(SITE, WIN_NAME, WIN_OPTS);
            /* 신규 창: 로드 완료 후 전송 시도 */
            if (_win) {
                /* load 이벤트 리스너 등록 시도 (같은 origin이면 동작, 다르면 fallback) */
                try {
                    _win.addEventListener('load', () => {
                        setTimeout(() => _send(text), 100);
                    });
                } catch (e) {}
                /* 타이밍 재시도 병행 (크로스도메인 load 이벤트 불가 대비) */
                _scheduleRetry(text);
            }
        }

        /* 4. ScholarSlide에서 준비됐다는 응답 수신 시 즉시 전송 */
        /* (ScholarSlide가 'mdpro_ready' 메시지를 보내면 즉시 텍스트 전달) */

        /* 5. 안내 토스트 */
        App._toast(
            copied
                ? '📊 ScholarSlide 전송 중…\n텍스트가 자동으로 입력됩니다.\n(안 되면 Ctrl+V 후 ✅ 텍스트 로드 클릭)'
                : '📊 ScholarSlide를 열었습니다.\n텍스트를 수동으로 붙여넣어 주세요.',
            4000
        );
    }

    /* ScholarSlide 로부터 'ready' 응답 수신 → 즉시 전송 */
    window.addEventListener('message', (e) => {
        if (e.data && e.data.type === 'mdpro_ready' && _pendingText) {
            _send(_pendingText);
        }
    });

    return { open };
})();


/* ═══════════════════════════════════════════════════════════
   REF SEARCH — CrossRef / OpenAlex 내장 논문 검색
═══════════════════════════════════════════════════════════ */
const RefSearch = (() => {
    let _loading = false;

    /* ── APA 포맷터 ── */
    function toAPA(w) {
        if (w._src === 'scholar' && w.full) return w.full;
        // 저자
        let authors = '';
        if (w._src === 'openalex') {
            const au = (w.authorships || []).map(a => a.author?.display_name || '').filter(Boolean);
            if (au.length === 0) authors = 'Unknown';
            else if (au.length <= 5) authors = au.map(fmtName).join(', ');
            else authors = fmtName(au[0]) + ', et al.';
        } else {
            // CrossRef 실제 구조: [{family:"Kim", given:"J."}, ...]
            // name 필드는 기관저자에만 간혹 존재
            const au = (w.author || []).map(a => {
                if (a.family && a.given) return `${a.family}, ${a.given.trim()[0].toUpperCase()}.`;
                if (a.family) return a.family;
                if (a.name) return a.name;
                return '';
            }).filter(Boolean);
            if (au.length === 0) authors = 'Unknown';
            else if (au.length <= 5) authors = au.join(', ');
            else authors = au[0] + ', et al.';
        }
        // 연도
        const year = w._year || 'n.d.';
        // 제목
        const title = w._title || 'Untitled';
        // 저널
        const journal = w._journal || '';
        // 권·호·페이지
        const vol = w.volume || w._vol || '';
        const iss = w.issue || w._iss || '';
        const page = w.page || w._page || '';
        // DOI
        const doi = w.DOI || w._doi || '';
        let cite = `${authors} (${year}). ${title}.`;
        if (journal) cite += ` ${journal}`;
        if (vol) cite += `, ${vol}`;
        if (iss) cite += `(${iss})`;
        if (page) cite += `, ${page}`;
        cite += '.';
        if (doi) cite += ` https://doi.org/${doi}`;
        return cite;
    }

    function fmtName(n) {
        // "Firstname Lastname" → "Lastname, F."
        if (!n) return '';
        const parts = n.trim().split(/\s+/);
        if (parts.length === 1) return parts[0];
        const last = parts[parts.length - 1];
        const initials = parts.slice(0, -1).map(p => p[0].toUpperCase() + '.').join(' ');
        return `${last}, ${initials}`;
    }

    /* ── CrossRef API ── */
    async function searchCrossRef(q, year) {
        const rows = 10;
        let url = `https://api.crossref.org/works?query=${encodeURIComponent(q)}&rows=${rows}&select=DOI,title,author,published-print,published-online,container-title,volume,issue,page&mailto=mdpro@editor.app`;
        if (year) url += `&filter=from-pub-date:${year}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error('CrossRef 응답 오류');
        const data = await res.json();
        return (data.message?.items || []).map(w => {
            const yr = (w['published-print'] || w['published-online'])?.['date-parts']?.[0]?.[0] || '';
            return {
                _src: 'crossref', _title: (w.title || [''])[0], _year: yr,
                _journal: (w['container-title'] || [])[0] || '',
                _vol: w.volume || '', _iss: w.issue || '', _page: w.page || '',
                DOI: w.DOI || '', author: w.author || [],
                _url: w.DOI ? `https://doi.org/${w.DOI}` : ''
            };
        });
    }

    /* ── OpenAlex API ── */
    async function searchOpenAlex(q, year) {
        let url = `https://api.openalex.org/works?search=${encodeURIComponent(q)}&per-page=10&select=id,title,authorships,publication_year,primary_location,biblio,doi,open_access`;
        if (year) url += `&filter=publication_year:>${parseInt(year) - 1}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error('OpenAlex 응답 오류');
        const data = await res.json();
        return (data.results || []).map(w => {
            const src = w.primary_location?.source;
            return {
                _src: 'openalex', _title: w.title || '', _year: w.publication_year || '',
                _journal: src?.display_name || '',
                _vol: w.biblio?.volume || '', _iss: w.biblio?.issue || '',
                _page: w.biblio?.first_page ? (w.biblio.first_page + (w.biblio.last_page ? '–' + w.biblio.last_page : '')) : '',
                _doi: w.doi ? w.doi.replace('https://doi.org/', '') : '',
                DOI: w.doi ? w.doi.replace('https://doi.org/', '') : '',
                authorships: w.authorships || [],
                _oa: w.open_access?.is_oa || false,
                _url: w.doi || ''
            };
        });
    }

    /* ── SerpAPI Google Scholar ── */
    async function searchScholarSerpApi(q, year) {
        const apiKey = typeof ScholarApiKey !== 'undefined' ? ScholarApiKey.get() : '';
        if (!apiKey) throw new Error('Scholar API 키가 없습니다. 설정에서 SerpAPI 키를 입력·저장하세요.');
        let url = `https://serpapi.com/search.json?engine=google_scholar&q=${encodeURIComponent(q)}&api_key=${encodeURIComponent(apiKey)}&hl=ko`;
        if (year) url += `&as_ylo=${year}`;
        let res;
        try {
            res = await fetch(url);
        } catch (e) {
            if (e && (e.message === 'Failed to fetch' || e.name === 'TypeError')) {
                try {
                    res = await fetch('https://corsproxy.io/?' + encodeURIComponent(url));
                } catch (e2) {
                    throw new Error('CORS로 차단되었습니다. 로컬 서버(npx serve 등)로 실행하거나 잠시 후 다시 시도하세요.');
                }
            } else throw e;
        }
        if (res.status === 429) throw new Error('SerpAPI 요청 한도 초과(429). 잠시 후 다시 시도하세요.');
        if (!res.ok) throw new Error('Google Scholar 검색 응답 오류');
        const data = await res.json();
        if (data.error) throw new Error(data.error || 'SerpAPI 오류');
        const results = data.organic_results || [];
        return results.map(r => {
            const summary = (r.publication_info && r.publication_info.summary) || '';
            const yearMatch = summary.match(/\b(19|20)\d{2}\b/);
            const _year = yearMatch ? yearMatch[0] : '';
            let doi = '';
            const doiMatch = (r.link || '').match(/doi\.org\/([^\s?#]+)/) || (r.snippet || '').match(/10\.\d{4}\/[^\s]+/);
            if (doiMatch) doi = doiMatch[1] || doiMatch[0];
            const full = `${r.title || ''}. ${summary}. ${r.link || ''}`.trim();
            return {
                _src: 'scholar',
                _title: r.title || '',
                _year,
                _journal: summary,
                _url: r.link || '',
                full,
                DOI: doi,
                author: []
            };
        });
    }

    /* ── 렌더링 ── */
    function renderCards(items) {
        const box = el('ref-results');
        if (!items.length) {
            box.innerHTML = '<div class="cite-empty">검색 결과가 없습니다.<br><span style="font-size:10px">다른 키워드를 시도하거나 Scholar ↗ 버튼으로 Google Scholar를 확인하세요.</span></div>';
            return;
        }
        box.innerHTML = items.map((w, i) => {
            const apa = toAPA(w);
            const doi = w.DOI || w._doi || '';
            const oa = w._oa ? '<span class="ref-tag" style="color:var(--ok);border-color:var(--ok)">OA</span>' : '';
            const src = w._src === 'scholar' ? '<span class="ref-tag">Scholar</span>' : w._src === 'openalex' ? '<span class="ref-tag">OpenAlex</span>' : '<span class="ref-tag">CrossRef</span>';
            const linkBtn = w._url && !(w.DOI || w._doi) ? `<a href="${w._url.replace(/"/g, '&quot;')}" target="_blank" rel="noopener" class="btn btn-g btn-sm">원문 ↗</a>` : '';
            return `<div class="ref-card">
  <div class="ref-card-title">${w._title || '제목 없음'}</div>
  <div class="ref-card-meta">
    ${w._year ? `<b>${w._year}</b> · ` : ''}${w._journal || ''}${w._vol ? ` ${w._vol}` : ''}${w._iss ? `(${w._iss})` : ''}
    ${src}${oa}
  </div>
  <div class="ref-card-apa" id="apa-${i}" title="클릭하면 전체 선택됨">${apa}</div>
  <div class="ref-card-btns">
    <button class="btn btn-p btn-sm" onclick="RefSearch.addToLib(${i})">+ 참고문헌에 추가</button>
    <button class="btn btn-g btn-sm" onclick="RefSearch.copyAPA(${i})">📋 APA 복사</button>
    ${doi ? `<a href="https://doi.org/${doi}" target="_blank" rel="noopener" class="btn btn-g btn-sm">DOI ↗</a>` : ''}
    ${linkBtn}
  </div>
</div>`;
        }).join('');
        // 데이터 저장 (버튼 콜백용)
        box._data = items;
        box._apas = items.map(toAPA);
    }

    /* ── 검색 실행 ── */
    async function search() {
        if (_loading) return;
        const db = el('ref-db').value;
        if (db === 'ai') syncAiPromptWithSearch();
        const q = db === 'ai' ? (el('ref-ai-prompt')?.value.trim() || el('ref-q').value.trim()) : el('ref-q').value.trim();
        const year = el('ref-year').value;
        if (!q) {
            if (db === 'ai') el('ref-ai-prompt')?.focus(); else el('ref-q').focus();
            return;
        }

        _loading = true;
        const status = el('ref-status');
        const box = el('ref-results');
        status.textContent = '🔄 검색 중...';
        box.innerHTML = '<div class="cite-empty" style="padding:24px"><div style="font-size:20px;margin-bottom:8px">⏳</div>잠시 기다려 주세요...</div>';

        try {
            let items;
            if (db === 'openalex') {
                items = await searchOpenAlex(q, year);
                status.textContent = `✅ ${items.length}건 검색됨 (OpenAlex) · "${q}"`;
            } else {
                items = await searchCrossRef(q, year);
                status.textContent = `✅ ${items.length}건 검색됨 (CrossRef) · "${q}"`;
            }
            renderCards(items);
        } catch (e) {
            status.textContent = `❌ 오류: ${e.message}`;
            box.innerHTML = `<div class="cite-empty">검색 실패: ${e.message}<br><span style="font-size:10px">네트워크를 확인하거나 Scholar ↗를 사용해주세요.</span></div>`;
        }
        _loading = false;
    }

    function syncAiPromptWithSearch() {
        const qEl = el('ref-q'), pEl = el('ref-ai-prompt');
        if (qEl && pEl) pEl.value = qEl.value;
    }

    function syncAiPromptVisibility() {
        const wrap = document.getElementById('ref-ai-prompt-wrap');
        const dbEl = document.getElementById('ref-db');
        if (wrap && dbEl) {
            const isAi = dbEl.value === 'ai';
            wrap.style.display = isAi ? 'block' : 'none';
            if (isAi) syncAiPromptWithSearch();
        }
    }

    function addToLib(i) {
        const box = el('ref-results');
        const apa = box._apas?.[i];
        if (!apa) return;
        CM.addRaw(apa);
        // 버튼 피드백
        const btns = box.querySelectorAll('.ref-card')[i]?.querySelectorAll('button');
        if (btns?.[0]) { btns[0].textContent = '✔ 추가됨'; btns[0].disabled = true; btns[0].style.opacity = '.6'; }
    }

    function copyAPA(i) {
        const box = el('ref-results');
        const apa = box._apas?.[i];
        if (!apa) return;
        navigator.clipboard.writeText(apa).then(() => {
            const btns = box.querySelectorAll('.ref-card')[i]?.querySelectorAll('button');
            if (btns?.[1]) { const orig = btns[1].textContent; btns[1].textContent = '✔ 복사됨'; setTimeout(() => btns[1].textContent = orig, 1500); }
        }).catch(() => {
            // fallback
            const el2 = document.createElement('textarea'); el2.value = apa; document.body.appendChild(el2); el2.select(); document.execCommand('copy'); el2.remove();
        });
    }

    function openScholar() {
        const q = el('ref-q').value.trim();
        const url = q ? `https://scholar.google.com/scholar?q=${encodeURIComponent(q)}&hl=ko` : 'https://scholar.google.com/?hl=ko';
        window.open(url, '_blank');
    }

    return { search, addToLib, copyAPA, openScholar, syncAiPromptVisibility, syncAiPromptWithSearch };
})();

    // ref-db 변경 시 AI 프롬프트 영역 표시/숨김 + AI 모드에서 검색어↔프롬프트 동기화
    (function initRefDbAi() {
        const dbEl = document.getElementById('ref-db');
        const qEl = document.getElementById('ref-q');
        const promptEl = document.getElementById('ref-ai-prompt');
        if (dbEl) dbEl.addEventListener('change', () => RefSearch.syncAiPromptVisibility());
        function syncIfAi() {
            if (dbEl && dbEl.value === 'ai' && qEl && promptEl) {
                qEl.value = promptEl.value;
            }
        }
        function syncFromSearch() {
            if (dbEl && dbEl.value === 'ai' && qEl && promptEl) {
                promptEl.value = qEl.value;
            }
        }
        if (qEl) qEl.addEventListener('input', syncFromSearch);
        if (promptEl) promptEl.addEventListener('input', syncIfAi);
    })();

/* ═══════════════════════════════════════════════════════════
   COLOR PICKER
═══════════════════════════════════════════════════════════ */
const ColorPicker = (() => {
    let mode = 'text';
    const TEXT_COLORS = ['#e8e8f0', '#ff4444', '#ff8800', '#ffcc00', '#44cc44', '#00aaff', '#aa44ff', '#ff44aa', '#000000', '#333333', '#666666', '#999999', '#cccccc', '#ffffff', '#5b4ce4', '#f7a06a'];
    const BG_COLORS = ['#fff176', '#ffcc80', '#ef9a9a', '#80cbc4', '#a5d6a7', '#90caf9', '#ce93d8', '#f48fb1', '#ffecb3', '#dcedc8', 'transparent'];

    function open(m) {
        mode = m;
        el('color-modal-title').textContent = m === 'text' ? '글자 색상 설정' : '형광펜 하이라이트 색상';
        const colors = m === 'text' ? TEXT_COLORS : BG_COLORS;
        el('color-swatches').innerHTML = colors.map(c => `<div class="csw" style="background:${c === 'transparent' ? 'repeating-linear-gradient(45deg,#888,#888 2px,transparent 2px,transparent 6px)' : c};border-color:${c === '#ffffff' ? '#ccc' : 'transparent'}" onclick="ColorPicker.setHex('${c}')" title="${c}"></div>`).join('');
        el('color-hex').value = '';
        // 스포이드 지원 여부
        const supported = 'EyeDropper' in window;
        el('eyedropper-btn').style.display = supported ? '' : 'none';
        el('eyedrop-support-msg').style.display = supported ? 'none' : 'block';
        // 팔레트 클릭 연동
        el('eyedrop-btn').onclick = e => { e.preventDefault(); el('color-native').click() };
        el('color-modal').classList.add('vis');
        updatePreview('');
    }

    function setHex(c) {
        el('color-hex').value = c;
        // native color input도 동기화 (투명 제외)
        if (c && c !== 'transparent') { try { el('color-native').value = c } catch (e) { } }
        updatePreview(c);
    }

    // <input type="color"> 팔레트에서 선택
    function fromNative(hex) {
        el('color-hex').value = hex;
        updatePreview(hex);
    }

    // EyeDropper API — Chrome 95+ / Edge 95+
    async function eyedrop() {
        if (!('EyeDropper' in window)) {
            el('eyedrop-support-msg').style.display = 'block'; return;
        }
        try {
            // 모달 투명화 → 화면 전체에서 색상 선택 가능
            el('color-modal').style.opacity = '0';
            el('color-modal').style.pointerEvents = 'none';
            const result = await new EyeDropper().open();
            el('color-modal').style.opacity = '';
            el('color-modal').style.pointerEvents = '';
            setHex(result.sRGBHex);
        } catch (e) {
            // 사용자 취소 시 조용히 복원
            el('color-modal').style.opacity = '';
            el('color-modal').style.pointerEvents = '';
        }
    }

    function updatePreview(c) {
        const prev = el('color-preview');
        if (!c || c === 'transparent') { prev.style.color = ''; prev.style.background = ''; return }
        if (mode === 'text') { prev.style.color = c; prev.style.background = '' }
        else { prev.style.background = c; prev.style.color = '' }
    }

    function apply() {
        const c = el('color-hex').value.trim(); if (!c) return;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd; const sel = ed.value.substring(s, e) || '텍스트';
        let wrapped;
        if (mode === 'text') { wrapped = `<span style="color:${c}">${sel}</span>` }
        else { wrapped = c === 'transparent' ? sel : `<span style="background:${c}">${sel}</span>` }
        ins(ed, s, e, wrapped);
        if (mode === 'text') { el('fc-bar').style.background = c }
        else { el('hl-bar').style.background = c }
        App.hideModal('color-modal');
    }

    return { open, setHex, fromNative, eyedrop, updatePreview, apply };
})();

/* ═══════════════════════════════════════════════════════════
   EDITOR ACTIONS
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   IMAGE DROP HANDLER
═══════════════════════════════════════════════════════════ */
const IMG = (() => {
    function dragOver(e) { e.preventDefault(); e.stopPropagation(); el('img-dropzone').style.borderColor = 'var(--ac)'; el('img-dropzone').style.background = 'var(--acg)' }
    function dragLeave(e) { el('img-dropzone').style.borderColor = 'var(--bd)'; el('img-dropzone').style.background = 'var(--bg3)' }
    function drop(e) {
        e.preventDefault(); e.stopPropagation();
        dragLeave(e);
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) loadImage(file);
    }
    function fileSelected(ev) {
        const file = ev.target.files[0];
        if (file) loadImage(file);
        ev.target.value = '';
    }
    function loadImage(file) {
        const reader = new FileReader();
        reader.onload = ev => {
            const dataUrl = ev.target.result;
            el('img-url').value = dataUrl;
            if (!el('img-alt').value) el('img-alt').value = file.name.replace(/\.[^.]+$/, '');
            _showImgpv(dataUrl);
            el('img-drop-text').textContent = '✓ ' + file.name + ' (' + Math.round(file.size / 1024) + 'KB)';
            el('img-drop-text').style.color = 'var(--ok)';
            const cropBtn = document.getElementById('img-insert-crop-btn');
            if (cropBtn) cropBtn.disabled = false;
        };
        reader.readAsDataURL(file);
    }
    return { dragOver, dragLeave, drop, fileSelected };
})();

function _showImgpv(src) {
    const ph = document.getElementById('imgpv-placeholder');
    const img = document.getElementById('imgpv-preview');
    if (!img) return;
    if (src && (src.startsWith('data:image') || src.startsWith('http'))) {
        img.src = src;
        img.style.display = 'block';
        if (ph) ph.style.display = 'none';
    } else {
        img.removeAttribute('src');
        img.style.display = 'none';
        if (ph) ph.style.display = 'block';
    }
}
function _bindImgUrlToImgpv() {
    const urlEl = document.getElementById('img-url');
    if (!urlEl || urlEl._imgpvBound) return;
    urlEl._imgpvBound = true;
    urlEl.addEventListener('input', () => _showImgpv(urlEl.value.trim()));
    urlEl.addEventListener('change', () => _showImgpv(urlEl.value.trim()));
}
function _parseImgCodeToPreview() {
    const ta = document.getElementById('img-code-input');
    if (!ta || !ta.value.trim()) return;
    const html = ta.value.trim();
    const m = html.match(/<img[^>]+src\s*=\s*["']([^"']+)["']/i);
    if (m && m[1]) _showImgpv(m[1]);
}
function _bindImgCodeToPreview() {
    const ta = document.getElementById('img-code-input');
    if (!ta || ta._imgCodeBound) return;
    ta._imgCodeBound = true;
    ta.addEventListener('input', _parseImgCodeToPreview);
    ta.addEventListener('change', _parseImgCodeToPreview);
}

const ImgCrop = {
    openForInsert() {
        const urlEl = document.getElementById('img-url');
        const previewEl = document.getElementById('imgpv-preview');
        const src = (urlEl && urlEl.value && urlEl.value.trim()) || (previewEl && previewEl.src);
        if (!src || (!src.startsWith('data:') && !src.startsWith('http'))) {
            alert('먼저 이미지를 업로드하거나 URL을 입력하세요.');
            return;
        }
        if (src.startsWith('http') && previewEl && !previewEl.complete) {
            alert('이미지 로딩 중입니다. 잠시 후 다시 시도하세요.');
            return;
        }
        window._imgCropTarget = 'insert';
        window._mdliveCropPending = src;
        const w = window.open('crop.html', 'crop', 'width=640,height=560,scrollbars=yes');
        if (!w) { alert('팝업이 차단되었습니다.'); window._imgCropTarget = null; window._mdliveCropPending = null; return; }
    }
};

const ImgInsert = {
    insertToNewFile() {
        const url = document.getElementById('img-url')?.value?.trim();
        const alt = document.getElementById('img-alt')?.value?.trim() || '이미지';
        if (!url) { alert('삽입할 이미지가 없습니다. URL을 입력하거나 이미지를 업로드하세요.'); return; }
        const title = '이미지-' + new Date().toISOString().slice(0, 10);
        if (typeof TM !== 'undefined' && TM.newTab) TM.newTab(title, `![${alt}](${url})`, 'md');
        if (url.startsWith('data:image') && typeof ImgStore !== 'undefined') ImgStore.save(url, alt);
    },
    _codeExamples: [
        '<img src="https://i.ibb.co/vCn4MwWK/pro-render-1771925609150.png" alt="pro render 1771925609150" border="0">',
        '<a href="https://ibb.co/spY9Xm4M"><img src="https://i.ibb.co/2043pnrf/pro-render-1771925609150.png" alt="pro-render-1771925609150" border="0"></a>',
        '<a href="https://ibb.co/spY9Xm4M"><img src="https://i.ibb.co/2043pnrf/pro-render-1771925609150.png" alt="pro-render-1771925609150" border="0"></a>',
        '<a href="https://ibb.co/spY9Xm4M"><img src="https://i.ibb.co/spY9Xm4M/pro-render-1771925609150.png" alt="pro-render-1771925609150" border="0"></a>'
    ],
    setCodeExample(n) {
        const ta = document.getElementById('img-code-input');
        if (ta && this._codeExamples[n - 1]) ta.value = this._codeExamples[n - 1];
        _parseImgCodeToPreview();
    },
    insertHtmlImage() {
        const url = document.getElementById('img-html-url')?.value?.trim();
        const w = document.getElementById('img-html-width')?.value?.trim();
        const h = document.getElementById('img-html-height')?.value?.trim();
        if (!url) { alert('링크를 입력하세요.'); return; }
        let tag = '<img src="' + url.replace(/"/g, '&quot;') + '" alt="" border="0"';
        if (w) tag += ' width="' + w.replace(/"/g, '&quot;') + '"';
        if (h) tag += ' height="' + h.replace(/"/g, '&quot;') + '"';
        tag += '>';
        const ed = document.getElementById('editor');
        if (!ed) return;
        const pos = ed.selectionEnd;
        const v = ed.value;
        ed.value = v.slice(0, pos) + tag + v.slice(pos);
        ed.setSelectionRange(pos + tag.length, pos + tag.length);
        if (typeof App !== 'undefined') App.render();
    }
};

const ImgStore = (() => {
    const DB = 'mdlive-img-store';
    const STORE = 'images';
    function open() {
        return new Promise((res, rej) => {
            const r = indexedDB.open(DB, 1);
            r.onupgradeneeded = e => {
                if (!e.target.result.objectStoreNames.contains(STORE)) e.target.result.createObjectStore(STORE, { keyPath: 'id' });
            };
            r.onsuccess = () => res(r.result);
            r.onerror = () => rej(r.error);
        });
    }
    async function save(dataUrl, alt) {
        if (!dataUrl || !dataUrl.startsWith('data:image')) return;
        const db = await open();
        return new Promise((res, rej) => {
            const t = db.transaction(STORE, 'readwrite');
            t.objectStore(STORE).put({ id: 'img-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9), dataUrl, alt: alt || '', createdAt: Date.now() });
            t.oncomplete = () => res();
            t.onerror = () => rej(t.error);
        });
    }
    return { save };
})();

(function initImgUrlPreview() {
    const urlEl = document.getElementById('img-url');
    if (!urlEl) return;
    urlEl.addEventListener('input', () => {
        const v = urlEl.value.trim();
        const preview = document.getElementById('img-preview');
        const wrap = document.getElementById('img-preview-wrap');
        const cropBtn = document.getElementById('img-insert-crop-btn');
        if (v.startsWith('data:image')) {
            if (preview) { preview.src = v; preview.style.display = 'block'; }
            if (wrap) wrap.style.display = 'block';
            if (cropBtn) cropBtn.disabled = false;
        } else if (cropBtn && (v.startsWith('http') || v.length > 0)) {
            cropBtn.disabled = !v;
        }
    });
})();

/* ═══════════════════════════════════════════════════════════
   AI IMAGE (이미지 모달 내 AI 이미지 탭)
   모델 선택, 시드 이미지, 프롬프트, 생성, 히스토리, 다운로드(일괄/ZIP/프로젝트.mdp), 크롭
═══════════════════════════════════════════════════════════ */
const AiImage = (() => {
    const DB_NAME = 'mdlive-aiimg-history';
    const STORE_NAME = 'history';
    let _seedDataUrl = '';
    let _resultImages = [];
    let _currentPrompt = '';
    let _busy = false;
    let _historyCache = [];
    let _cropImageUrl = '';
    let _cropRect = { x: 0, y: 0, w: 0, h: 0 };
    let _cropDragging = false;
    let _cropStart = { x: 0, y: 0 };
    let _aspectRatio = '1:1';
    let _seedAspectRatio = '';
    let _analysisResult = { face: '', outfit: '' };
    let _analysisHistory = [];
    let _virtualTryOnDataUrl = '';
    let _virtualTryOnExtractedDataUrl = '';

    function _openDB() {
        return new Promise((resolve, reject) => {
            const r = indexedDB.open(DB_NAME, 1);
            r.onerror = () => reject(r.error);
            r.onsuccess = () => resolve(r.result);
            r.onupgradeneeded = (e) => {
                if (!e.target.result.objectStoreNames.contains(STORE_NAME)) {
                    e.target.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
                }
            };
        });
    }
    async function _getAll() {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readonly');
            const req = t.objectStore(STORE_NAME).getAll();
            req.onsuccess = () => resolve(req.result || []);
            req.onerror = () => reject(req.error);
        });
    }
    async function _add(record) {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readwrite');
            t.objectStore(STORE_NAME).put(record);
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
        });
    }
    async function _delete(id) {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readwrite');
            t.objectStore(STORE_NAME).delete(id);
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
        });
    }
    async function _clearAll() {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readwrite');
            t.objectStore(STORE_NAME).clear();
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
        });
    }

    function switchTab(tab) {
        const insertPanel = el('img-insert-panel');
        const historyPanel = el('aiimg-history-panel');
        const centerInsert = el('imgpv');
        const centerAi = el('img-center-ai');
        const rightSidebar = el('img-right-sidebar');
        const box = el('image-modal-box');
        const tabs = document.querySelectorAll('.img-side-tab');
        if (!insertPanel || !historyPanel) return;
        if (tab === 'ai') {
            insertPanel.style.display = 'none';
            historyPanel.style.display = 'flex';
            if (centerInsert) centerInsert.style.display = 'none';
            if (centerAi) centerAi.style.display = 'flex';
            if (rightSidebar) { rightSidebar.style.display = 'flex'; }
            if (box) box.style.maxWidth = '960px';
            tabs.forEach(t => { t.classList.toggle('active', t.getAttribute('data-tab') === 'ai'); });
            loadHistory();
        } else {
            insertPanel.style.display = 'block';
            historyPanel.style.display = 'none';
            if (centerInsert) centerInsert.style.display = 'flex';
            if (centerAi) centerAi.style.display = 'none';
            if (rightSidebar) rightSidebar.style.display = 'none';
            if (box) box.style.maxWidth = '720px';
            tabs.forEach(t => { t.classList.toggle('active', t.getAttribute('data-tab') === 'insert'); });
        }
    }

    function toggleMaximize() {
        const box = el('image-modal-box');
        if (!box) return;
        const on = box.classList.toggle('img-modal-maximized');
        if (on) {
            box.style.maxWidth = '';
        } else {
            const isAi = document.querySelector('.img-side-tab.active')?.getAttribute('data-tab') === 'ai';
            box.style.maxWidth = isAi ? '960px' : '720px';
        }
        const btn = document.getElementById('img-modal-maximize');
        if (btn) {
            btn.textContent = on ? '전체화면 해제' : '전체화면';
            btn.title = on ? '전체화면 해제' : '전체화면';
        }
    }

    function _gcd(a, b) { return b ? _gcd(b, a % b) : a; }
    function _setSeedAspectRatio(dataUrl) {
        _seedAspectRatio = '';
        if (!dataUrl) return;
        const img = new Image();
        img.onload = function() {
            const w = img.naturalWidth, h = img.naturalHeight;
            if (w && h) {
                const g = _gcd(w, h);
                _seedAspectRatio = (w / g) + ':' + (h / g);
            }
        };
        img.src = dataUrl;
    }
    (function initRatioButtons() {
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('.aiimg-ratio');
            if (!btn) return;
            const sidebar = document.getElementById('img-right-sidebar');
            if (!sidebar || sidebar.style.display === 'none') return;
            document.querySelectorAll('.aiimg-ratio').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            _aspectRatio = btn.getAttribute('data-ratio') || '1:1';
            const ta = document.getElementById('aiimg-prompt');
            if (ta) {
                const v = ta.value || '';
                ta.value = v.replace(/\s*\[비율:\s*[\d:]+\]\s*/g, '').replace(/\s*[\d:]+\s*비율로\s*(해줘|넣어줘)\s*/g, '').trim();
                const ratioText = _aspectRatio + ' 비율로 넣어줘';
                const suffix = ' ' + ratioText;
                if (ta.value) ta.value = ta.value + suffix;
                else ta.value = ratioText;
            }
        });
    })();

    const PRESETS = {
        person: 'Same person. Keep the same character. ',
        outfit: 'Same outfit. Keep the same clothing. ',
        diagram: 'Flowchart, statistics diagram. Clear and readable. ',
        chart: 'Chart visualization. ',
        story: 'Notebook LM style story illustration. '
    };
    const MENU_TYPE_EN = {
        '극사실주의': 'hyperrealism',
        '스튜디오': 'studio',
        '패션': 'fashion',
        '일본만화': 'japanese manga style',
        '수채화': 'watercolor',
        '단순화그림체': 'simplified illustration style'
    };
    function applyPreset(type) {
        const ta = el('aiimg-prompt');
        if (!ta) return;
        let prefix = '';
        if (type === 'person') {
            const faceText = _analysisResult.face || (document.getElementById('aiimg-analysis-text') && document.getElementById('aiimg-analysis-text').textContent.trim()) || '';
            if (faceText) {
                prefix = faceText + '\n\nKeep the same person. Maintain the character\'s face and appearance. ';
            } else {
                prefix = PRESETS.person;
            }
        } else if (type === 'outfit') {
            if (_analysisResult.outfit) prefix = '[복장 고정]\n' + _analysisResult.outfit + '\n\n';
            else prefix = PRESETS.outfit;
        } else {
            prefix = PRESETS[type] || '';
        }
        ta.value = prefix + (ta.value || '');
        ta.focus();
    }
    function sendAnalysisToPrompt() {
        const analysisEl = document.getElementById('aiimg-analysis-text');
        const ta = document.getElementById('aiimg-prompt');
        if (!analysisEl || !ta) return;
        const text = (analysisEl.textContent || '').trim();
        if (!text) return;
        const current = (ta.value || '').trim();
        ta.value = current ? current + '\n\n' + text : text;
        ta.focus();
    }
    function applyMenuType(type) {
        const ta = el('aiimg-prompt');
        if (!ta) return;
        const en = MENU_TYPE_EN[type] || type;
        const text = (ta.value || '').trim();
        ta.value = text ? text + ', ' + en : en;
        ta.focus();
    }
    async function analyzeSeedImage() {
        if (!_seedDataUrl) return;
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) { alert('AI API 키를 설정에서 입력해 주세요.'); return; }
        const btn = document.getElementById('aiimg-analyze-btn');
        if (btn) btn.disabled = true;
        const analysisEl = document.getElementById('aiimg-analysis-text');
        if (analysisEl) analysisEl.textContent = '분석 중…';
        try {
            const base64 = _seedDataUrl.replace(/^data:image\/\w+;base64,/, '');
            const mime = _seedDataUrl.match(/^data:(image\/\w+);/);
            const modelId = 'gemini-2.5-flash';
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(key)}`;
            const body = {
                contents: [{
                    role: 'user',
                    parts: [
                        { inlineData: { mimeType: mime ? mime[1] : 'image/png', data: base64 } },
                        { text: '이 이미지에 등장하는 인물과 복장을 분석해서 다음 형식으로만 답해. 다른 말 없이 아래 형식만.\n\n[인물]\n얼굴: 눈 특징, 눈썹, 코, 입 모양, 피부톤 등\n헤어: 길이, 스타일, 색 등\n기타: 성별, 나이대 등\n\n[복장]\n상의, 하의, 악세서리 등 입은 옷과 스타일을 구체적으로.' }
                    ]
                }],
                generationConfig: { temperature: 0.2, maxOutputTokens: 1024 }
            };
            const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
            const data = await r.json();
            if (!r.ok) throw new Error(data.error?.message || 'API 오류');
            const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
            const faceMatch = text.match(/\[인물\]([\s\S]*?)(?=\[복장\]|$)/);
            const outfitMatch = text.match(/\[복장\]([\s\S]*?)$/);
            _analysisResult.face = faceMatch ? faceMatch[1].trim() : '';
            _analysisResult.outfit = outfitMatch ? outfitMatch[1].trim() : '';
            const displayText = (_analysisResult.face ? '[인물]\n' + _analysisResult.face + '\n\n' : '') + (_analysisResult.outfit ? '[복장]\n' + _analysisResult.outfit : '') || '분석 결과 없음';
            if (analysisEl) analysisEl.textContent = displayText;
            _analysisHistory.unshift({
                id: 'analysis-' + Date.now(),
                text: displayText,
                face: _analysisResult.face,
                outfit: _analysisResult.outfit,
                createdAt: Date.now()
            });
            if (_analysisHistory.length > 50) _analysisHistory.pop();
        } catch (e) {
            if (analysisEl) analysisEl.textContent = '오류: ' + (e.message || String(e));
        }
        if (btn) btn.disabled = false;
    }
    function onVirtualTryOnFile(ev) {
        const file = ev.target.files[0];
        if (!file || !file.type.startsWith('image/')) return;
        ev.target.value = '';
        const reader = new FileReader();
        reader.onload = () => {
            _virtualTryOnDataUrl = reader.result;
            _virtualTryOnExtractedDataUrl = '';
            const imgEl = document.getElementById('aiimg-virtual-tryon-img');
            const wrap = document.getElementById('aiimg-virtual-tryon-preview');
            const nameEl = document.getElementById('aiimg-virtual-tryon-name');
            const clearBtn = document.getElementById('aiimg-virtual-tryon-clear');
            const extractedWrap = document.getElementById('aiimg-virtual-tryon-extracted-wrap');
            const extractedImg = document.getElementById('aiimg-virtual-tryon-extracted-img');
            const extractedLoading = document.getElementById('aiimg-virtual-tryon-extracted-loading');
            if (imgEl) imgEl.src = _virtualTryOnDataUrl;
            if (wrap) wrap.style.display = 'block';
            const descEl = document.getElementById('aiimg-virtual-tryon-desc');
            if (descEl) descEl.textContent = '옷 이미지 또는 인물 이미지를 올리면 AI가 옷을 추출하고, 생성 시 적용됩니다.';
            if (nameEl) nameEl.textContent = file.name;
            if (clearBtn) clearBtn.disabled = false;
            const reextractBtn = document.getElementById('aiimg-virtual-tryon-reextract');
            if (reextractBtn) reextractBtn.disabled = false;
            const refExtracted = document.getElementById('aiimg-tryon-ref-extracted');
            if (refExtracted) refExtracted.checked = true;
            if (extractedWrap) { extractedWrap.style.display = 'none'; if (extractedImg) extractedImg.style.display = 'none'; }
            extractClothingForTryOn();
        };
        reader.readAsDataURL(file);
    }
    async function extractClothingForTryOn() {
        if (!_virtualTryOnDataUrl) return;
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) return;
        const modelId = (el('aiimg-model') && el('aiimg-model').value) || 'gemini-2.0-flash-exp-image-generation';
        const extractedWrap = document.getElementById('aiimg-virtual-tryon-extracted-wrap');
        const extractedImg = document.getElementById('aiimg-virtual-tryon-extracted-img');
        const extractedLoading = document.getElementById('aiimg-virtual-tryon-extracted-loading');
        if (extractedLoading) { extractedLoading.style.display = 'block'; extractedImg.style.display = 'none'; }
        if (extractedWrap) extractedWrap.style.display = 'block';
        try {
            const base64 = _virtualTryOnDataUrl.replace(/^data:image\/\w+;base64,/, '');
            const mime = _virtualTryOnDataUrl.match(/^data:(image\/\w+);/);
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(key)}`;
            const body = {
                contents: [{
                    role: 'user',
                    parts: [
                        { inlineData: { mimeType: mime ? mime[1] : 'image/png', data: base64 } },
                        { text: '이 이미지에서 옷(의상)만 추출해서 흰색 배경 위에 의상만 보이게 해줘. 인물은 제거하고 옷만 보이게 생성해 줘.' }
                    ]
                }],
                generationConfig: {
                    responseModalities: ['TEXT', 'IMAGE'],
                    responseMimeType: 'text/plain'
                }
            };
            const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(60000) });
            const data = await r.json();
            if (!r.ok) throw new Error(data.error?.message || 'API 오류');
            const parts = data.candidates?.[0]?.content?.parts || [];
            let extractedDataUrl = '';
            parts.forEach(p => {
                if (p.inlineData && p.inlineData.data) {
                    const mt = p.inlineData.mimeType || 'image/png';
                    extractedDataUrl = 'data:' + mt + ';base64,' + p.inlineData.data;
                }
            });
            if (extractedDataUrl) {
                _virtualTryOnExtractedDataUrl = extractedDataUrl;
                if (extractedImg) { extractedImg.src = extractedDataUrl; extractedImg.style.display = 'block'; }
            }
        } catch (e) {
            if (extractedLoading) {
                extractedLoading.textContent = '오류: ' + (e.message || String(e)).slice(0, 40);
                extractedLoading.style.display = 'block';
            }
        }
        if (extractedLoading && _virtualTryOnExtractedDataUrl) extractedLoading.style.display = 'none';
    }
    function clearVirtualTryOn() {
        _virtualTryOnDataUrl = '';
        _virtualTryOnExtractedDataUrl = '';
        const imgEl = document.getElementById('aiimg-virtual-tryon-img');
        const wrap = document.getElementById('aiimg-virtual-tryon-preview');
        const nameEl = document.getElementById('aiimg-virtual-tryon-name');
        const clearBtn = document.getElementById('aiimg-virtual-tryon-clear');
        const input = document.getElementById('aiimg-virtual-tryon-input');
        const extractedWrap = document.getElementById('aiimg-virtual-tryon-extracted-wrap');
        const extractedImg = document.getElementById('aiimg-virtual-tryon-extracted-img');
        const extractedLoading = document.getElementById('aiimg-virtual-tryon-extracted-loading');
        if (imgEl) imgEl.src = '';
        if (wrap) wrap.style.display = 'none';
        const descEl = document.getElementById('aiimg-virtual-tryon-desc');
        if (descEl) descEl.textContent = '이미지가 없는 경우 참고하지 않습니다.';
        if (nameEl) nameEl.textContent = '';
        if (clearBtn) clearBtn.disabled = true;
        if (input) input.value = '';
        const reextractBtn = document.getElementById('aiimg-virtual-tryon-reextract');
        if (reextractBtn) reextractBtn.disabled = true;
        if (extractedWrap) extractedWrap.style.display = 'none';
        if (extractedImg) extractedImg.src = '';
        if (extractedLoading) { extractedLoading.style.display = 'none'; extractedLoading.textContent = '추출 중…'; }
    }

    function onSeedFile(ev) {
        const file = ev.target.files[0];
        if (!file || !file.type.startsWith('image/')) return;
        const reader = new FileReader();
        reader.onload = () => {
            _seedDataUrl = reader.result;
            _setSeedAspectRatio(_seedDataUrl);
            const preview = el('aiimg-seed-preview');
            const placeholder = el('aiimg-seed-placeholder');
            if (preview) { preview.src = _seedDataUrl; preview.style.display = 'block'; }
            if (placeholder) placeholder.style.display = 'none';
            const bigBtn = document.getElementById('aiimg-seed-big-btn');
            if (bigBtn) bigBtn.style.display = 'block';
            el('aiimg-crop-btn').disabled = false;
        };
        reader.readAsDataURL(file);
        ev.target.value = '';
        const analyzeBtn = document.getElementById('aiimg-analyze-btn');
        if (analyzeBtn) analyzeBtn.disabled = false;
    }
    function clearSeed() {
        _seedDataUrl = '';
        _seedAspectRatio = '';
        _analysisResult = { face: '', outfit: '' };
        const preview = el('aiimg-seed-preview');
        const placeholder = el('aiimg-seed-placeholder');
        if (preview) { preview.src = ''; preview.style.display = 'none'; }
        if (placeholder) placeholder.style.display = 'block';
        const bigBtn = document.getElementById('aiimg-seed-big-btn');
        if (bigBtn) bigBtn.style.display = 'none';
        el('aiimg-crop-btn').disabled = true;
        const analyzeBtn = document.getElementById('aiimg-analyze-btn');
        if (analyzeBtn) analyzeBtn.disabled = true;
        const analysisEl = document.getElementById('aiimg-analysis-text');
        if (analysisEl) analysisEl.textContent = '';
        const personCb = document.getElementById('aiimg-fix-person-cb');
        const outfitCb = document.getElementById('aiimg-fix-outfit-cb');
        if (personCb) personCb.checked = false;
        if (outfitCb) outfitCb.checked = false;
    }
    function setResultAsSeed() {
        if (_resultImages.length === 0) return;
        if (_virtualTryOnExtractedDataUrl && _resultImages[0] === _virtualTryOnExtractedDataUrl) {
            alert('Try-on 추출 이미지는 시드로 사용할 수 없습니다.');
            return;
        }
        _seedDataUrl = _resultImages[0];
        if (_virtualTryOnExtractedDataUrl && _seedDataUrl === _virtualTryOnExtractedDataUrl) return;
        _setSeedAspectRatio(_seedDataUrl);
        const preview = el('aiimg-seed-preview');
        const placeholder = el('aiimg-seed-placeholder');
        if (preview) { preview.src = _seedDataUrl; preview.style.display = 'block'; }
        if (placeholder) placeholder.style.display = 'none';
        const bigBtn = document.getElementById('aiimg-seed-big-btn');
        if (bigBtn) bigBtn.style.display = 'block';
        el('aiimg-crop-btn').disabled = false;
        const analyzeBtn = document.getElementById('aiimg-analyze-btn');
        if (analyzeBtn) analyzeBtn.disabled = false;
    }

    function openCropUpload() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'image/*';
        input.onchange = (ev) => {
            const file = ev.target.files[0];
            if (!file || !file.type.startsWith('image/')) return;
            const reader = new FileReader();
            reader.onload = () => _openCropPopup(reader.result);
            reader.readAsDataURL(file);
        };
        input.click();
    }
    function openCropEdit() {
        if (!_seedDataUrl) return;
        _openCropPopup(_seedDataUrl);
    }
    function openTryOnCropEdit() {
        if (!_virtualTryOnDataUrl) return;
        window._imgCropTarget = 'tryon';
        _openCropPopup(_virtualTryOnDataUrl);
    }
    function openTryOnExtractedCropEdit() {
        if (!_virtualTryOnExtractedDataUrl) return;
        window._imgCropTarget = 'tryon-extracted';
        _openCropPopup(_virtualTryOnExtractedDataUrl);
    }
    function openCropForResult(index) {
        const dataUrl = _resultImages[index];
        if (!dataUrl) return;
        window._imgCropTarget = 'result';
        window._cropResultIndex = index;
        _openCropPopup(dataUrl);
    }
    function openResultInNewWindow(dataUrl) {
        const w = window.open('', '_blank', 'width=800,height=700,scrollbars=yes');
        if (!w) return;
        const esc = (s) => (s || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');
        const html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>이미지 보기</title><style>body{margin:0;background:#1a1a2e;display:flex;flex-direction:column;min-height:100vh;align-items:center}.img-toolbar{flex-shrink:0;padding:8px;display:flex;gap:8px;align-items:center}.img-toolbar button{padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px;border:1px solid #4a4a6a;background:#2a2a3a;color:#e8e8f0}.img-toolbar button:hover{background:#3a3a4a}.img-wrap{flex:1;overflow:auto;display:flex;align-items:flex-start;justify-content:center;padding:12px;min-height:0}.img-wrap img{display:block}</style></head><body><div class="img-toolbar"><button type="button" id="zoomOut">축소</button><button type="button" id="zoomIn">확대</button><span id="zoomPct" style="color:#888;font-size:13px;min-width:60px">100%</span></div><div class="img-wrap" id="imgWrap"><img id="viewImg" src="' + esc(dataUrl) + '" alt=""></div><script>(function(){var img=document.getElementById("viewImg");var wrap=document.getElementById("imgWrap");var pct=document.getElementById("zoomPct");var scale=1;var nw,nh;function update(){if(nw&&nh){img.style.width=(nw*scale)+"px";img.style.height=(nh*scale)+"px";wrap.style.width=(nw*scale)+"px";wrap.style.height=(nh*scale)+"px";}pct.textContent=Math.round(scale*100)+"%";}img.onload=function(){nw=img.naturalWidth;nh=img.naturalHeight;update();};document.getElementById("zoomIn").onclick=function(){scale=Math.min(scale*1.25,5);update();};document.getElementById("zoomOut").onclick=function(){scale=Math.max(scale/1.25,0.2);update();};})();</script></body></html>';
        w.document.write(html);
        w.document.close();
    }
    function openSeedInNewWindow() {
        if (!_seedDataUrl) return;
        openResultInNewWindow(_seedDataUrl);
    }
    function openTryOnImageInNewWindow(type) {
        const imgEl = type === 'extracted' ? document.getElementById('aiimg-virtual-tryon-extracted-img') : document.querySelector('#aiimg-virtual-tryon-img');
        const src = imgEl && imgEl.src;
        if (!src || src === window.location.href) return;
        const w = window.open('', '_blank', 'width=800,height=700,scrollbars=yes');
        if (!w) return;
        w.document.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>이미지 보기</title><style>body{margin:0;background:#1a1a2e;display:flex;align-items:center;justify-content:center;min-height:100vh}</style></head><body><img src="' + src.replace(/"/g, '&quot;') + '" style="max-width:100%;max-height:100vh;object-fit:contain" alt=""></body></html>');
        w.document.close();
    }
    function cropCurrentResult() {
        if (_resultImages.length === 0) return;
        openCropForResult(0);
    }
    function openCurrentResultInNewWindow() {
        if (_resultImages.length === 0) return;
        openResultInNewWindow(_resultImages[0]);
    }
    function resetModal() {
        _seedDataUrl = '';
        _seedAspectRatio = '';
        _resultImages = [];
        _currentPrompt = '';
        _analysisResult = { face: '', outfit: '' };
        _virtualTryOnDataUrl = '';
        const preview = el('aiimg-seed-preview');
        const placeholder = el('aiimg-seed-placeholder');
        if (preview) { preview.src = ''; preview.style.display = 'none'; }
        if (placeholder) placeholder.style.display = 'block';
        const seedBigBtn = document.getElementById('aiimg-seed-big-btn');
        if (seedBigBtn) seedBigBtn.style.display = 'none';
        const cropBtn = document.getElementById('aiimg-crop-btn');
        if (cropBtn) cropBtn.disabled = true;
        if (el('aiimg-prompt')) el('aiimg-prompt').value = '';
        const centerCrop = document.getElementById('aiimg-center-crop-btn');
        const centerBig = document.getElementById('aiimg-center-big-btn');
        if (centerCrop) centerCrop.disabled = true;
        if (centerBig) centerBig.disabled = true;
        const rw = el('aiimg-result-wrap');
        const empty = el('aiimg-empty-result');
        if (rw) rw.style.display = 'none';
        if (empty) empty.style.display = 'flex';
        const wrap = el('aiimg-result-images');
        if (wrap) wrap.innerHTML = '';
        const analyzeBtn = document.getElementById('aiimg-analyze-btn');
        if (analyzeBtn) analyzeBtn.disabled = true;
        const analysisEl = document.getElementById('aiimg-analysis-text');
        if (analysisEl) analysisEl.textContent = '';
        const personCb = document.getElementById('aiimg-fix-person-cb');
        const outfitCb = document.getElementById('aiimg-fix-outfit-cb');
        if (personCb) personCb.checked = false;
        if (outfitCb) outfitCb.checked = false;
        clearVirtualTryOn();
    }
    function _openCropPopup(imageDataUrl) {
        const w = window.open('crop.html', 'crop', 'width=640,height=560,scrollbars=yes');
        if (!w) { alert('팝업이 차단되었습니다. 크롭 창을 허용해 주세요.'); return; }
        window._mdliveCropPending = imageDataUrl;
    }
    (function initCropMessage() {
        window.addEventListener('message', (ev) => {
            if (ev.data && ev.data.type === 'crop-ready') {
                const img = window._mdliveCropPending;
                window._mdliveCropPending = null;
                if (ev.source && !ev.source.closed && img) ev.source.postMessage({ type: 'crop', image: img }, '*');
                return;
            }
            if (!ev.data || ev.data.type !== 'aiimg-cropped' || !ev.data.dataUrl) return;
            if (window._imgCropTarget === 'tryon') {
                window._imgCropTarget = null;
                _virtualTryOnDataUrl = ev.data.dataUrl;
                const imgEl = document.getElementById('aiimg-virtual-tryon-img');
                if (imgEl) { imgEl.src = _virtualTryOnDataUrl; }
                return;
            }
            if (window._imgCropTarget === 'tryon-extracted') {
                window._imgCropTarget = null;
                _virtualTryOnExtractedDataUrl = ev.data.dataUrl;
                const imgEl = document.getElementById('aiimg-virtual-tryon-extracted-img');
                if (imgEl) { imgEl.src = _virtualTryOnExtractedDataUrl; imgEl.style.display = 'block'; }
                const loadingEl = document.getElementById('aiimg-virtual-tryon-extracted-loading');
                if (loadingEl) loadingEl.style.display = 'none';
                return;
            }
            if (window._imgCropTarget === 'result' && typeof window._cropResultIndex === 'number') {
                const idx = window._cropResultIndex;
                window._imgCropTarget = null;
                window._cropResultIndex = null;
                if (_resultImages[idx] !== undefined) {
                    _resultImages[idx] = ev.data.dataUrl;
                    _renderResult();
                }
                return;
            }
            if (window._imgCropTarget === 'insert') {
                window._imgCropTarget = null;
                const urlEl = el('img-url');
                if (urlEl) urlEl.value = ev.data.dataUrl;
                _showImgpv(ev.data.dataUrl);
                return;
            }
            if (_virtualTryOnExtractedDataUrl && ev.data.dataUrl === _virtualTryOnExtractedDataUrl) {
                alert('Try-on 추출 이미지는 시드로 사용할 수 없습니다.');
                return;
            }
            _seedDataUrl = ev.data.dataUrl;
            _setSeedAspectRatio(_seedDataUrl);
            const preview = el('aiimg-seed-preview');
            const placeholder = el('aiimg-seed-placeholder');
            if (preview) { preview.src = _seedDataUrl; preview.style.display = 'block'; }
            if (placeholder) placeholder.style.display = 'none';
            const bigBtn = document.getElementById('aiimg-seed-big-btn');
            if (bigBtn) bigBtn.style.display = 'block';
            const cropBtn = document.getElementById('aiimg-crop-btn');
            if (cropBtn) cropBtn.disabled = false;
            const analyzeBtn = document.getElementById('aiimg-analyze-btn');
            if (analyzeBtn) analyzeBtn.disabled = false;
        });
    })();

    function _renderResult() {
        const wrap = el('aiimg-result-images');
        if (!wrap) return;
        wrap.innerHTML = '';
        const rw = el('aiimg-result-wrap');
        const empty = el('aiimg-empty-result');
        if (_resultImages.length) {
            if (rw) rw.style.display = 'block';
            if (empty) empty.style.display = 'none';
            _resultImages.forEach((dataUrl, i) => {
                const wrapper = document.createElement('div');
                wrapper.style.cssText = 'position:relative;display:inline-block';
                const img = document.createElement('img');
                img.src = dataUrl;
                img.style.cssText = 'max-width:100%;max-height:400px;width:auto;object-fit:contain;border-radius:8px;border:1px solid var(--bd);cursor:pointer;display:block';
                img.title = '클릭: 다운로드 | 더블클릭: 크게 보기';
                img.dataset.index = String(i);
                img.onclick = (e) => {
                    if (e.detail === 2) {
                        openResultInNewWindow(dataUrl);
                        return;
                    }
                    const a = document.createElement('a');
                    a.href = dataUrl;
                    a.download = `aiimg-${Date.now()}-${i}.png`;
                    a.click();
                };
                wrapper.appendChild(img);
                wrap.appendChild(wrapper);
            });
            const centerCrop = document.getElementById('aiimg-center-crop-btn');
            const centerBig = document.getElementById('aiimg-center-big-btn');
            if (centerCrop) centerCrop.disabled = false;
            if (centerBig) centerBig.disabled = false;
        } else {
            if (rw) rw.style.display = 'none';
            if (empty) empty.style.display = 'flex';
            const centerCrop = document.getElementById('aiimg-center-crop-btn');
            const centerBig = document.getElementById('aiimg-center-big-btn');
            if (centerCrop) centerCrop.disabled = true;
            if (centerBig) centerBig.disabled = true;
        }
    }

    async function generate() {
        if (_busy) return;
        const promptEl = el('aiimg-prompt');
        let prompt = promptEl ? promptEl.value.trim() : '';
        if (!prompt) { alert('프롬프트를 입력하세요.'); return; }
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) { alert('AI API 키를 설정에서 입력해 주세요.'); return; }
        const textModelEl = el('aiimg-text-model');
        const textModelId = textModelEl && textModelEl.value ? textModelEl.value.trim() : '';
        if (textModelId) {
            try {
                const refineUrl = `https://generativelanguage.googleapis.com/v1beta/models/${textModelId}:generateContent?key=${encodeURIComponent(key)}`;
                const refineBody = {
                    contents: [{
                        role: 'user',
                        parts: [{ text: `다음 사용자 요청을 이미지 생성 AI에 전달할 수 있도록, 구체적이고 시각적으로 묘사된 단일 프롬프트로만 변환해 주세요. 다른 설명이나 접두사 없이 변환된 프롬프트 한 개만 출력하세요.\n\n사용자 요청:\n${prompt}` }]
                    }],
                    generationConfig: { temperature: 0.4, maxOutputTokens: 1024 }
                };
                const refineRes = await fetch(refineUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(refineBody),
                    signal: AbortSignal.timeout(30000)
                });
                const refineData = await refineRes.json();
                if (refineRes.ok && refineData.candidates?.[0]?.content?.parts?.[0]?.text) {
                    const enhanced = String(refineData.candidates[0].content.parts[0].text).trim();
                    if (enhanced) prompt = enhanced;
                }
            } catch (e) {
                console.warn('텍스트 모델 프롬프트 보강 실패, 원본 사용:', e);
            }
        }
        const modelId = (el('aiimg-model') && el('aiimg-model').value) || 'gemini-2.0-flash-exp-image-generation';
        _busy = true;
        _currentPrompt = prompt;
        const loadingEl = el('aiimg-loading');
        if (loadingEl) loadingEl.style.display = 'block';
        el('aiimg-generate-btn').disabled = true;
        _setProgress(0);
        let progressInterval = setInterval(() => {
            const pctEl = document.getElementById('aiimg-progress-pct');
            if (!pctEl) return;
            const current = parseInt(pctEl.textContent, 10) || 0;
            if (current >= 90) return;
            _setProgress(Math.min(current + 5, 90));
        }, 500);
        const contents = [];
        if (_seedDataUrl) {
            const base64 = _seedDataUrl.replace(/^data:image\/\w+;base64,/, '');
            const mime = _seedDataUrl.match(/^data:(image\/\w+);/);
            contents.push({
                inlineData: { mimeType: mime ? mime[1] : 'image/png', data: base64 }
            });
        }
        contents.push({ text: prompt });
        const promptHasRatio = /비율|\d+\s*:\s*\d+/.test(prompt);
        let aspectHint = '';
        if (!promptHasRatio && _seedAspectRatio) aspectHint = '\n[이미지 비율: ' + _seedAspectRatio + '로 생성해 주세요.]';
        contents[contents.length - 1].text = prompt + aspectHint;
        const personCb = document.getElementById('aiimg-fix-person-cb');
        const outfitCb = document.getElementById('aiimg-fix-outfit-cb');
        let prefix = '';
        if (personCb && personCb.checked && _analysisResult.face) {
            prefix += '[인물 고정 - 아래 특징 유지]\n' + _analysisResult.face + '\n\n';
        }
        if (outfitCb && outfitCb.checked && _analysisResult.outfit) {
            prefix += '[복장 고정 - 아래 의상 유지]\n' + _analysisResult.outfit + '\n\n';
        }
        if (prefix) contents[contents.length - 1].text = prefix + contents[contents.length - 1].text;
        const useOrigin = document.getElementById('aiimg-tryon-ref-origin') && document.getElementById('aiimg-tryon-ref-origin').checked;
        const tryOnDataUrl = useOrigin ? _virtualTryOnDataUrl : _virtualTryOnExtractedDataUrl;
        if (tryOnDataUrl) {
            const vbase64 = tryOnDataUrl.replace(/^data:image\/\w+;base64,/, '');
            const vmime = tryOnDataUrl.match(/^data:(image\/\w+);/);
            contents.push({
                inlineData: { mimeType: vmime ? vmime[1] : 'image/png', data: vbase64 }
            });
            contents.push({ text: useOrigin ? '위 이미지를 참고하여 생성해 주세요.' : '위 옷/스타일을 적용한 이미지로 생성해 주세요.' });
        }
        const body = {
            contents: [{ role: 'user', parts: contents }],
            generationConfig: {
                responseModalities: ['TEXT', 'IMAGE'],
                responseMimeType: 'text/plain'
            }
        };
        try {
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(key)}`;
            const r = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
                signal: AbortSignal.timeout(120000)
            });
            const data = await r.json();
            if (!r.ok) throw new Error(data.error?.message || `HTTP ${r.status}`);
            const parts = data.candidates?.[0]?.content?.parts || [];
            const newImages = [];
            parts.forEach(p => {
                if (p.inlineData && p.inlineData.data) {
                    const mime = p.inlineData.mimeType || 'image/png';
                    newImages.push('data:' + mime + ';base64,' + p.inlineData.data);
                }
            });
            if (newImages.length > 0) {
                _resultImages = newImages;
                _renderResult();
                const record = {
                    id: 'aiimg-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9),
                    prompt,
                    imageData: newImages,
                    createdAt: Date.now()
                };
                await _add(record);
                _historyCache.unshift(record);
                _renderHistory();
            } else {
                _resultImages = [];
                _renderResult();
                alert('이미지가 생성되지 않았습니다. 다른 모델이나 프롬프트를 시도해 보세요.');
            }
        } catch (e) {
            _resultImages = [];
            _renderResult();
            alert('오류: ' + (e.message || String(e)));
        } finally {
            _busy = false;
            clearInterval(progressInterval);
            _setProgress(100);
            setTimeout(() => {
                const loadingEl = el('aiimg-loading');
                if (loadingEl) loadingEl.style.display = 'none';
                _setProgress(0);
            }, 400);
            el('aiimg-generate-btn').disabled = false;
        }
    }
    function _setProgress(pct) {
        const pctEl = document.getElementById('aiimg-progress-pct');
        const barEl = document.getElementById('aiimg-progress-bar');
        if (pctEl) pctEl.textContent = pct + '%';
        if (barEl) barEl.style.width = pct + '%';
    }

    function _renderHistory() {
        const list = el('aiimg-history-list');
        if (!list) return;
        list.textContent = '';
        list.removeAttribute('data-empty');
        if (!_historyCache.length) {
            list.setAttribute('data-empty', '생성된 이미지가 여기에 저장됩니다.');
            return;
        }
        _historyCache.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
        _historyCache.forEach(item => {
            const div = document.createElement('div');
            div.className = 'dr-history-item';
            div.style.cssText = 'padding:6px;margin-bottom:6px;border-radius:6px;border:1px solid var(--bd);cursor:pointer;background:var(--bg4);position:relative';
            const delBtn = document.createElement('button');
            delBtn.type = 'button';
            delBtn.className = 'btn btn-g btn-sm';
            delBtn.style.cssText = 'position:absolute;top:4px;left:4px;font-size:10px;padding:2px 6px;z-index:2';
            delBtn.textContent = '×';
            delBtn.title = '이 항목 삭제';
            delBtn.onclick = (e) => { e.stopPropagation(); removeHistoryItem(item.id); };
            const row = document.createElement('div');
            row.style.cssText = 'display:flex;align-items:flex-start;gap:6px';
            const thumbWrap = document.createElement('div');
            thumbWrap.style.cssText = 'flex:1;min-width:0;height:72px;background:var(--bg3);border-radius:4px;overflow:hidden;display:flex;align-items:center;justify-content:center';
            const img = document.createElement('img');
            img.src = Array.isArray(item.imageData) && item.imageData[0] ? item.imageData[0] : '';
            img.style.cssText = 'max-width:100%;max-height:100%;width:auto;height:auto;object-fit:contain;display:block';
            const cap = document.createElement('div');
            cap.style.cssText = 'font-size:10px;color:var(--tx3);margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
            cap.textContent = (item.prompt || '').slice(0, 24) + (item.prompt && item.prompt.length > 24 ? '…' : '');
            thumbWrap.appendChild(img);
            const col = document.createElement('div');
            col.style.cssText = 'flex:1;min-width:0';
            col.appendChild(thumbWrap);
            col.appendChild(cap);
            row.appendChild(col);
            div.appendChild(delBtn);
            div.appendChild(row);
            div.onclick = () => {
                _resultImages = Array.isArray(item.imageData) ? [...item.imageData] : [];
                _currentPrompt = item.prompt || '';
                if (el('aiimg-prompt')) el('aiimg-prompt').value = _currentPrompt;
                _renderResult();
            };
            list.appendChild(div);
        });
    }
    async function loadHistory() {
        try {
            _historyCache = await _getAll();
        } catch (_) {
            _historyCache = [];
        }
        _renderHistory();
    }
    async function clearAllHistory() {
        if (!_historyCache.length) return;
        if (!confirm('히스토리를 모두 삭제할까요?')) return;
        try {
            await _clearAll();
            _historyCache = [];
            _renderHistory();
        } catch (e) {
            alert('삭제 실패: ' + (e.message || String(e)));
        }
    }
    async function removeHistoryItem(id) {
        try {
            await _delete(id);
            _historyCache = _historyCache.filter(item => item.id !== id);
            _renderHistory();
        } catch (e) {
            alert('삭제 실패: ' + (e.message || String(e)));
        }
    }

    function downloadAll() {
        _resultImages.forEach((dataUrl, i) => {
            const a = document.createElement('a');
            a.href = dataUrl;
            a.download = `aiimg-${Date.now()}-${i}.png`;
            a.click();
        });
    }
    function downloadZip() {
        if (typeof JSZip === 'undefined') { alert('ZIP 라이브러리를 불러올 수 없습니다.'); return; }
        const zip = new JSZip();
        _resultImages.forEach((dataUrl, i) => {
            const base64 = dataUrl.replace(/^data:image\/\w+;base64,/, '');
            zip.file(`aiimg-${i + 1}.png`, base64, { base64: true });
        });
        zip.generateAsync({ type: 'blob' }).then(blob => {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `aiimg-${Date.now()}.zip`;
            a.click();
            URL.revokeObjectURL(a.href);
        });
    }
    function downloadProject() {
        if (typeof JSZip === 'undefined') { alert('ZIP 라이브러리를 불러올 수 없습니다.'); return; }
        const project = {
            version: 1,
            prompt: _currentPrompt,
            modelId: (el('aiimg-model') && el('aiimg-model').value) || '',
            seedImage: _seedDataUrl || null,
            results: _resultImages.map((dataUrl, i) => ({ index: i, data: dataUrl })),
            createdAt: Date.now()
        };
        const zip = new JSZip();
        zip.file('project.json', JSON.stringify(project, null, 2));
        _resultImages.forEach((dataUrl, i) => {
            const base64 = dataUrl.replace(/^data:image\/\w+;base64,/, '');
            zip.file(`image-${i + 1}.png`, base64, { base64: true });
        });
        zip.generateAsync({ type: 'blob' }).then(blob => {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `aiimg-project-${Date.now()}.mdp`;
            a.click();
            URL.revokeObjectURL(a.href);
        });
    }

    function insertToEditor() {
        const dataUrl = _resultImages[0];
        if (!dataUrl) { alert('삽입할 결과 이미지가 없습니다.'); return; }
        const ed = typeof ED !== 'undefined' && ED.ed ? ED.ed() : null;
        if (!ed) { alert('에디터를 찾을 수 없습니다.'); return; }
        const alt = 'AI 이미지';
        const s = ed.selectionStart, e = ed.selectionEnd;
        ins(ed, s, e, `![${alt}](${dataUrl})`);
        if (typeof ImgStore !== 'undefined') ImgStore.save(dataUrl, alt);
        if (typeof App !== 'undefined' && App.render) App.render();
        if (typeof US !== 'undefined' && US.snap) US.snap();
    }
    function insertToNewFile() {
        const dataUrl = _resultImages[0];
        if (!dataUrl) { alert('삽입할 결과 이미지가 없습니다.'); return; }
        const title = '이미지-' + new Date().toISOString().slice(0, 10);
        if (typeof TM !== 'undefined' && TM.newTab) TM.newTab(title, `![AI 이미지](${dataUrl})`, 'md');
        if (typeof ImgStore !== 'undefined') ImgStore.save(dataUrl, 'AI 이미지');
    }
    function insertSeedToEditor() {
        if (!_seedDataUrl) { alert('삽입할 시드 이미지가 없습니다.'); return; }
        const ed = typeof ED !== 'undefined' && ED.ed ? ED.ed() : null;
        if (!ed) { alert('에디터를 찾을 수 없습니다.'); return; }
        const alt = '시드 이미지';
        const s = ed.selectionStart, e = ed.selectionEnd;
        ins(ed, s, e, `![${alt}](${_seedDataUrl})`);
        if (typeof ImgStore !== 'undefined') ImgStore.save(_seedDataUrl, alt);
        if (typeof App !== 'undefined' && App.render) App.render();
        if (typeof US !== 'undefined' && US.snap) US.snap();
    }
    function insertSeedToNewFile() {
        if (!_seedDataUrl) { alert('삽입할 시드 이미지가 없습니다.'); return; }
        const title = '이미지-' + new Date().toISOString().slice(0, 10);
        if (typeof TM !== 'undefined' && TM.newTab) TM.newTab(title, `![시드 이미지](${_seedDataUrl})`, 'md');
        if (typeof ImgStore !== 'undefined') ImgStore.save(_seedDataUrl, '시드 이미지');
    }
    function insertAnalysisToEditor() {
        const analysisEl = document.getElementById('aiimg-analysis-text');
        const text = (analysisEl && analysisEl.textContent || '').trim();
        if (!text) { alert('삽입할 분석 결과가 없습니다.'); return; }
        const ed = typeof ED !== 'undefined' && ED.ed ? ED.ed() : null;
        if (!ed) { alert('에디터를 찾을 수 없습니다.'); return; }
        const s = ed.selectionStart, e = ed.selectionEnd;
        ins(ed, s, e, '\n\n' + text + '\n\n');
        if (typeof App !== 'undefined' && App.render) App.render();
        if (typeof US !== 'undefined' && US.snap) US.snap();
    }

    return {
        switchTab, toggleMaximize, applyPreset, applyMenuType, sendAnalysisToPrompt, onSeedFile, clearSeed,
        openCropUpload, openCropEdit, openTryOnCropEdit, openTryOnExtractedCropEdit,
        generate, setResultAsSeed, downloadAll, downloadZip, downloadProject, loadHistory,
        insertToEditor, insertToNewFile, insertSeedToEditor, insertSeedToNewFile, insertAnalysisToEditor,
        resetModal, clearAllHistory, removeHistoryItem,
        cropCurrentResult, openCurrentResultInNewWindow, openSeedInNewWindow,
        analyzeSeedImage, onVirtualTryOnFile, clearVirtualTryOn, extractClothingForTryOn, openTryOnImageInNewWindow
    };
})();
window.AiImage = AiImage;

let lastCodeLang = 'python';// track last used language for Alt+C

const ED = {
    ed() { return el('editor') },
    h(lv) { const ed = this.ed(); repCL(ed, '#'.repeat(lv) + ' ' + getCL(ed).text.replace(/^#+\s*/, '')) },
    bold() {
        const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd, sel = ed.value.substring(s, e);
        if (!sel) { ins(ed, s, e, '**텍스트**'); ed.setSelectionRange(s + 2, s + 5); return }
        const b2 = ed.value.substring(s - 2, s), a2 = ed.value.substring(e, e + 2);
        if (b2 === '**' && a2 === '**') { ed.value = ed.value.substring(0, s - 2) + sel + ed.value.substring(e + 2); ed.setSelectionRange(s - 2, e - 2); App.render(); US.snap(); return }
        const b3 = ed.value.substring(s - 3, s), a4 = ed.value.substring(e, e + 4);
        if (b3 === '<b>' && a4 === '</b>') { ed.value = ed.value.substring(0, s - 3) + sel + ed.value.substring(e + 4); ed.setSelectionRange(s - 3, e - 3); App.render(); US.snap(); return }
        const w = /[()[\]{}<>]/.test(sel) ? `<b>${sel}</b>` : `**${sel}**`;
        ins(ed, s, e, w); ed.setSelectionRange(s, s + w.length);
    },
    italic() { const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd, sel = ed.value.substring(s, e) || '텍스트'; const b = ed.value.substring(s - 1, s), a = ed.value.substring(e, e + 1); if (b === '*' && a === '*') { ed.value = ed.value.substring(0, s - 1) + sel + ed.value.substring(e + 1); ed.setSelectionRange(s - 1, s - 1 + sel.length); App.render() } else ins(ed, s, e, `*${sel}*`) },
    strike() { const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd; ins(ed, s, e, `~~${ed.value.substring(s, e) || '텍스트'}~~`) },
    inlineCode() { const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd; ins(ed, s, e, `\`${ed.value.substring(s, e) || 'code'}\``) },
    fontSize(size) { if (!size) return; const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd, sel = ed.value.substring(s, e) || '텍스트'; ins(ed, s, e, `<span style="font-size:${size}">${sel}</span>`) },
    align(dir) { const ed = this.ed(); const { text } = getCL(ed); const c = text.replace(/<div[^>]*>(.*?)<\/div>/gi, '$1'); repCL(ed, dir === 'left' ? c : `<div style="text-align:${dir}">${c}</div>`) },
    textToList() {
        const ed = this.ed();
        if (!ed) return;
        const val = ed.value;
        const ss  = ed.selectionStart;
        const se  = ed.selectionEnd;
        if (ss === se) {
            /* 선택 없음 → 현재 줄 토글 */
            const ls = val.lastIndexOf('\n', ss - 1) + 1;
            const nlPos = val.indexOf('\n', ls);
            const lineEnd = nlPos === -1 ? val.length : nlPos;
            const line = val.slice(ls, lineEnd);
            if (line.match(/^[-*+]\s/) || line.match(/^\d+\.\s/)) {
                ed.setRangeText(line.replace(/^([-*+]\s|\d+\.\s)/, ''), ls, lineEnd, 'start');
            } else {
                ed.setRangeText('- ', ls, ls, 'start');
            }
        } else {
            /* 선택 있음 → 선택한 텍스트 전체를 줄 단위로 나누어 각 줄에 "- " 토글 */
            const block = val.substring(ss, se);
            const lines = block.split('\n');
            const allList = lines.every(l => l.match(/^[-*+]\s/) || l.match(/^\d+\.\s/) || l.trim() === '');
            const newBlock = allList
                ? lines.map(l => l.replace(/^([-*+]\s|\d+\.\s)/, '')).join('\n')
                : lines.map(l => l.trim() === '' ? l : (l.match(/^[-*+]\s/) || l.match(/^\d+\.\s/) ? l : '- ' + l)).join('\n');
            ed.setRangeText(newBlock, ss, se, 'select');
        }
        US.snap(); TM.markDirty(); App.render();
    },
    textToNumberedList() {
        const ed = this.ed();
        if (!ed) return;
        const val = ed.value;
        const ss = ed.selectionStart;
        const se = ed.selectionEnd;
        if (ss === se) {
            const ls = val.lastIndexOf('\n', ss - 1) + 1;
            const nlPos = val.indexOf('\n', ls);
            const lineEnd = nlPos === -1 ? val.length : nlPos;
            const line = val.slice(ls, lineEnd);
            if (line.match(/^\d+\.\s/)) {
                ed.setRangeText(line.replace(/^\d+\.\s/, ''), ls, lineEnd, 'start');
            } else {
                ed.setRangeText('1. ', ls, ls, 'start');
            }
        } else {
            const block = val.substring(ss, se);
            const lines = block.split('\n');
            const allNumbered = lines.every(l => l.match(/^\d+\.\s/) || l.trim() === '');
            const newBlock = allNumbered
                ? lines.map(l => l.replace(/^\d+\.\s/, '')).join('\n')
                : lines.map((l, i) => l.trim() === '' ? l : (l.match(/^\d+\.\s/) ? l : (i + 1) + '. ' + l)).join('\n');
            ed.setRangeText(newBlock, ss, se, 'select');
        }
        US.snap(); TM.markDirty(); App.render();
    },
        list(type) { const ed = this.ed(), s = ed.selectionStart; const p = type === 'ul' ? '- ' : '1. '; ins(ed, s, s, `\n${p}항목 1\n${p}항목 2\n${p}항목 3\n`) },
    bquote() { const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd, sel = ed.value.substring(s, e); if (sel) ins(ed, s, e, sel.split('\n').map(l => '> ' + l).join('\n')); else ins(ed, s, s, '\n> 인용문을 입력하세요\n') },
    table() { const ed = this.ed(), s = ed.selectionStart; ins(ed, s, s, '\n| 헤더 1 | 헤더 2 | 헤더 3 |\n| :-- | :-- | :-- |\n| 셀 | 셀 | 셀 |\n| 셀 | 셀 | 셀 |\n') },
    tableRow() { const ed = this.ed(), val = ed.value, pos = ed.selectionStart; const le = val.indexOf('\n', pos), ln = val.substring(val.lastIndexOf('\n', pos - 1) + 1, le === -1 ? val.length : le); if (!ln.trim().startsWith('|')) { this.table(); return } const cols = ln.split('|').filter(c => c.trim() !== '').length; ins(ed, le === -1 ? val.length : le, le === -1 ? val.length : le, '\n|' + ' 셀 |'.repeat(cols)) },
    tableCol() { const ed = this.ed(), lines = ed.value.split('\n'); const cur = ed.value.substring(0, ed.selectionStart).split('\n').length - 1; if (!lines[cur].trim().startsWith('|')) { this.table(); return } let s = cur, e2 = cur; while (s > 0 && lines[s - 1].trim().startsWith('|')) s--; while (e2 < lines.length - 1 && lines[e2 + 1].trim().startsWith('|')) e2++; ed.value = lines.map((l, i) => { if (i < s || i > e2 || !l.trim().startsWith('|')) return l; return /^\|[\s:|-]+\|$/.test(l.trim()) ? l.trimEnd() + ' :-- |' : l.trimEnd() + ' 새열 |' }).join('\n'); App.render(); US.snap() },

    /* ── 셀 병합 시스템 (MD 표 + HTML 표 모두 지원, 반복 병합 가능) ── */

    _getMdTable(ed) {
        const lines = ed.value.split('\n');
        const cur = ed.value.substring(0, ed.selectionStart).split('\n').length - 1;
        if (!lines[cur].trim().startsWith('|')) return null;
        let s = cur, e2 = cur;
        while (s > 0 && lines[s - 1].trim().startsWith('|')) s--;
        while (e2 < lines.length - 1 && lines[e2 + 1].trim().startsWith('|')) e2++;
        let sepIdx = -1;
        for (let i = s; i <= e2; i++) { if (/^\|[\s:|-]+\|$/.test(lines[i].trim())) { sepIdx = i; break; } }
        return { lines, start: s, end: e2, cur, sep: sepIdx };
    },

    _parseCells(line) {
        return line.split('|').slice(1, -1).map(c => c.trim());
    },

    _getCursorCell(ed) {
        const val = ed.value, pos = ed.selectionStart;
        const ls = val.lastIndexOf('\n', pos - 1) + 1;
        const part = val.substring(ls, pos);
        return Math.max(0, part.split('|').length - 2);
    },

    /* HTML 표 파싱: DOMParser로 기존 colspan/rowspan 유지하며 재파싱 */
    _getHTMLTable(ed) {
        const val = ed.value, pos = ed.selectionStart;
        const before = val.substring(0, pos);
        const tStart = before.lastIndexOf('<table');
        if (tStart === -1) return null;
        const tEnd = val.indexOf('</table>', tStart);
        if (tEnd === -1) return null;
        const tableHTML = val.substring(tStart, tEnd + 8);
        const doc = new DOMParser().parseFromString('<body>' + tableHTML + '</body>', 'text/html');
        const table = doc.querySelector('table');
        if (!table) return null;
        const trs = [...table.querySelectorAll('tr')];
        if (!trs.length) return null;
        // 최대 열 수 계산
        const cols = trs.reduce((mx, tr) => {
            let n = 0;[...tr.cells].forEach(c => n += c.colSpan || 1); return Math.max(mx, n);
        }, 0);
        const rows = trs.length;
        // cells[r][c] = {text,cs,rs,skip}
        const cells = Array.from({ length: rows }, () => Array(cols).fill(null));
        const occupied = Array.from({ length: rows }, () => Array(cols).fill(false));
        trs.forEach((tr, r) => {
            let gc = 0;
            [...tr.cells].forEach(td => {
                while (gc < cols && occupied[r][gc]) gc++;
                const cs = td.colSpan || 1, rs = td.rowSpan || 1;
                cells[r][gc] = { text: td.innerHTML.trim(), cs, rs, skip: false };
                for (let dr = 0; dr < rs; dr++)for (let dc = 0; dc < cs; dc++) {
                    if (r + dr < rows && gc + dc < cols) {
                        occupied[r + dr][gc + dc] = true;
                        if (dr > 0 || dc > 0) cells[r + dr][gc + dc] = { text: '', cs: 1, rs: 1, skip: true };
                    }
                }
                gc += cs;
            });
        });
        // 빈 셀 보정
        for (let r = 0; r < rows; r++)for (let c = 0; c < cols; c++) {
            if (!cells[r][c]) cells[r][c] = { text: '', cs: 1, rs: 1, skip: false };
        }
        // 커서 위치 → rowIdx, curCol 계산
        const posInTable = pos - tStart;
        const sliced = tableHTML.substring(0, posInTable);
        const rowIdx = Math.max(0, (sliced.match(/<tr[\s>]/gi) || []).length - 1);
        const tdIdx = Math.max(0, (sliced.match(/<t[dh][\s>]/gi) || []).length - 1);
        // tdIdx번째 실제 td/th가 그리드의 몇 번 열인지
        let gc2 = 0, counted = 0, curCol = 0;
        if (trs[rowIdx]) {
            for (const td of trs[rowIdx].cells) {
                while (gc2 < cols && occupied[rowIdx] && rowIdx > 0 && cells[rowIdx][gc2]?.skip) gc2++;
                if (counted === tdIdx) { curCol = gc2; break; }
                gc2 += td.colSpan || 1; counted++;
            }
        }

        return { cells, rows, cols, rowIdx, curCol, tStart, tEnd: tEnd + 8, val };
    },

    _renderHTMLTable(cells, rows, cols) {
        let html = '\n<table>\n<thead>\n<tr>';
        for (let c = 0; c < cols; c++) {
            const cell = cells[0]?.[c]; if (!cell || cell.skip) continue;
            const cs = cell.cs > 1 ? ` colspan="${cell.cs}"` : ''
            const rs = cell.rs > 1 ? ` rowspan="${cell.rs}"` : ''
            html += `<th${cs}${rs}>${cell.text}</th>`;
        }
        html += '</tr>\n</thead>\n<tbody>';
        for (let r = 1; r < rows; r++) {
            html += '\n<tr>';
            for (let c = 0; c < cols; c++) {
                const cell = cells[r]?.[c]; if (!cell || cell.skip) continue;
                const cs = cell.cs > 1 ? ` colspan="${cell.cs}"` : ''
                const rs = cell.rs > 1 ? ` rowspan="${cell.rs}"` : ''
                html += `<td${cs}${rs}>${cell.text}</td>`;
            }
            html += '</tr>';
        }
        html += '\n</tbody>\n</table>\n';
        return html;
    },

    /* 공통 병합 실행: MD 표 → HTML 변환, HTML 표 → 직접 파싱 후 재병합 */
    _doMerge(dir) {
        const ed = this.ed();
        // ① HTML 표 우선 시도
        const htbl = this._getHTMLTable(ed);
        if (htbl) {
            const { cells, rows, cols, rowIdx, curCol, tStart, tEnd, val } = htbl;
            const cell = cells[rowIdx]?.[curCol];
            if (!cell || cell.skip) { alert('이미 병합된 셀이거나 유효하지 않은 위치입니다.\n셀 텍스트 위에 커서를 놓고 실행하세요.'); return; }
            if (dir === 'h') {
                const nc = curCol + cell.cs;
                if (nc >= cols) { alert('오른쪽에 병합할 셀이 없습니다.'); return; }
                const right = cells[rowIdx][nc];
                if (!right || right.skip) { alert('오른쪽 셀이 이미 병합 중입니다.'); return; }
                cell.text = (cell.text + (right.text ? ' ' + right.text : '')).trim();
                cell.cs += right.cs;
                for (let cc = curCol + 1; cc < curCol + cell.cs; cc++)if (cells[rowIdx][cc]) cells[rowIdx][cc].skip = true;
            } else {
                const nr = rowIdx + cell.rs;
                if (nr >= rows) { alert('아래에 병합할 셀이 없습니다.'); return; }
                const below = cells[nr]?.[curCol];
                if (!below || below.skip) { alert('아래 셀이 이미 병합 중입니다.'); return; }
                cell.text = (cell.text + (below.text ? ' ' + below.text : '')).trim();
                cell.rs += below.rs;
                for (let rr = rowIdx + 1; rr < rowIdx + cell.rs; rr++)if (cells[rr]?.[curCol]) cells[rr][curCol].skip = true;
            }
            const newHTML = this._renderHTMLTable(cells, rows, cols);
            ed.value = val.substring(0, tStart) + newHTML + val.substring(tEnd);
            App.render(); US.snap();
            return;
        }
        // ② Markdown 표 처리
        const tbl = this._getMdTable(ed);
        if (!tbl) { alert('커서를 표 안에 놓고 실행하세요.'); return; }
        const { lines, start, end, cur, sep } = tbl;
        const col = this._getCursorCell(ed);
        const allRows = [];
        for (let i = start; i <= end; i++) { if (i !== sep) allRows.push(this._parseCells(lines[i])); }
        if (allRows.length < 2) return;
        const cols2 = allRows[0].length;
        const cells2 = allRows.map(row => row.map(t => ({ text: t || '', cs: 1, rs: 1, skip: false })));
        const dataLines = [];
        for (let i = start; i <= end; i++) { if (i !== sep) dataLines.push(i); }
        const rowIdx2 = dataLines.indexOf(cur);
        if (rowIdx2 < 0) { alert('커서를 표 셀 안에 놓고 실행하세요.'); return; }
        if (dir === 'h') {
            if (col >= cols2 - 1) { alert('오른쪽에 병합할 셀이 없습니다.'); return; }
            const c1 = cells2[rowIdx2][col], c2 = cells2[rowIdx2][col + 1];
            c1.text = (c1.text + (c2.text ? ' ' + c2.text : '')).trim(); c1.cs = 2; c2.skip = true;
        } else {
            if (rowIdx2 >= allRows.length - 1) { alert('아래에 병합할 셀이 없습니다.'); return; }
            const c1 = cells2[rowIdx2][col], c2 = cells2[rowIdx2 + 1][col];
            c1.text = (c1.text + (c2.text ? ' ' + c2.text : '')).trim(); c1.rs = 2; c2.skip = true;
        }
        const bef = lines.slice(0, start).join('\n');
        const aft = lines.slice(end + 1).join('\n');
        ed.value = (bef ? (bef + '\n') : '') + this._renderHTMLTable(cells2, allRows.length, cols2) + (aft ? ('\n' + aft) : '');
        App.render(); US.snap();
    },

    mergeH() { this._doMerge('h'); },
    mergeV() { this._doMerge('v'); },

    /* HTML 표를 들여쓰기가 잘 된 형태로 정돈 */
    tidyTable() {
        const ed = this.ed();
        const htbl = this._getHTMLTable(ed);
        if (!htbl) { alert('커서를 HTML 표 안에 놓고 Tidy를 실행하세요.\n(병합이 있는 HTML 표에서 사용합니다.)'); return; }
        const { cells, rows, cols, tStart, tEnd, val } = htbl;

        // 들여쓰기 정돈된 HTML 생성
        function tidyCell(tag, cell, indent) {
            const attrs = [];
            if (cell.rs > 1) attrs.push(`rowspan="${cell.rs}"`);
            if (cell.cs > 1) attrs.push(`colspan="${cell.cs}"`);
            const attrStr = attrs.length ? ' ' + attrs.join(' ') : '';
            return `${indent}<${tag}${attrStr}>${cell.text}</${tag}>`;
        }

        const lines = [];
        lines.push('<table>');

        // thead: 첫 번째 행
        lines.push('  <thead>');
        lines.push('    <tr>');
        for (let c = 0; c < cols; c++) {
            const cell = cells[0]?.[c];
            if (!cell || cell.skip) continue;
            lines.push(tidyCell('th', cell, '      '));
        }
        lines.push('    </tr>');
        lines.push('  </thead>');

        // tbody: 나머지 행
        lines.push('  <tbody>');
        for (let r = 1; r < rows; r++) {
            lines.push('    <tr>');
            for (let c = 0; c < cols; c++) {
                const cell = cells[r]?.[c];
                if (!cell || cell.skip) continue;
                lines.push(tidyCell('td', cell, '      '));
            }
            lines.push('    </tr>');
        }
        lines.push('  </tbody>');
        lines.push('</table>');

        const newHTML = '\n' + lines.join('\n') + '\n';
        ed.value = val.substring(0, tStart) + newHTML + val.substring(tEnd);
        App.render(); US.snap();
    },

    // 언어별 주석 기호 반환  // 언어별 주석 기호 반환
    _cmt(lang) {
        const hash = ['python', 'r', 'ruby', 'bash', 'shell', 'sh', 'perl', 'yaml', 'toml', 'powershell', 'coffee'];
        const dash = ['sql', 'haskell', 'lua', 'ada'];
        const pct = ['matlab', 'latex', 'tex'];
        const semi = ['lisp', 'clojure', 'scheme'];
        const html = ['html', 'xml', 'markdown', 'md'];
        const l = lang.toLowerCase();
        if (hash.some(x => l.startsWith(x))) return '#';
        if (dash.some(x => l.startsWith(x))) return '--';
        if (pct.some(x => l.startsWith(x))) return '%';
        if (semi.some(x => l.startsWith(x))) return ';';
        if (html.some(x => l.startsWith(x))) return '<!--';
        return '//';// js, ts, java, c, cpp, go, swift, kotlin, rust, …
    },
    // Direct code block with last used language (for Alt+C hotkey)
    codeBlockDirect() {
        const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd;
        const cmt = this._cmt(lastCodeLang);
        const placeholder = cmt === '<!--' ? `<!-- 코드 입력 -->` : cmt + ' 코드 입력';
        const sel = ed.value.substring(s, e) || placeholder;
        ins(ed, s, e, `\n\`\`\`${lastCodeLang}\n${sel}\n\`\`\`\n`);
    },
    // Code block from modal (toolbar ⌨ button)
    codeBlockModal() {
        const lang = el('code-lang').value; lastCodeLang = lang || lastCodeLang;
        const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd;
        const cmt = this._cmt(lastCodeLang);
        const placeholder = cmt === '<!--' ? `<!-- 코드 입력 -->` : cmt + ' 코드 입력';
        const sel = ed.value.substring(s, e) || placeholder;
        ins(ed, s, e, `\n\`\`\`${lastCodeLang}\n${sel}\n\`\`\`\n`);
        App.hideModal('code-modal');
    },
    pageBreak() { const ed = this.ed(), s = ed.selectionStart; ins(ed, s, s, '\n\n<div class="page-break"></div>\n\n') },
    lineBreak() { const ed = this.ed(), s = ed.selectionStart; ins(ed, s, s, '<br>\n') },
    insertNbsp() { const ed = this.ed(); if (!ed) return; const s = ed.selectionStart, e = ed.selectionEnd; ins(ed, s, e, '&nbsp;'); US.snap(); },
    link() { const text = el('link-text').value || '링크'; const url = el('link-url').value || '#'; const ed = this.ed(), s = ed.selectionStart; ins(ed, s, s, `[${text}](${url})`); App.hideModal('link-modal'); el('link-text').value = ''; el('link-url').value = '' },
    image() { const alt = el('img-alt').value || '이미지'; const url = el('img-url').value || '#'; const ed = this.ed(), s = ed.selectionStart; ins(ed, s, s, `![${alt}](${url})`); if (url.startsWith('data:image') && typeof ImgStore !== 'undefined') ImgStore.save(url, alt); el('img-alt').value = ''; el('img-url').value = ''; App.hideModal('image-modal') },
    math() { const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd, sel = ed.value.substring(s, e); ins(ed, s, e, sel ? `$$\n${sel}\n$$` : '\n$$\n\\phi = \\frac{\\lambda_2}{c^2}\n$$\n') },
    footnote() {
        const ed = this.ed();
        const pos = ed.selectionStart;
        const val = ed.value;
        const n = Math.floor((val.match(/\[\^\d+\]/g) || []).length / 2) + 1;
        const marker = `[^${n}]`;
        const defLine = `\n[^${n}]: <span style="font-size:9pt">각주 내용.</span>`;
        ed.value = val.substring(0, pos) + marker + val.substring(pos) + defLine;
        ed.setSelectionRange(pos + marker.length, pos + marker.length);
        App.render(); US.snap();
    },
    dupLine() {
        const ed = this.ed();
        const s = ed.selectionStart, e = ed.selectionEnd;
        if (s !== e) {
            // 선택 영역이 있으면 — 선택한 텍스트를 그대로 복제해서 바로 뒤에 삽입
            const sel = ed.value.substring(s, e);
            // 줄 경계에 맞게: 선택 끝 위치 뒤에 삽입
            // 선택이 줄 중간일 수도 있으므로 그냥 선택 직후에 붙임
            const insert = '\n' + sel;
            ed.value = ed.value.substring(0, e) + insert + ed.value.substring(e);
            // 복제된 부분을 선택 상태로 표시
            ed.setSelectionRange(e + 1, e + 1 + sel.length);
            ed.focus(); App.render(); US.snap();
        } else {
            // 선택 없으면 커서가 있는 줄 복제 (기존 동작)
            const { le, text } = getCL(ed);
            ins(ed, le, le, '\n' + text);
        }
    },
    // Alt+↑/↓ — 현재 줄(또는 선택 줄들)을 위/아래로 이동
    moveLine(dir) {
        const ed = this.ed();
        const val = ed.value;
        const ss = ed.selectionStart;
        const se = ed.selectionEnd;
        const lines = val.split('\n');

        // 1. 선택 범위가 포함된 시작/끝 줄 찾기 및 시작점의 절대 위치 계산
        let pos = 0;
        let startLine = -1, endLine = -1;
        let startLineAbsPos = 0;

        for (let i = 0; i < lines.length; i++) {
            const lEnd = pos + lines[i].length;
            if (startLine === -1 && ss <= lEnd) {
                startLine = i;
                startLineAbsPos = pos; // 선택된 블록이 시작되는 문자 위치 저장
            }
            if (se - (ss === se ? 0 : 1) <= lEnd) {
                endLine = i;
                break;
            }
            pos += lines[i].length + 1;
        }

        if (startLine < 0) startLine = 0;
        if (endLine < 0) endLine = startLine;

        // 경계 검사
        if (dir === -1 && startLine === 0) return;
        if (dir === 1 && endLine === lines.length - 1) return;

        // 2. 상대적 커서 오프셋 저장 (블록 시작점 기준)
        const offsetStart = ss - startLineAbsPos;
        const offsetEnd = se - startLineAbsPos;

        // 3. 줄 이동 로직
        const block = lines.splice(startLine, endLine - startLine + 1);
        const insertAt = (dir === -1) ? startLine - 1 : startLine + 1;
        lines.splice(insertAt, 0, ...block);
        ed.value = lines.join('\n');

        // 4. 이동 후의 새로운 시작 위치 계산
        let newBlockStartPos = 0;
        for (let i = 0; i < insertAt; i++) {
            newBlockStartPos += lines[i].length + 1;
        }

        // 5. 저장했던 오프셋을 적용하여 커서/선택영역 복구
        ed.setSelectionRange(newBlockStartPos + offsetStart, newBlockStartPos + offsetEnd);

        ed.focus();
        App.render();
        US.snap();
    },
    tabInTable(ed, ev) { const val = ed.value, pos = ed.selectionStart; const ls = val.lastIndexOf('\n', pos - 1) + 1, le = val.indexOf('\n', pos); const ln = val.substring(ls, le === -1 ? val.length : le); if (!ln.trim().startsWith('|')) return false; ev.preventDefault(); const pipes = []; for (let i = ls; i < (le === -1 ? val.length : le); i++)if (val[i] === '|') pipes.push(i); const nx = pipes.find(p => p > pos), nn = nx !== undefined ? pipes.find(p => p > nx) : undefined; if (nx !== undefined && nn !== undefined) ed.setSelectionRange(nx + 1, nn); return true },
    enterInTable(ed, ev) { const val = ed.value, pos = ed.selectionStart; const ls = val.lastIndexOf('\n', pos - 1) + 1, le = val.indexOf('\n', pos); const ln = val.substring(ls, le === -1 ? val.length : le); if (!ln.trim().startsWith('|') || /^\|[\s:|-]+\|$/.test(ln.trim())) return false; ev.preventDefault(); const cols = ln.split('|').filter(c => c.trim() !== '').length; ins(ed, le === -1 ? val.length : le, le === -1 ? val.length : le, '\n|' + ' 셀 |'.repeat(cols)); return true },

    /* ── 선택 텍스트 → Markdown 표 변환 (Alt+7) ────────────
       지원 구분자: 쉼표(,) / 탭(\t) / 파이프(|) / 세미콜론(;)
       첫 행 → 헤더, 두 번째 행 → 구분선, 나머지 → 데이터      */
    textToTable() {
        const ed  = el('editor');
        if (!ed) return;
        const s   = ed.selectionStart;
        const e   = ed.selectionEnd;
        const sel = ed.value.slice(s, e).trim();
        if (!sel) { App._toast('⚠ 변환할 텍스트를 먼저 선택하세요'); return; }

        const rawLines = sel.split('\n').map(l => l.trim()).filter(l => l);
        if (rawLines.length < 1) { App._toast('⚠ 선택된 텍스트가 없습니다'); return; }

        /* 구분자 자동 감지 */
        const detectSep = (line) => {
            if (line.includes('\t')) return '\t';
            if (line.includes('|'))  return '|';
            if (line.includes(';'))  return ';';
            return ',';
        };
        const sep = detectSep(rawLines[0]);

        /* 각 행을 셀 배열로 파싱 */
        const parseRow = (line) => {
            /* 파이프 구분 시 앞뒤 | 제거 */
            if (sep === '|') line = line.replace(/^\|/, '').replace(/\|$/, '');
            return line.split(sep).map(c => c.trim());
        };

        const rows = rawLines.map(parseRow);
        const colCount = Math.max(...rows.map(r => r.length));

        /* 열 수 맞추기 */
        rows.forEach(r => { while (r.length < colCount) r.push(''); });

        /* Markdown 표 생성 */
        const mkRow = cells => '| ' + cells.join(' | ') + ' |';
        const header = mkRow(rows[0]);
        const divider = '| ' + Array(colCount).fill('---').join(' | ') + ' |';
        const body = rows.slice(1).map(mkRow).join('\n');
        const table = header + '\n' + divider + (body ? '\n' + body : '');

        ed.setRangeText(table, s, e, 'end');
        US.snap(); TM.markDirty(); App.render();
        App._toast('✓ 표 변환 완료 (' + colCount + '열 × ' + rows.length + '행)');
    },

    /* ── 마크다운 표 → HTML 표 변환 ─────────────────────
       커서가 표 안에 있거나, 표 영역을 선택한 상태에서 실행    */
    mdTableToHtml() {
        const ed = el('editor');
        if (!ed) return;
        const val = ed.value;
        const pos = ed.selectionStart;
        const selEnd = ed.selectionEnd;

        /* 선택 영역이 있으면 그 범위에서 표 찾기, 없으면 커서 위치 기준 */
        let tableStart = -1, tableEnd = -1;

        const lines = val.split('\n');
        let charPos = 0;
        const lineStarts = lines.map(l => { const s = charPos; charPos += l.length + 1; return s; });

        /* 커서/선택 위치의 라인 찾기 */
        let cursorLine = 0;
        for (let i = 0; i < lineStarts.length; i++) {
            if (lineStarts[i] <= pos) cursorLine = i;
        }

        /* 커서 라인이 표인지 확인 */
        const isTableLine = (line) => line.trim().startsWith('|');

        /* 표 블록 범위 찾기 */
        let tStart = cursorLine, tEnd = cursorLine;
        while (tStart > 0 && isTableLine(lines[tStart - 1])) tStart--;
        while (tEnd < lines.length - 1 && isTableLine(lines[tEnd + 1])) tEnd++;

        if (!isTableLine(lines[cursorLine])) {
            App._toast('⚠ 커서를 표 안에 위치시키거나 표를 선택하세요');
            return;
        }

        tableStart = lineStarts[tStart];
        tableEnd = (tEnd < lines.length - 1) ? lineStarts[tEnd + 1] - 1 : val.length;

        const tableLines = lines.slice(tStart, tEnd + 1);

        /* 파싱 */
        const parseRow = (line) => {
            return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
        };

        const dataLines = tableLines.filter(l => !/^\|[\s:|-]+\|/.test(l.trim()));
        if (dataLines.length < 1) { App._toast('⚠ 표 데이터를 찾을 수 없습니다'); return; }

        const headerRow = parseRow(dataLines[0]);
        const bodyRows  = dataLines.slice(1).map(parseRow);

        /* HTML 생성 */
        const indent = '  ';
        let html = '<table>\n';
        html += indent + '<thead>\n';
        html += indent + indent + '<tr>\n';
        headerRow.forEach(cell => { html += indent + indent + indent + `<th>${cell}</th>\n`; });
        html += indent + indent + '</tr>\n';
        html += indent + '</thead>\n';
        if (bodyRows.length) {
            html += indent + '<tbody>\n';
            bodyRows.forEach(row => {
                html += indent + indent + '<tr>\n';
                row.forEach(cell => { html += indent + indent + indent + `<td>${cell}</td>\n`; });
                html += indent + indent + '</tr>\n';
            });
            html += indent + '</tbody>\n';
        }
        html += '</table>';

        ed.setRangeText(html, tableStart, tableEnd, 'end');
        US.snap(); TM.markDirty(); App.render();
        App._toast(`✓ HTML 표 변환 완료 (${headerRow.length}열 × ${dataLines.length}행)`);
    },
};

/* ═══════════════════════════════════════════════════════════
   DelConfirm — 파일 삭제 확인 모달 (로컬 / GitHub 공용)
═══════════════════════════════════════════════════════════ */
const DelConfirm = (() => {
    let _cb = null;

    function show({ name, path, type, onConfirm }) {
        _cb = onConfirm;
        const modal  = document.getElementById('del-confirm-modal');
        const fname  = document.getElementById('dc-filename');
        const fpath  = document.getElementById('dc-filepath');
        const badge  = document.getElementById('dc-type-badge');
        const cmWrap = document.getElementById('dc-commit-wrap');
        const cmMsg  = document.getElementById('dc-commit-msg');
        if (!modal) return;

        if (fname)  fname.textContent  = name;
        if (fpath)  fpath.textContent  = path;
        if (badge) {
            badge.textContent  = type === 'github' ? '🐙 GitHub' : '💻 로컬';
            badge.style.background = type === 'github'
                ? 'rgba(124,106,247,.2)' : 'rgba(106,247,176,.15)';
            badge.style.borderColor = type === 'github'
                ? 'rgba(124,106,247,.5)' : 'rgba(106,247,176,.4)';
            badge.style.color = type === 'github' ? '#c0baff' : '#6af7b0';
        }
        /* GitHub만 커밋 메시지 입력 표시 */
        if (cmWrap) cmWrap.style.display = type === 'github' ? '' : 'none';
        if (cmMsg)  cmMsg.value = `Delete ${name}`;

        modal.classList.add('vis');
        setTimeout(() => {
            const btn = document.getElementById('dc-confirm-btn');
            if (btn) btn.focus();
        }, 80);
    }

    function hide() {
        const modal = document.getElementById('del-confirm-modal');
        if (modal) modal.classList.remove('vis');
        _cb = null;
    }

    async function confirm() {
        if (typeof _cb !== 'function') { hide(); return; }
        const cmMsg = document.getElementById('dc-commit-msg');
        const msg   = cmMsg ? cmMsg.value.trim() : '';
        const cb = _cb;   // hide() 전에 저장 — hide()가 _cb = null 하기 때문
        hide();
        try {
            await cb(msg);
        } catch(e) {
            alert('삭제 중 오류: ' + (e.message || e));
        }
    }

    return { show, hide, confirm };
})();

/* ═══════════════════════════════════════════════════════════
   EZ — 에디터 입력창 글자 크기 확대/축소 (Ctrl+0/Ctrl+9)
═══════════════════════════════════════════════════════════ */
const EZ = (() => {
    const SIZES = [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 22, 24];
    const LHMAP = [14, 15, 16, 18, 19, 21, 22, 24, 26, 28, 30, 33, 36];
    let idx = 3; /* 기본 12px */

    function _apply() {
        const ed = el('editor');
        if (!ed) return;
        const sz = SIZES[idx];
        const lh = LHMAP[idx];
        ed.style.fontSize  = sz + 'px';
        ed.style.lineHeight = lh + 'px';
        const lbl = el('ez-lbl');
        if (lbl) lbl.textContent = sz + 'px';
        /* 라인 넘버 높이도 동기화 */
        const lnc = el('lnc');
        if (lnc) lnc.style.lineHeight = lh + 'px';
        /* 저장 */
        try { localStorage.setItem('mdpro_ez_idx', idx); } catch(e) {}
        if (typeof EditorLineHighlight !== 'undefined' && EditorLineHighlight.isEnabled()) EditorLineHighlight.updateHighlight();
    }

    function inc() { if (idx < SIZES.length - 1) { idx++; _apply(); } }
    function dec() { if (idx > 0) { idx--; _apply(); } }

    function init() {
        try {
            const saved = parseInt(localStorage.getItem('mdpro_ez_idx'));
            if (!isNaN(saved) && saved >= 0 && saved < SIZES.length) idx = saved;
        } catch(e) {}
        _apply();
    }

    return { inc, dec, init };
})();

/* ═══════════════════════════════════════════════════════════
   EDITOR CURRENT LINE HIGHLIGHT (아주 투명한 현재 줄 표시)
═══════════════════════════════════════════════════════════ */
const EditorLineHighlight = (() => {
    const STORAGE_KEY = 'mdpro_editor_line_highlight';
    let enabled = true;

    function isEnabled() {
        try { return localStorage.getItem(STORAGE_KEY) !== 'off'; } catch (e) { return true; }
    }

    function updateUI() {
        enabled = isEnabled();
        const hl = document.getElementById('editor-line-highlight');
        const btn = document.getElementById('hk-line-highlight-btn');
        if (hl) hl.classList.toggle('vis', enabled);
        if (btn) btn.textContent = enabled ? 'ON' : 'OFF';
    }

    function updateHighlight() {
        const hl = document.getElementById('editor-line-highlight');
        const ed = document.getElementById('editor');
        if (!hl || !ed || !enabled) return;
        const text = ed.value.substring(0, ed.selectionStart);
        const lineIndex = (text.match(/\n/g) || []).length;
        const style = window.getComputedStyle(ed);
        const lineHeight = parseFloat(style.lineHeight) || 21;
        const paddingTop = parseFloat(style.paddingTop) || 12;
        const paddingLeft = parseFloat(style.paddingLeft) || 14;
        const paddingRight = parseFloat(style.paddingRight) || 14;
        const top = paddingTop + lineIndex * lineHeight - ed.scrollTop;
        hl.style.height = lineHeight + 'px';
        hl.style.top = top + 'px';
        hl.style.left = paddingLeft + 'px';
        hl.style.right = paddingRight + 'px';
    }

    function toggle() {
        try {
            enabled = isEnabled();
            enabled = !enabled;
            localStorage.setItem(STORAGE_KEY, enabled ? 'on' : 'off');
        } catch (e) {}
        updateUI();
        if (enabled) updateHighlight();
    }

    function init() {
        updateUI();
        const ed = document.getElementById('editor');
        if (!ed) return;
        const run = () => { if (enabled) updateHighlight(); };
        ed.addEventListener('scroll', run, { passive: true });
        ed.addEventListener('click', run);
        ed.addEventListener('keyup', run);
        ed.addEventListener('input', run);
        document.addEventListener('selectionchange', () => { if (document.activeElement === ed) run(); });
        if (enabled) updateHighlight();
    }

    return { toggle, init, updateHighlight, isEnabled, updateUI };
})();

/* ═══════════════════════════════════════════════════════════
   EDITOR AUTO PAIR — ( ) [ ] " " ' ' 자동쌍 & 선택 시 감싸기
═══════════════════════════════════════════════════════════ */
const EditorAutoPair = (() => {
    const STORAGE_KEY = 'mdpro_editor_auto_pair';
    const PAIRS = { '(': ')', '[': ']', '"': '"', "'": "'", '{': '}', '<': '>' };

    function isEnabled() {
        try { return localStorage.getItem(STORAGE_KEY) !== 'off'; } catch (e) { return true; }
    }

    function updateUI() {
        const enabled = isEnabled();
        const btn = document.getElementById('hk-auto-pair-btn');
        if (btn) btn.textContent = enabled ? 'ON' : 'OFF';
    }

    function toggle() {
        let enabled = isEnabled();
        enabled = !enabled;
        try { localStorage.setItem(STORAGE_KEY, enabled ? 'on' : 'off'); } catch (e) {}
        updateUI();
    }

    /** 에디터에서 ( [ " ' 입력 시 처리. 처리했으면 true, 아니면 false */
    function handleKey(e) {
        if (!e.key || e.key.length !== 1) return false;
        const open = e.key;
        const close = PAIRS[open];
        if (close === undefined) return false;
        if (e.ctrlKey || e.metaKey || e.altKey) return false;
        if (!isEnabled()) return false;

        const edi = document.getElementById('editor');
        if (!edi || document.activeElement !== edi) return false;

        const ss = edi.selectionStart;
        const se = edi.selectionEnd;
        const val = edi.value;

        if (ss !== se) {
            /* 선택 영역 wrap: "텍스트" → "텍스트" */
            e.preventDefault();
            const sel = val.substring(ss, se);
            edi.value = val.substring(0, ss) + open + sel + close + val.substring(se);
            edi.setSelectionRange(ss + 1 + sel.length, ss + 1 + sel.length);
            edi.focus();
            if (typeof US !== 'undefined') US.snap();
            if (typeof TM !== 'undefined') TM.markDirty();
            if (typeof App !== 'undefined' && App.render) App.render();
            return true;
        }

        /* 커서만 있을 때: 자동쌍 ( ) [ ] " " ' ' */
        e.preventDefault();
        edi.value = val.substring(0, ss) + open + close + val.substring(se);
        edi.setSelectionRange(ss + 1, ss + 1);
        edi.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
        return true;
    }

    function init() {
        updateUI();
    }

    return { handleKey, isEnabled, toggle, init, updateUI };
})();

/* ═══════════════════════════════════════════════════════════
   AUTHOR INFO — 이름/소속/메일/연락처 저장 및 Shift+Alt+A 삽입
═══════════════════════════════════════════════════════════ */
const AuthorInfo = (() => {
    const STORAGE_KEY = 'mdpro_author_info';
    const INSERT_KEY = 'mdpro_author_insert';
    const DEFAULT_INSERT = { name: true, affiliation: false, email: false, contact: false };

    function load() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : { name: '', affiliation: '', email: '', contact: '' };
        } catch (e) { return { name: '', affiliation: '', email: '', contact: '' }; }
    }

    function loadInsert() {
        try {
            const raw = localStorage.getItem(INSERT_KEY);
            return raw ? JSON.parse(raw) : { ...DEFAULT_INSERT };
        } catch (e) { return { ...DEFAULT_INSERT }; }
    }

    function saveInputs() {
        const name = document.getElementById('hk-author-name');
        const affiliation = document.getElementById('hk-author-affiliation');
        const email = document.getElementById('hk-author-email');
        const contact = document.getElementById('hk-author-contact');
        if (!name) return;
        const data = {
            name: (name.value || '').trim(),
            affiliation: (affiliation && affiliation.value ? affiliation.value : '').trim(),
            email: (email && email.value ? email.value : '').trim(),
            contact: (contact && contact.value ? contact.value : '').trim()
        };
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) {}
        saveInsertFromCheckboxes();
    }

    function saveInsertFromCheckboxes() {
        const chkName = document.getElementById('hk-insert-name');
        const chkAff = document.getElementById('hk-insert-affiliation');
        const chkEmail = document.getElementById('hk-insert-email');
        const chkContact = document.getElementById('hk-insert-contact');
        if (!chkName) return;
        const data = {
            name: !!chkName.checked,
            affiliation: !!(chkAff && chkAff.checked),
            email: !!(chkEmail && chkEmail.checked),
            contact: !!(chkContact && chkContact.checked)
        };
        try { localStorage.setItem(INSERT_KEY, JSON.stringify(data)); } catch (e) {}
    }

    function loadToPanel() {
        const data = load();
        const nameEl = document.getElementById('hk-author-name');
        const affEl = document.getElementById('hk-author-affiliation');
        const emailEl = document.getElementById('hk-author-email');
        const contactEl = document.getElementById('hk-author-contact');
        if (nameEl) nameEl.value = data.name || '';
        if (affEl) affEl.value = data.affiliation || '';
        if (emailEl) emailEl.value = data.email || '';
        if (contactEl) contactEl.value = data.contact || '';

        const ins = loadInsert();
        const chkName = document.getElementById('hk-insert-name');
        const chkAff = document.getElementById('hk-insert-affiliation');
        const chkEmail = document.getElementById('hk-insert-email');
        const chkContact = document.getElementById('hk-insert-contact');
        if (chkName) chkName.checked = ins.name;
        if (chkAff) chkAff.checked = ins.affiliation;
        if (chkEmail) chkEmail.checked = ins.email;
        if (chkContact) chkContact.checked = ins.contact;

        [chkName, chkAff, chkEmail, chkContact].forEach(el => {
            if (el) el.removeEventListener('change', saveInsertFromCheckboxes);
            if (el) el.addEventListener('change', saveInsertFromCheckboxes);
        });
    }

    function getTextToInsert() {
        const data = load();
        const ins = loadInsert();
        const lines = [];
        if (ins.name && data.name) lines.push(data.name);
        if (ins.affiliation && data.affiliation) lines.push(data.affiliation);
        if (ins.email && data.email) lines.push(data.email);
        if (ins.contact && data.contact) lines.push(data.contact);
        return lines.join('\n');
    }

    /** 패널 입력란에서 작성된 항목만 모두 모아서 삽입 (체크박스 무시) */
    function getAllWrittenText() {
        const nameEl = document.getElementById('hk-author-name');
        const affEl = document.getElementById('hk-author-affiliation');
        const emailEl = document.getElementById('hk-author-email');
        const contactEl = document.getElementById('hk-author-contact');
        const lines = [];
        if (nameEl && (nameEl.value || '').trim()) lines.push((nameEl.value || '').trim());
        if (affEl && (affEl.value || '').trim()) lines.push((affEl.value || '').trim());
        if (emailEl && (emailEl.value || '').trim()) lines.push((emailEl.value || '').trim());
        if (contactEl && (contactEl.value || '').trim()) lines.push((contactEl.value || '').trim());
        return lines.join('\n');
    }

    function insertIntoEditor() {
        const ed = document.getElementById('editor');
        if (!ed) return;
        const text = getTextToInsert();
        if (!text) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        const val = ed.value;
        ed.value = val.substring(0, s) + text + val.substring(e);
        ed.setSelectionRange(s + text.length, s + text.length);
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    }

    function insertAllIntoEditor() {
        const ed = document.getElementById('editor');
        if (!ed) return;
        const text = getAllWrittenText();
        if (!text) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        const val = ed.value;
        ed.value = val.substring(0, s) + text + val.substring(e);
        ed.setSelectionRange(s + text.length, s + text.length);
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    }

    return { load, loadInsert, saveInputs, loadToPanel, getTextToInsert, getAllWrittenText, insertIntoEditor, insertAllIntoEditor };
})();

/* ═══════════════════════════════════════════════════════════
   FONT SIZE MANAGER  (선택 텍스트에 크기 적용)
═══════════════════════════════════════════════════════════ */
const FS = (() => {
    const SIZES = [8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 36, 40, 48, 50];
    let cur = 4;// 기본 12pt

    function updateDisplay() {
        el('fsize-display').textContent = SIZES[cur] + 'pt';
    }

    function apply() {
        const pt = SIZES[cur];
        const ed = el('editor');
        const s = ed.selectionStart, e = ed.selectionEnd;
        const sel = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="font-size:${pt}pt">${sel}</span>`);
    }

    function inc() { if (cur < SIZES.length - 1) { cur++; updateDisplay(); apply() } }
    function dec() { if (cur > 0) { cur--; updateDisplay(); apply() } }

    // 한번 클릭 → 드롭다운 픽커
    let _picker = null;
    function clickPick(ev) {
        ev.stopPropagation();
        if (_picker) { _picker.remove(); _picker = null; return }
        const rect = el('fsize-display').getBoundingClientRect();
        const div = document.createElement('div');
        div.style.cssText = `position:fixed;left:${rect.left}px;top:${rect.bottom + 2}px;background:var(--bg2);border:1px solid var(--bd);border-radius:6px;box-shadow:0 6px 24px rgba(0,0,0,.4);z-index:9999;overflow:hidden;min-width:70px`;
        div.innerHTML = SIZES.map((s, i) => `<div data-i="${i}" style="padding:5px 14px;font-family:var(--fm);font-size:12px;cursor:pointer;color:${i === cur ? 'var(--ac)' : 'var(--tx)'};background:${i === cur ? 'var(--acg)' : 'transparent'};transition:background .1s" onmouseenter="this.style.background='var(--bg5)'" onmouseleave="this.style.background='${i === cur ? 'var(--acg)' : 'transparent'}'" onclick="FS.pickSize(${i},event)">${s}pt</div>`).join('');
        document.body.appendChild(div); _picker = div;
        setTimeout(() => document.addEventListener('click', _closePicker, { once: true }), 10);
    }
    function _closePicker() { if (_picker) { _picker.remove(); _picker = null } }
    function pickSize(i, ev) { if (ev) ev.stopPropagation(); cur = i; updateDisplay(); _closePicker(); apply() }

    // 두번 클릭 → 인라인 직접 입력
    function startEdit(ev) {
        ev.stopPropagation(); _closePicker();
        const disp = el('fsize-display'), inp = el('fsize-input');
        inp.value = SIZES[cur];
        disp.style.display = 'none'; inp.style.display = 'inline-block';
        inp.focus(); inp.select();
    }
    function endEdit() {
        const inp = el('fsize-input'), disp = el('fsize-display');
        const v = parseInt(inp.value);
        if (v >= 6 && v <= 200) {
            // find nearest or add
            let best = 0, bDiff = 999;
            SIZES.forEach((s, i) => { const d = Math.abs(s - v); if (d < bDiff) { bDiff = d; best = i } });
            cur = best; updateDisplay(); apply();
        }
        inp.style.display = 'none'; disp.style.display = '';
    }
    function editKey(ev) { if (ev.key === 'Enter') el('fsize-input').blur(); if (ev.key === 'Escape') { el('fsize-input').style.display = 'none'; el('fsize-display').style.display = ''; } }

    function update() { updateDisplay() }
    return { inc, dec, update, clickPick, pickSize, startEdit, endEdit, editKey };
})();

/* ═══════════════════════════════════════════════════════════
   FORMAT QUICK PANEL (Alt+L)
═══════════════════════════════════════════════════════════ */
const FP = (() => {
    let vis = false;
    function show() {
        const panel = el('fmt-panel');
        if (vis) { hide(); return }
        // position near toolbar
        const tb = document.querySelector('#toolbar');
        const rect = tb.getBoundingClientRect();
        panel.style.left = '50%'; panel.style.top = (rect.bottom + 4) + 'px';
        panel.style.transform = 'translateX(-50%)';
        panel.classList.add('vis'); vis = true;
        setTimeout(() => document.addEventListener('click', _outside, { once: true }), 10);
    }
    function hide() { el('fmt-panel').classList.remove('vis'); vis = false }
    function _outside(e) { if (!el('fmt-panel').contains(e.target)) hide(); else setTimeout(() => document.addEventListener('click', _outside, { once: true }), 10) }

    function fsz(dir) {
        const sel = el('fp-fsize');
        const idx = sel.selectedIndex;
        const ni = Math.max(0, Math.min(sel.options.length - 1, idx + dir));
        sel.selectedIndex = ni; applyFsize();
    }
    function applyFsize() {
        const size = el('fp-fsize').value;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="font-size:${size}">${sel2}</span>`);
    }
    function setFc(c) { el('fp-fc').value = c === '#e8e8f0' ? '#e8e8f0' : c; applyColor() }
    function applyColor() {
        const c = el('fp-fc').value;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="color:${c}">${sel2}</span>`);
    }
    function setHL(c) { if (c === 'none') { applyHLnone(); return } el('fp-hl').value = c; applyHL() }
    function applyHL() {
        const c = el('fp-hl').value;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="background:${c}">${sel2}</span>`);
    }
    function applyHLnone() {
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e);
        if (sel2) ins(ed, s, e, sel2.replace(/<span style="background:[^"]*">(.*?)<\/span>/gs, '$1'));
    }
    return { show, hide, fsz, applyFsize, setFc, applyColor, setHL, applyHL };
})();

/* ═══════════════════════════════════════════════════════════
   APA STATISTICS INSERTER
═══════════════════════════════════════════════════════════ */
const STATS = (() => {
    const CUSTOM_KEY = 'mdpro_custom_stats';
    let curType = 'ttest';
    let customList = [];

    const TYPES = {
        ttest: {
            label: 't-test',
            fields: [
                { id: 'df', label: 'df', ph: '자유도', req: true },
                { id: 't', label: 't', ph: 't값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
                { id: 'd', label: "Cohen's d", ph: '효과크기 (선택)', req: false },
            ],
            fmt: (v) => {
                let s = `(t(${v.df}) = ${v.t}, p = ${fmtP(v.p)}`;
                if (v.d) s += `, d = ${v.d}`;
                return s + ')';
            }
        },
        anova: {
            label: 'ANOVA',
            fields: [
                { id: 'df1', label: 'df₁', ph: '처리 자유도', req: true },
                { id: 'df2', label: 'df₂', ph: '오차 자유도', req: true },
                { id: 'F', label: 'F', ph: 'F값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
                { id: 'np2', label: 'η²p', ph: '부분 에타제곱 (선택)', req: false },
            ],
            fmt: (v) => {
                let s = `(F(${v.df1}, ${v.df2}) = ${v.F}, p = ${fmtP(v.p)}`;
                if (v.np2) s += `, η²p = ${v.np2}`;
                return s + ')';
            }
        },
        regression: {
            label: 'Regression',
            fields: [
                { id: 'beta', label: 'β (표준화)', ph: '베타 (선택)', req: false },
                { id: 'B', label: 'B (비표준화)', ph: 'B (선택)', req: false },
                { id: 'SE', label: 'SE', ph: '표준오차 (선택)', req: false },
                { id: 't', label: 't', ph: 't값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
            ],
            fmt: (v) => {
                const parts = [];
                if (v.beta) parts.push(`β = ${v.beta}`);
                if (v.B) parts.push(`B = ${v.B}`);
                if (v.SE) parts.push(`SE = ${v.SE}`);
                parts.push(`t = ${v.t}`);
                parts.push(`p = ${fmtP(v.p)}`);
                return '(' + parts.join(', ') + ')';
            }
        },
        correlation: {
            label: 'Correlation',
            fields: [
                { id: 'r', label: 'r', ph: '상관계수', req: true },
                { id: 'df', label: 'df', ph: '자유도 (선택)', req: false },
                { id: 'p', label: 'p', ph: 'p값', req: true },
            ],
            fmt: (v) => {
                let s = v.df ? `(r(${v.df}) = ${v.r}` : `(r = ${v.r}`;
                s += `, p = ${fmtP(v.p)})`;
                return s;
            }
        },
        chisq: {
            label: 'Chi-square',
            fields: [
                { id: 'df', label: 'df', ph: '자유도', req: true },
                { id: 'chisq', label: 'χ²', ph: '카이제곱값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
                { id: 'V', label: "Cramer's V", ph: '효과크기 (선택)', req: false },
            ],
            fmt: (v) => {
                let s = `(χ²(${v.df}) = ${v.chisq}, p = ${fmtP(v.p)}`;
                if (v.V) s += `, Cramer's V = ${v.V}`;
                return s + ')';
            }
        },
        sem: {
            label: 'SEM',
            fields: [
                { id: 'beta', label: 'β (표준화)', ph: '베타 (선택)', req: false },
                { id: 'b', label: 'b (비표준화)', ph: 'b (선택)', req: false },
                { id: 'SE', label: 'SE', ph: '표준오차 (선택)', req: false },
                { id: 'z', label: 'z', ph: 'z값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
            ],
            fmt: (v) => {
                const parts = [];
                if (v.beta) parts.push(`β = ${v.beta}`);
                if (v.b) parts.push(`b = ${v.b}`);
                if (v.SE) parts.push(`SE = ${v.SE}`);
                parts.push(`z = ${v.z}`);
                parts.push(`p = ${fmtP(v.p)}`);
                return '(' + parts.join(', ') + ')';
            }
        },
        logistic: {
            label: 'Logistic Regression',
            fields: [
                { id: 'OR', label: 'OR', ph: '오즈비', req: true },
                { id: 'CI_low', label: '95% CI 하한', ph: '하한값', req: true },
                { id: 'CI_high', label: '95% CI 상한', ph: '상한값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
            ],
            fmt: (v) => `(OR = ${v.OR}, 95% CI [${v.CI_low}, ${v.CI_high}], p = ${fmtP(v.p)})`
        },
        multilevel: {
            label: 'Multilevel (HLM)',
            fields: [
                { id: 'gamma', label: 'γ', ph: '감마 계수', req: true },
                { id: 'SE', label: 'SE', ph: '표준오차', req: true },
                { id: 't', label: 't', ph: 't값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
            ],
            fmt: (v) => `(γ = ${v.gamma}, SE = ${v.SE}, t = ${v.t}, p = ${fmtP(v.p)})`
        },
    };

    function fmtP(p) {
        if (!p) return '?';
        const n = parseFloat(p);
        if (isNaN(n)) return p;
        if (n < .001) return '< .001';
        if (n < .01) return n.toFixed(3).replace('0.', '. ').replace(/ /, '');
        return n.toFixed(3).replace('0.', '.').replace(/0+$/, '').replace(/\.$/, '');
    }

    function loadCustom() { try { customList = JSON.parse(localStorage.getItem(CUSTOM_KEY) || '[]') } catch (e) { customList = [] } }
    function saveCustomList() { try { localStorage.setItem(CUSTOM_KEY, JSON.stringify(customList)) } catch (e) { } }

    function renderFields(type) {
        const area = el('stats-fields');
        const customArea = el('stats-custom-area');
        if (type === 'custom') {
            area.style.display = 'none';
            customArea.style.display = 'block';
            renderCustomSavedSel();
            updateCustomVars();
        } else {
            area.style.display = 'grid';
            customArea.style.display = 'none';
            const t = TYPES[type]; if (!t) return;
            area.innerHTML = t.fields.map(f => `
        <div class="fg" style="margin:0">
          <label class="fl">${f.label}${f.req ? '' : ' <span style="color:var(--tx3)">(선택)</span>'}</label>
          <input class="fi" id="sf_${f.id}" type="text" placeholder="${f.ph}" oninput="STATS.preview()" style="padding:5px 8px">
        </div>`).join('');
        }
        preview();
    }

    function preview() {
        const pv = el('stats-preview');
        try {
            if (curType === 'custom') {
                const fmt = el('custom-fmt').value;
                const vars = (el('custom-vars').value || '').split(',').map(s => s.trim()).filter(Boolean);
                const vals = {};
                vars.forEach(v => { const inp = el('cfsf_' + v); vals[v] = inp ? inp.value.trim() : ''; });
                let out = fmt;
                vars.forEach(v => { if (vals[v]) out = out.replaceAll('{' + v + '}', vals[v]); });
                pv.textContent = out || '(출력 미리보기)';
            } else {
                const t = TYPES[curType]; if (!t) { pv.textContent = ''; return }
                const vals = {};
                t.fields.forEach(f => { const inp = el('sf_' + f.id); vals[f.id] = inp ? inp.value.trim() : ''; });
                pv.textContent = t.fmt(vals);
            }
        } catch (e) { pv.textContent = '입력값 오류' }
    }

    function setType(type) {
        curType = type;
        document.querySelectorAll('#stats-type-row .btn-tog').forEach(b => b.classList.remove('active'));
        const btn = el('st-' + type); if (btn) btn.classList.add('active');
        renderFields(type);
    }

    function insert() {
        const pv = el('stats-preview').textContent;
        if (!pv || (pv === '(출력 미리보기)' && curType === 'custom')) return;
        const ed = el('editor'); const pos = ed.selectionEnd;
        ed.value = ed.value.substring(0, pos) + pv + ed.value.substring(pos);
        ed.setSelectionRange(pos + pv.length, pos + pv.length);
        ed.focus(); App.render(); US.snap();
        App.hideModal('stats-modal');
    }

    function updateCustomVars() {
        const vars = (el('custom-vars').value || '').split(',').map(s => s.trim()).filter(Boolean);
        const area = el('custom-fields');
        area.innerHTML = vars.map(v => `
      <div class="fg" style="margin:0">
        <label class="fl">${v}</label>
        <input class="fi" id="cfsf_${v}" type="text" placeholder="${v} 값" oninput="STATS.preview()" style="padding:5px 8px">
      </div>`).join('');
        preview();
    }

    function saveCustom() {
        const name = (el('custom-name').value || '').trim();
        const fmt = (el('custom-fmt').value || '').trim();
        const vars = (el('custom-vars').value || '').trim();
        if (!name || !fmt) { alert('이름과 포맷을 입력하세요.'); return }
        const existing = customList.findIndex(c => c.name === name);
        const entry = { name, fmt, vars };
        if (existing >= 0) customList[existing] = entry;
        else customList.push(entry);
        saveCustomList();
        renderCustomSavedSel();
        el('custom-name').value = '';
        alert(`"${name}" 저장됨`);
    }

    function deleteCustom() {
        const sel = el('custom-saved-sel').value;
        if (!sel) return;
        customList = customList.filter(c => c.name !== sel);
        saveCustomList();
        renderCustomSavedSel();
        el('custom-name').value = ''; el('custom-fmt').value = ''; el('custom-vars').value = '';
        el('custom-fields').innerHTML = '';
        preview();
    }

    function loadCustom(name) {
        if (!name) return;
        const c = customList.find(x => x.name === name);
        if (!c) return;
        el('custom-name').value = c.name;
        el('custom-fmt').value = c.fmt;
        el('custom-vars').value = c.vars || '';
        updateCustomVars();
    }

    function renderCustomSavedSel() {
        const sel = el('custom-saved-sel');
        sel.innerHTML = '<option value="">— 저장된 커스텀 —</option>' + customList.map(c => `<option value="${c.name}">${c.name}</option>`).join('');
    }

    function show() {
        loadCustom();
        el('stats-modal').classList.add('vis');
        setType(curType);
    }

    return { show, setType, preview, insert, updateCustomVars, saveCustom, deleteCustom, loadCustom };
})();

/* ═══════════════════════════════════════════════════════════
   HOTKEY ENGINE
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   HK — 단축키 목록 매니저 (편집 가능)
═══════════════════════════════════════════════════════════ */
const HK = (() => {
    const STORAGE_KEY = 'mdpro-hotkeys-v2';

    /* ── action → 실제 함수 매핑 ───────────────────────────────
       handleKey()가 HK.getDispatch()를 통해 이 테이블을 참조하여
       동적으로 디스패치한다. 키 수정 시 rebuild()가 재빌드한다.  */
    const ACTION_MAP = {
        'view.split':       () => App.setViewCycle('split'),
        'view.editor':      () => App.setViewCycle('editor'),
        'view.preview':     () => App.setViewCycle('preview'),
        'ed.h1':            () => ED.h(1),
        'ed.h2':            () => ED.h(2),
        'ed.h3':            () => ED.h(3),
        'ed.pageBreak':     () => ED.pageBreak(),
        'ed.lineBreak':     () => ED.lineBreak(),
        'ed.bold':          () => ED.bold(),
        'ed.italic':        () => ED.italic(),
        'ed.bquote':        () => ED.bquote(),
        'ed.inlineCode':    () => ED.inlineCode(),
        'ed.codeBlock':     () => ED.codeBlockDirect(),
        'ed.table':         () => ED.table(),
        'ed.tableRow':      () => ED.tableRow(),
        'ed.tableCol':      () => ED.tableCol(),
        'ed.mergeH':        () => ED.mergeH(),
        'ed.mergeV':        () => ED.mergeV(),
        'ed.footnote':      () => ED.footnote(),
        'ed.alignLeft':     () => ED.align('left'),
        'ed.alignCenter':   () => ED.align('center'),
        'ed.alignRight':    () => ED.align('right'),
        'ed.moveUp':        () => ED.moveLine(-1),
        'ed.moveDown':      () => ED.moveLine(1),
        'ed.dupLine':       () => ED.dupLine(),
        'ed.undo':          () => US.undo(),
        'ed.redo':          () => US.redo(),
        'fs.inc':           () => FS.inc(),
        'fs.dec':           () => FS.dec(),
        'app.stats':        () => STATS.show(),
        'app.translator':   () => Translator.show(),
        'app.fmtPanel':     () => FP.show(),
        'app.previewWin':   () => PW.open(),
        'app.previewPPT':   () => PW.openSlide(),
        'app.researchMode': () => App.toggleRM(),
        'app.cite':         () => App.showCite(),
        'app.scholar':      () => Scholar.show(),
        'app.aiPPT':        () => AiPPT.open(),
        'app.save':         () => App.smartSave(),
        'app.find':         () => App.toggleFind(),
        'app.toggleMultiEditBar': () => App.toggleMultiEditBar(),
        'app.multiEditApply': () => { if (el('multi-edit-bar') && el('multi-edit-bar').classList.contains('vis')) App.multiEditApply(); },
        'app.hotkeys':      () => App.showHK(),
        'app.themeDark':    () => App.setTheme('dark'),
        'app.themeLight':   () => App.setTheme('light'),
        'app.themeToggle':  () => App.toggleTheme(),
        'app.lock':         () => { if (typeof AppLock !== 'undefined') AppLock.lockNow(); },
        'app.nbsp':         () => { const ed = el('editor'), s = ed.selectionStart; ins(ed, s, ed.selectionEnd, '&nbsp;'); US.snap(); },
        'tab.new':          () => TM.newTab(),
        'tab.open':         () => TM.openFile(),
        'tab.saveAll':      () => TM.saveAll(),
        'tab.close':        () => { const t = TM.getActive(); if (t) TM.closeTab(t.id); },
        'tab.print':        () => App.printDoc(),
        'edit.deleteLine':  () => App.deleteLine(),
        'ed.strikethrough': () => EdCommands.strikethrough(),
        'ed.underline':     () => EdCommands.underline(),
        'ed.sup':           () => EdCommands.sup(),
        'ed.sub':           () => EdCommands.sub(),
        'ed.highlight':     () => EdCommands.highlight(),
        'ed.hr':            () => EdCommands.hr(),
        'ed.ul':            () => EdCommands.ul(),
        'ed.ol':            () => EdCommands.ol(),
        'ed.textToList':    () => { ED.textToList(); },
        'ed.textToNumberedList': () => { ED.textToNumberedList(); },
        'ed.task':          () => EdCommands.task(),
        'ed.link':          () => EdCommands.link(),
        'ed.image':         () => EdCommands.image(),
        'ed.indentIn':      () => EdCommands.indentIn(),
        'ed.indentOut':     () => EdCommands.indentOut(),
        'ed.textToTable':   () => ED.textToTable(),
        'ed.mdTableToHtml': () => ED.mdTableToHtml(),
        'tab.prev':         () => { const tabs=TM.getAll(); const i=tabs.findIndex(t=>t.id===TM.getActive()?.id); if(i>0) TM.switchTab(tabs[i-1].id); },
        'tab.next':         () => { const tabs=TM.getAll(); const i=tabs.findIndex(t=>t.id===TM.getActive()?.id); if(i<tabs.length-1) TM.switchTab(tabs[i+1].id); },
        'app.insertDate':   () => App.insertDate(),
        'app.makeImageLink': () => App.makeImageLink(),
        'app.openSelectionAsLink': () => App.openSelectionAsLink(),
        'app.insertAuthorInfo': () => { if (typeof AuthorInfo !== 'undefined') AuthorInfo.insertIntoEditor(); },
        'app.charMap':      () => CharMap.show(),
        'app.syncToggle':   () => SS.toggle(),
        'app.ghCommit':     () => { const t=TM.getActive(); if(t&&t.ghPath) App._openGHSaveModal(t); },
        'app.pullGH':       () => FM.pullFromGitHub(),
        'app.pushGH':       () => FM.syncToGitHub(),
        'edit.deleteLine':  () => App.deleteLine(),
    };

    /* ── 기본 단축키 데이터 ─────────────────────────────────────
       keys : 표시용 문자열 (사용자가 편집)
       action: ACTION_MAP 키 — 이 값이 실제 동작을 결정한다.     */
    const DEFAULT_DATA = [
        {
            section: '문서 구조', items: [
                { desc: 'H1', keys: 'Ctrl + Alt + 1', action: 'ed.h1' },
                { desc: 'H2', keys: 'Ctrl + Alt + 2', action: 'ed.h2' },
                { desc: 'H3', keys: 'Ctrl + Alt + 3', action: 'ed.h3' },
                { desc: '페이지 나누기', keys: 'Ctrl + Enter', action: 'ed.pageBreak' },
                { desc: '줄바꿈 (<br>)', keys: 'Ctrl + Shift + Enter', action: 'ed.lineBreak' },
            ]
        },
        {
            section: '표 편집', items: [
                { desc: '텍스트 → 표 변환', keys: 'Alt + 7', action: 'ed.textToTable' },
                { desc: '마크다운 표 → HTML 표', keys: 'Alt + H', action: 'ed.mdTableToHtml' },
                { desc: '표 삽입', keys: 'Alt + 8', action: 'ed.table' },
                { desc: '행 추가', keys: 'Alt + 9', action: 'ed.tableRow' },
                { desc: '열 추가', keys: 'Alt + 0', action: 'ed.tableCol' },
                { desc: '가로 병합 (colspan)', keys: 'Alt + Shift + H', action: 'ed.mergeH' },
                { desc: '세로 병합 (rowspan)', keys: 'Alt + Shift + V', action: 'ed.mergeV' },
                { desc: 'HTML 표 들여쓰기 정돈', keys: 'Tidy 버튼', action: '' },
            ]
        },
        {
            section: '텍스트 서식', items: [
                { desc: 'Smart Bold', keys: 'Ctrl + B', action: 'ed.bold' },
                { desc: '기울임꼴', keys: 'Ctrl + I', action: 'ed.italic' },
                { desc: '인용구', keys: 'Ctrl + .', action: 'ed.bquote' },
                { desc: '인라인 코드 `code`', keys: 'Alt + V', action: 'ed.inlineCode' },
                { desc: '코드 직접 삽입 (마지막 언어)', keys: 'Alt + C', action: 'ed.codeBlock' },
                { desc: '글자 크기 키우기', keys: 'Shift + Alt + .', action: 'fs.inc' },
                { desc: '글자 크기 줄이기', keys: 'Shift + Alt + ,', action: 'fs.dec' },
            ]
        },
        {
            section: '레이아웃 / 정렬', items: [
                { desc: '왼쪽 정렬', keys: 'Shift + Alt + L', action: 'ed.alignLeft' },
                { desc: '가운데 정렬', keys: 'Shift + Alt + C', action: 'ed.alignCenter' },
                { desc: '오른쪽 정렬', keys: 'Shift + Alt + R', action: 'ed.alignRight' },
                { desc: 'Split 보기', keys: 'Alt + 1', action: 'view.split' },
                { desc: '에디터만', keys: 'Alt + 2', action: 'view.editor' },
                { desc: '미리보기만', keys: 'Alt + 3', action: 'view.preview' },
                { desc: '전체 다크/라이트 토글', keys: 'Alt + 4', action: 'app.themeToggle' },
            ]
        },
        {
            section: '편집', items: [
                { desc: '줄 위로 이동', keys: 'Alt + ArrowUp', action: 'ed.moveUp' },
                { desc: '줄 아래로 이동', keys: 'Alt + ArrowDown', action: 'ed.moveDown' },
                { desc: '줄 / 선택 복제', keys: 'Shift + Alt + ArrowDown', action: 'ed.dupLine' },
                { desc: '실행 취소', keys: 'Ctrl + Z', action: 'ed.undo' },
                { desc: '다시 실행', keys: 'Ctrl + Shift + Z', action: 'ed.redo' },
                { desc: '다시 실행 (대체)', keys: 'Ctrl + Y', action: 'ed.redo' },
                { desc: '현재 줄 삭제', keys: 'Alt + Y', action: 'edit.deleteLine' },
            ]
        },
        {
            section: '삽입 / 도구', items: [
                { desc: '오늘 날짜 삽입', keys: 'Shift + Alt + D', action: 'app.insertDate' },
                { desc: '작성자 정보 삽입', keys: 'Shift + Alt + A', action: 'app.insertAuthorInfo' },
                { desc: '이미지 링크 만들기', keys: 'Alt + I', action: 'app.makeImageLink' },
                { desc: '선택 텍스트 → 하이퍼링크 새창', keys: 'Shift + Alt + I', action: 'app.openSelectionAsLink' },
                { desc: '인용 삽입', keys: 'Ctrl + Shift + C', action: 'app.cite' },
                { desc: '각주 삽입', keys: 'Shift + Alt + N', action: 'ed.footnote' },
                { desc: 'APA 통계 삽입', keys: 'Shift + Alt + 9', action: 'app.stats' },
                { desc: '번역기', keys: 'Shift + Alt + G', action: 'app.translator' },
                { desc: '서식 패널 (크기·색·형광펜)', keys: 'Alt + L', action: 'app.fmtPanel' },
                { desc: '새창 미리보기', keys: 'Ctrl + Shift + P', action: 'app.previewWin' },
                { desc: '슬라이드 모드로 새창 열기', keys: 'Ctrl + Shift + T', action: 'app.previewPPT' },
                { desc: '저장 다이얼로그', keys: 'Ctrl + S', action: 'app.save' },
                { desc: '찾기 / 바꾸기', keys: 'Ctrl + H', action: 'app.find' },
                { desc: '다중선택 편집 (선택 시 메뉴 열기)', keys: 'Ctrl + Alt + K', action: 'app.toggleMultiEditBar' },
                { desc: '다중선택 편집 (선택→바꾸기 전체 적용)', keys: 'Ctrl + Enter', action: 'app.multiEditApply' },
                { desc: 'Research Mode', keys: 'Ctrl + Shift + R', action: 'app.researchMode' },
                { desc: 'Scholar 검색', keys: 'Ctrl + Shift + G', action: 'app.scholar' },
                { desc: 'AI PPT (ScholarSlide)', keys: 'Ctrl + Shift + L', action: 'app.aiPPT' },
                { desc: '단축키 목록 & 설정', keys: 'Alt + ?', action: 'app.hotkeys' },
                { desc: '문자표 (특수문자)', keys: 'Ctrl + Q', action: 'app.charMap' },
                { desc: '에디터-PV 스크롤 동기화', keys: 'Shift + Alt + M', action: 'app.syncToggle' },
                { desc: '앱 잠금', keys: 'Ctrl + G', action: 'app.lock' },
                { desc: '새 탭', keys: 'Ctrl + N', action: 'tab.new' },
                { desc: '파일 열기', keys: 'Ctrl + O', action: 'tab.open' },
                { desc: '탭 닫기', keys: 'Ctrl + W', action: 'tab.close' },
                { desc: '전체 저장', keys: 'Ctrl + Shift + S', action: 'tab.saveAll' },
                { desc: '인쇄', keys: 'Ctrl + P', action: 'tab.print' },
                { desc: '줄바꿈 공백 (&nbsp;)', keys: 'Ctrl + Shift + Space', action: 'app.nbsp' },
            ]
        },
        {
            section: '추가 서식', items: [
                { desc: '취소선 (~~)', keys: '', action: 'ed.strikethrough' },
                { desc: '밑줄', keys: '', action: 'ed.underline' },
                { desc: '위첨자', keys: '', action: 'ed.sup' },
                { desc: '아래첨자', keys: '', action: 'ed.sub' },
                { desc: '형광펜 (==)', keys: '', action: 'ed.highlight' },
                { desc: '수평선', keys: '', action: 'ed.hr' },
                { desc: '순서없는 목록', keys: '', action: 'ed.ul' },
                { desc: '텍스트→목록 항목 (•)', keys: 'Alt + 5', action: 'ed.textToList' },
                { desc: '텍스트→숫자 목록 (1. 2. 3.)', keys: 'Alt + 6', action: 'ed.textToNumberedList' },
                { desc: '체크리스트', keys: '', action: 'ed.task' },
                { desc: '링크 삽입', keys: '', action: 'ed.link' },
                { desc: '이미지 삽입', keys: '', action: 'ed.image' },
                { desc: '들여쓰기', keys: '', action: 'ed.indentIn' },
                { desc: '내어쓰기', keys: '', action: 'ed.indentOut' },
            ]
        },
        {
            section: '탭 이동', items: [
                { desc: '이전 탭', keys: '', action: 'tab.prev' },
                { desc: '다음 탭', keys: '', action: 'tab.next' },
            ]
        },
        {
            section: 'GitHub 연동', items: [
                { desc: 'GitHub 커밋 (현재 파일)', keys: '', action: 'app.ghCommit' },
                { desc: 'GitHub Pull', keys: '', action: 'app.pullGH' },
                { desc: 'GitHub Push', keys: '', action: 'app.pushGH' },
            ]
        },
    ];

    let data = [];
    let editMode = false;

    function load() {
        try {
            const saved = localStorage.getItem(STORAGE_KEY);
            if (saved) {
                const parsed = JSON.parse(saved);
                // action 필드가 없는 구버전(v1) 데이터 → 기본값으로 초기화
                const hasAction = parsed.some(g => g.items && g.items.some(i => i.action !== undefined));
                data = hasAction ? parsed : JSON.parse(JSON.stringify(DEFAULT_DATA));
            } else {
                data = JSON.parse(JSON.stringify(DEFAULT_DATA));
            }
        } catch (e) {
            data = JSON.parse(JSON.stringify(DEFAULT_DATA));
        }
    }

    function save() {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) { }
    }

    /* ── keys 표시 문자열 → hkKey() 정규화 형식 변환 ───────────
       'Ctrl + Shift + Z'  →  'C+S+Z'
       'Alt + ArrowUp'     →  'A+ArrowUp'
       'Tidy 버튼' 같은 비키 항목 → null                         */
    function parseHotkey(keysStr) {
        if (!keysStr) return null;
        // modifier 없이 '버튼', 'Tidy' 등 단순 텍스트는 키 항목이 아님
        const hasMod = /ctrl|shift|alt|cmd|option/i.test(keysStr);
        if (!hasMod && !keysStr.includes('+')) return null;
        const tokens = keysStr.split('+').map(s => s.trim()).filter(Boolean);
        if (tokens.length === 0) return null;
        const mods = [];
        let mainKey = null;
        for (const t of tokens) {
            const lo = t.toLowerCase();
            if (lo === 'ctrl' || lo === 'cmd') mods.push('C');
            else if (lo === 'shift') mods.push('S');
            else if (lo === 'alt' || lo === 'option') mods.push('A');
            else mainKey = t;
        }
        if (!mainKey) return null;
        // 특수 키 이름은 그대로, 단일 문자는 대문자로
        if (mainKey.length === 1) mainKey = mainKey.toUpperCase();
        // 'Space' → 공백 문자로 (hkKey는 e.key=' '를 ' '.toUpperCase()=' '로 반환)
        if (mainKey.toLowerCase() === 'space') mainKey = ' ';
        return [...mods, mainKey].join('+');
    }

    /* ── Shift 조합 시 브라우저 e.key 변환 대응 ────────────────
       Shift+9 → e.key='(' 이므로 canonical 'S+A+9' 외에
       'S+A+(' 도 함께 등록해야 매칭된다.                         */
    const SHIFT_CHAR = {
        '1':'!','2':'@','3':'#','4':'$','5':'%',
        '6':'^','7':'&','8':'*','9':'(','0':')',
        '-':'_','=':'+',
        ';':':',',':'<','.':'>','/':'?',
    };

    function getMatchKeys(keysStr) {
        const base = parseHotkey(keysStr);
        if (!base) return [];
        const results = [base];
        // Shift가 포함된 단일 문자 키: 실제 e.key 변환값도 추가
        const tokens = keysStr.split('+').map(s => s.trim());
        const hasShift = tokens.some(t => t.toLowerCase() === 'shift');
        const mainKey = tokens.find(t => !['ctrl','cmd','shift','alt','option'].includes(t.toLowerCase()));
        if (hasShift && mainKey && mainKey.length === 1) {
            const shifted = SHIFT_CHAR[mainKey.toLowerCase()];
            if (shifted) {
                // 'C+S+9' → 'C+S+(' 형태로 교체
                const alt = base.slice(0, base.lastIndexOf('+') + 1) + shifted.toUpperCase();
                if (alt !== base) results.push(alt);
            }
        }
        return results;
    }

    /* ── dispatch 테이블 빌드 ───────────────────────────────────
       data를 순회하며 { hkKey형식: fn } 매핑을 생성한다.
       save() 또는 resetDefault() 후에 반드시 호출해야 한다.      */
    let _dispatch = {};

    function rebuild() {
        _dispatch = {};
        data.forEach(group => {
            (group.items || []).forEach(item => {
                if (!item.action || !item.keys) return;
                const fn = ACTION_MAP[item.action];
                if (!fn) return;
                getMatchKeys(item.keys).forEach(k => { _dispatch[k] = fn; });
            });
        });
        /* 역방향 맵 갱신 (handleKey의 getActionId에서 사용) */
        _fnToId = new Map();
        Object.entries(ACTION_MAP).forEach(([id, fn]) => { _fnToId.set(fn, id); });
    }

    function getDispatch() { return _dispatch; }
    function getActionMap() { return ACTION_MAP; }

    /* fn → actionId 역방향 조회 캐시 (rebuild() 내에서 갱신) */
    let _fnToId = new Map();

    function getActionId(fn) { return _fnToId.get(fn) || null; }

    function render() {
        const wrap = el('hk-list-wrap');
        wrap.innerHTML = '';
        const actionKeys = Object.keys(ACTION_MAP);
        data.forEach((group, gi) => {
            // 섹션 헤더
            const sec = document.createElement('div');
            sec.className = 'hk-s';
            sec.style.cssText = 'display:flex;align-items:center;gap:6px';
            if (editMode) {
                const inp = document.createElement('input');
                inp.className = 'hk-editable desc';
                inp.style.cssText = 'font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--ac);flex:1';
                inp.value = group.section;
                inp.oninput = () => { data[gi].section = inp.value; };
                const delSec = document.createElement('button');
                delSec.className = 'hk-del-btn';
                delSec.title = '섹션 삭제';
                delSec.textContent = '✕';
                delSec.onclick = () => { data.splice(gi, 1); render(); };
                sec.appendChild(inp);
                sec.appendChild(delSec);
            } else {
                sec.textContent = group.section;
            }
            wrap.appendChild(sec);

            // 그리드
            const grid = document.createElement('div');
            grid.className = editMode ? 'hk-grid edit-mode' : 'hk-grid';
            grid.style.marginBottom = '4px';

            group.items.forEach((item, ii) => {
                const row = document.createElement('div');
                if (editMode) {
                    row.className = 'hk-item-edit';

                    const descInp = document.createElement('input');
                    descInp.className = 'hk-editable desc';
                    descInp.value = item.desc;
                    descInp.oninput = () => { data[gi].items[ii].desc = descInp.value; };

                    const keysInp = document.createElement('input');
                    keysInp.className = 'hk-editable keys';
                    keysInp.value = item.keys;
                    keysInp.placeholder = 'Ctrl + Shift + X';
                    keysInp.title = '예: Ctrl + Z  |  Shift + Alt + ArrowDown  |  Alt + 9';
                    keysInp.oninput = () => { data[gi].items[ii].keys = keysInp.value; };

                    // action 드롭다운 — 핵심: 어떤 기능과 연결할지 선택
                    const actSel = document.createElement('select');
                    actSel.className = 'hk-editable';
                    actSel.style.cssText = 'font-size:10px;padding:2px 4px;background:var(--bg4);color:var(--tx2);border:1px solid var(--bd);border-radius:3px;min-width:90px;max-width:150px;flex-shrink:0';
                    actSel.title = '이 키에 연결할 기능';
                    const emptyOpt = document.createElement('option');
                    emptyOpt.value = '';
                    emptyOpt.textContent = '— 표시용 —';
                    actSel.appendChild(emptyOpt);
                    actionKeys.forEach(ak => {
                        const opt = document.createElement('option');
                        opt.value = ak;
                        opt.textContent = ak;
                        opt.selected = item.action === ak;
                        actSel.appendChild(opt);
                    });
                    actSel.onchange = () => { data[gi].items[ii].action = actSel.value; };

                    const del = document.createElement('button');
                    del.className = 'hk-del-btn';
                    del.title = '행 삭제';
                    del.innerHTML = '🗑';
                    del.onclick = () => { data[gi].items.splice(ii, 1); render(); };

                    row.appendChild(descInp);
                    row.appendChild(keysInp);
                    row.appendChild(actSel);
                    row.appendChild(del);
                } else {
                    row.className = 'hk-item';
                    const keys = item.keys.split('+').map(k => k.trim()).filter(Boolean);
                    row.innerHTML = `<span class="hk-desc">${item.desc}</span><div class="hk-keys">${keys.map(k => `<kbd>${k}</kbd>`).join('')}</div>`;
                }
                grid.appendChild(row);
            });

            // 편집 모드: 이 섹션에 행 추가 버튼
            if (editMode) {
                const addRow = document.createElement('div');
                addRow.style.cssText = 'padding:2px 6px;';
                const addBtn = document.createElement('button');
                addBtn.className = 'btn btn-g btn-sm';
                addBtn.style.cssText = 'font-size:10px;padding:2px 7px;width:100%;opacity:.7';
                addBtn.textContent = '+ 이 섹션에 행 추가';
                addBtn.onclick = () => { data[gi].items.push({ desc: '새 항목', keys: '', action: '' }); render(); };
                addRow.appendChild(addBtn);
                grid.appendChild(addRow);
            }

            wrap.appendChild(grid);
        });

        // 편집 모드: 섹션 추가 버튼
        if (editMode) {
            const addSec = document.createElement('button');
            addSec.className = 'btn btn-g btn-sm';
            addSec.style.cssText = 'width:100%;margin-top:6px;font-size:11px';
            addSec.textContent = '＋ 섹션 추가';
            addSec.onclick = () => { data.push({ section: '새 섹션', items: [{ desc: '항목', keys: '', action: '' }] }); render(); };
            wrap.appendChild(addSec);
        }
    }

    return {
        open() {
            try {
                load(); rebuild(); editMode = false;
                const editBtn = el('hk-edit-btn');
                if (editBtn) { editBtn.textContent = '✎ 편집'; editBtn.classList.remove('btn-p'); editBtn.classList.add('btn-g'); }
                const editHint = el('hk-edit-hint');
                if (editHint) editHint.style.display = 'none';
                const editActions = el('hk-edit-actions');
                if (editActions) editActions.style.display = 'none';
                /* 로그인 후에만 설정(비밀번호 변경 / 앱 잠금) 표시 */
                const settingsRow = document.getElementById('hk-settings-row');
                const btnChangePw = document.getElementById('hk-btn-change-pw');
                const btnLock = document.getElementById('hk-btn-lock');
                if (settingsRow && typeof AppLock !== 'undefined') {
                    const unlocked = AppLock.isUnlocked();
                    const hasLock = AppLock.hasLock();
                    settingsRow.style.display = 'flex';
                    if (btnChangePw) {
                        if (hasLock) {
                            btnChangePw.textContent = '🔑 비밀번호 변경';
                            btnChangePw.onclick = function() { App.hideHK(); AppLock.showChangePw(); };
                            btnChangePw.style.display = '';
                        } else {
                            btnChangePw.textContent = '🔑 비밀번호 설정';
                            btnChangePw.onclick = function() { App.hideHK(); AppLock.showSetPw(); };
                            btnChangePw.style.display = '';
                        }
                    }
                    if (btnLock) {
                        btnLock.style.display = hasLock ? '' : 'none';
                    }
                    const autolockInp = document.getElementById('hk-autolock-input');
                    if (autolockInp) autolockInp.value = AppLock.getAutoLockMinutes();
                } else if (settingsRow) {
                    settingsRow.style.display = 'none';
                }
                /* 다중선택 span방식 (설정, 기본 ON) - 로그인 여부와 무관하게 표시 */
                const spanChk = document.getElementById('hk-me-spanmethod');
                if (spanChk) {
                    spanChk.checked = localStorage.getItem('mdpro_me_spanmethod') !== '0';
                    spanChk.onchange = function() { try { localStorage.setItem('mdpro_me_spanmethod', spanChk.checked ? '1' : '0'); } catch (e) {} };
                }
                /* 에디터 현재 줄 하이라이트 행 항상 표시 */
                const lineHighlightRow = document.getElementById('hk-line-highlight-row');
                if (lineHighlightRow) lineHighlightRow.style.display = 'flex';
                render();
                el('hk-overlay').classList.add('vis');
                try { if (typeof EditorLineHighlight !== 'undefined') EditorLineHighlight.updateUI(); } catch (e) { console.warn('EditorLineHighlight.updateUI:', e); }
                try { if (typeof EditorAutoPair !== 'undefined') EditorAutoPair.updateUI(); } catch (e) { console.warn('EditorAutoPair.updateUI:', e); }
                try { if (typeof AuthorInfo !== 'undefined') AuthorInfo.loadToPanel(); } catch (e) { console.warn('AuthorInfo.loadToPanel:', e); }
            } catch (err) {
                console.error('HK.open:', err);
                const ov = el('hk-overlay');
                if (ov) ov.classList.add('vis');
            }
        },
        close() {
            el('hk-overlay').classList.remove('vis');
            editMode = false;
        },
        toggleEdit() {
            editMode = !editMode;
            const btn = el('hk-edit-btn');
            if (editMode) {
                btn.textContent = '✓ 완료';
                btn.classList.add('btn-p');
                btn.classList.remove('btn-g');
                el('hk-edit-hint').style.display = 'block';
                el('hk-edit-actions').style.display = 'flex';
            } else {
                // 완료 → 저장 + dispatch 재빌드
                save(); rebuild();
                btn.textContent = '✎ 편집';
                btn.classList.remove('btn-p');
                btn.classList.add('btn-g');
                el('hk-edit-hint').style.display = 'none';
                el('hk-edit-actions').style.display = 'none';
            }
            render();
        },
        addRow() {
            if (data.length === 0) data.push({ section: '기타', items: [] });
            data[data.length - 1].items.push({ desc: '새 항목', keys: '', action: '' });
            render();
        },
        saveEdit() {
            save(); rebuild(); editMode = false;
            el('hk-edit-btn').textContent = '✎ 편집';
            el('hk-edit-btn').classList.remove('btn-p');
            el('hk-edit-btn').classList.add('btn-g');
            el('hk-edit-hint').style.display = 'none';
            el('hk-edit-actions').style.display = 'none';
            render();
        },
        resetDefault() {
            if (!confirm('단축키 목록을 기본값으로 되돌리겠습니까?')) return;
            data = JSON.parse(JSON.stringify(DEFAULT_DATA));
            save(); rebuild(); render();
        },
        /* 앱 초기화 시 App.init()에서 호출 — open() 없이도 dispatch 테이블 구성 */
        _initDispatch() {
            load();
            rebuild();
        },
        getDispatch,
        getActionMap,
        getActionId,
    };
})();


function hkKey(e) {
    const mac = navigator.platform.toUpperCase().includes('MAC');
    const ctrl = mac ? e.metaKey : e.ctrlKey;
    const parts = [];
    if (ctrl) parts.push('C');
    if (e.shiftKey) parts.push('S');
    if (e.altKey) parts.push('A');
    /* Alt+숫자 시 e.key가 %^ 등으로 오므로, Digit 키는 e.code로 숫자 사용 */
    let mainKey = e.key;
    if (e.altKey && e.code && /^Digit\d$/.test(e.code)) mainKey = e.code.replace('Digit', '');
    /* Shift+Ctrl+숫자 시 e.key가 !@# 등으로 오므로, Digit는 e.code로 숫자 사용 (전체 테마 단축키 등 매칭) */
    else if ((ctrl || e.ctrlKey || e.metaKey) && e.shiftKey && e.code && /^Digit\d$/.test(e.code)) mainKey = e.code.replace('Digit', '');
    else if (e.key && e.key.length === 1) mainKey = e.key.toUpperCase();
    parts.push(mainKey);
    return parts.join('+');
}

function handleKey(e) {
    const edi = el('editor');
    const inEd = document.activeElement === edi;
    const k = hkKey(e);

    /* ── 괄호·따옴표 자동쌍 & 선택 감싸기: ( [ " ' (설정 ON일 때만) ── */
    if (inEd && typeof EditorAutoPair !== 'undefined' && EditorAutoPair.handleKey(e)) return;

    /* ── Ctrl+H: 찾기/바꾸기 (브라우저 히스토리 등에 빼앗기지 않도록 우선 처리) ── */
    if ((e.ctrlKey || e.metaKey) && e.key && e.key.toLowerCase() === 'h') {
        e.preventDefault();
        e.stopPropagation();
        if (typeof App !== 'undefined' && App.toggleFind) App.toggleFind();
        return;
    }

    /* ── Alt+4: 전체 다크/라이트 토글 (항상 동작) ── */
    if (e.altKey && !e.ctrlKey && !e.metaKey && (e.code === 'Digit4' || e.key === '4')) {
        e.preventDefault();
        if (typeof App !== 'undefined' && App.toggleTheme) App.toggleTheme();
        return;
    }

    /* ── Ctrl+9: 에디터 축소, Ctrl+0: 에디터 확대 ── */
    if ((e.ctrlKey || e.metaKey) && e.key === '9') { e.preventDefault(); EZ.dec(); return; }
    if ((e.ctrlKey || e.metaKey) && e.key === '0') { e.preventDefault(); EZ.inc(); return; }

    /* ── Tab / Shift+Tab: 에디터 들여쓰기 (표 안이면 셀 이동 우선) ──────
       표 안 → tabInTable()이 처리 (셀 이동)
       표 밖 + 선택 없음:
           Tab        → 커서 위치에 공백 2칸 삽입
           Shift+Tab  → 줄 앞 공백 2칸 제거
       표 밖 + 다중 줄 선택:
           Tab        → 선택된 각 줄 앞에 공백 2칸 추가
           Shift+Tab  → 선택된 각 줄 앞 공백 2칸 제거
    ─────────────────────────────────────────────────────────────── */
    if (e.key === 'Tab' && inEd) {
        if (ED.tabInTable(edi, e)) return;   // 표 안: 셀 이동
        e.preventDefault();
        const val = edi.value;
        const ss = edi.selectionStart;
        const se = edi.selectionEnd;
        const INDENT = '  ';                  // 공백 2칸

        if (ss === se) {
            /* 선택 없음: 커서 위치에 공백 삽입 or 줄 앞 제거 */
            if (e.shiftKey) {
                const ls = val.lastIndexOf('\n', ss - 1) + 1;
                if (val.slice(ls, ls + INDENT.length) === INDENT) {
                    edi.value = val.slice(0, ls) + val.slice(ls + INDENT.length);
                    edi.setSelectionRange(Math.max(ls, ss - INDENT.length), Math.max(ls, ss - INDENT.length));
                }
            } else {
                edi.value = val.slice(0, ss) + INDENT + val.slice(se);
                edi.setSelectionRange(ss + INDENT.length, ss + INDENT.length);
            }
        } else {
            /* 다중 줄 선택: 각 줄 일괄 indent / dedent */
            const ls = val.lastIndexOf('\n', ss - 1) + 1;   // 선택 첫 줄 시작
            const block = val.slice(ls, se);
            let newBlock;
            if (e.shiftKey) {
                newBlock = block.replace(/^  /gm, '');
            } else {
                newBlock = block.replace(/^/gm, INDENT);
            }
            const delta = newBlock.length - block.length;
            edi.value = val.slice(0, ls) + newBlock + val.slice(se);
            edi.setSelectionRange(ls, se + delta);
        }
        US.snap(); TM.markDirty(); App.render();
        return;
    }

    /* ── Enter: 표 행 자동 추가 비활성화 (행 추가는 툴바 +행 버튼 사용) ── */
    // if (e.key === 'Enter' && inEd) { if (ED.enterInTable(edi, e)) return; }

    /* ── Alt+Enter: 현재 줄 목록 수준 유지하며 줄바꿈 ──────────────────────
       - "  - 내용"   → "\n  - "  (같은 indent + bullet)
       - "  1. 내용"  → "\n  2. " (같은 indent + 다음 번호)
       - "  - [ ] "   → "\n  - [ ] " (체크박스)
       - prefix 없음  → "\n" 일반 줄바꿈
    ─────────────────────────────────────────────────────────────────────── */
    if (e.altKey && e.key === 'Enter' && inEd) {
        e.preventDefault();
        const { text } = getCL(edi);
        const pos = edi.selectionStart;
        const m = text.match(/^(\s*)([-*+]\s+(?:\[[ xX]\]\s+)?|(\d+)\.\s+)/);
        let insertion;
        if (m) {
            const indent = m[1];
            const num    = m[3];
            if (num !== undefined) {
                insertion = '\n' + indent + (parseInt(num, 10) + 1) + '. ';
            } else if (/\[[ xX]\]/.test(m[2])) {
                insertion = '\n' + indent + '- [ ] ';
            } else {
                insertion = '\n' + indent + m[2];
            }
        } else {
            insertion = '\n';
        }
        ins(edi, pos, edi.selectionEnd, insertion);
        return;
    }

    /* ── Alt+5 / Alt+6: 목록 변환 (Windows 등에서 e.key가 %^ 로 오므로 e.code로만 판별) ── */
    if (inEd && e.altKey && !e.ctrlKey && !e.metaKey &&
        (e.code === 'Digit5' || e.code === 'Digit6')) {
        e.preventDefault();
        e.stopPropagation();
        if (e.code === 'Digit5') ED.textToList();
        else ED.textToNumberedList();
        return;
    }

    /* ── Alt+I: 이미지 링크 만들기 (선택 URL → HTML img) ── */
    if (e.altKey && !e.ctrlKey && !e.metaKey && (e.key === 'i' || e.key === 'I')) {
        e.preventDefault();
        if (typeof App !== 'undefined' && App.makeImageLink) App.makeImageLink();
        return;
    }

    const dispatch = HK.getDispatch();
    const fn = dispatch[k];
    if (!fn) return;

    /* ── action prefix로 전역/에디터 전용 분기 ─────────────────
       view.* / app.* / fs.*  → 전역: 에디터 포커스와 무관하게 실행
       ed.*                   → 에디터 전용: 에디터에 포커스가 있을 때만 실행
       이 구분 덕분에 Alt+3으로 preview 전환 후에도 Alt+1,2가 정상 동작함 */
    const actionId = HK.getActionId(fn);
    const isGlobal = actionId && !actionId.startsWith('ed.');

    if (isGlobal) {
        e.preventDefault();
        fn();
    } else if (inEd) {
        e.preventDefault();
        fn();
    }
    /* ed.* 이고 에디터 포커스가 없으면: preventDefault 없이 return → 브라우저 기본 동작 유지 */
}


/* ═══════════════════════════════════════════════════════════
   TOOLTIP
═══════════════════════════════════════════════════════════ */
function initTooltip() {
    const tip = el('tooltip'); let t;
    document.addEventListener('mouseover', e => { const target = e.target.closest('[data-tooltip]'); if (!target) return; clearTimeout(t); t = setTimeout(() => { const key = target.dataset.key; tip.innerHTML = target.dataset.tooltip + (key ? ` <span class="tt-key">${key}</span>` : ''); tip.classList.add('vis'); let x = e.clientX + 12, y = e.clientY + 16; if (x + 260 > window.innerWidth) x = e.clientX - 260; if (y + 40 > window.innerHeight) y = e.clientY - 40; tip.style.left = x + 'px'; tip.style.top = y + 'px' }, 300) });
    document.addEventListener('mouseout', () => { clearTimeout(t); tip.classList.remove('vis') });
}

/* ═══════════════════════════════════════════════════════════
   ERROR DETECTION
═══════════════════════════════════════════════════════════ */
function detectErrors(md) {
    const errs = []; const lines = md.split('\n');
    function colCount(line) {
        const parts = line.split('|').map(c => c.trim());
        if (parts[0] === '' && parts[parts.length - 1] === '') return parts.length - 2;
        return parts.length;
    }
    lines.forEach((l, i) => {
        if (!l.startsWith('|')) return;
        const cols = colCount(l);
        if (i > 0 && lines[i - 1].startsWith('|')) {
            const prev = colCount(lines[i - 1]);
            if (prev !== cols && !l.includes('---') && !lines[i - 1].includes('---'))
                errs.push(`줄 ${i + 1}: 표 열 불일치 (이전 ${prev}, 현재 ${cols})`);
        }
    });
    if ((md.match(/^```/gm) || []).length % 2 !== 0) errs.push('코드 블록 미닫힘 (``` 누락)');
    return errs;
}

/* ═══════════════════════════════════════════════════════════
   MAIN APP
═══════════════════════════════════════════════════════════ */
const App = {
    rm: false, rt: null, colorMode: 'text', capType: 'table',

    init() {
        TM.init(); CM.load(); initTooltip(); SS.init(); FS.update(); LN.init(); EZ.init();
        if (typeof EditorLineHighlight !== 'undefined') EditorLineHighlight.init();
        if (typeof EditorAutoPair !== 'undefined') EditorAutoPair.init();
        SB.init();  /* 저장된 소스 탭(로컬/GitHub) 복원 */
        /* 테마 복원: 전체 / 에디터 / PV 각각 */
        try {
            const globalTheme = localStorage.getItem('mdpro_theme');
            if (globalTheme === 'light') document.documentElement.dataset.theme = 'light';
            const edTheme = localStorage.getItem('mdpro_editor_theme');
            const ep = document.getElementById('editor-pane');
            if (ep && edTheme) ep.dataset.editorTheme = edTheme;
            if (typeof PV !== 'undefined' && PV.initTheme) PV.initTheme();
        } catch (e) {}
        App._updateEditorThemeBtn();
        /* FM.restore는 DOMContentLoaded에서 별도 호출 */
        /* HK 초기화: 앱 시작 시 load + rebuild 해야 핫키가 작동함 */
        try { HK._initDispatch(); } catch(e) {}
        /* Ctrl+H: 찾기/바꾸기 — 캡처 단계에서 선점해 브라우저(히스토리 등)에 빼앗기지 않도록 */
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key && e.key.toLowerCase() === 'h') {
                e.preventDefault();
                e.stopPropagation();
                App.toggleFind();
            }
        }, true);
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.altKey && e.key && e.key.toLowerCase() === 'k') {
                const edi = el('editor');
                if (edi && document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
                    e.preventDefault();
                    e.stopPropagation();
                    App.toggleMultiEditBar();
                }
            }
        }, true);
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const meBar = el('multi-edit-bar');
                if (meBar && meBar.classList.contains('vis')) {
                    e.preventDefault();
                    App.multiEditApply();
                    return;
                }
                if (document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
                    e.preventDefault();
                    App.toggleMultiEditBar();
                }
            }
        }, true);
        // Set default view button state
        const splitBtn = el('vm-split'); if (splitBtn) splitBtn.classList.add('active');
        const edi = el('editor');
        /* 한글 NFD(분리형) 방지: 삽입 시 NFC 강제 */
        edi.addEventListener('beforeinput', (e) => {
            if (e.data != null && typeof e.data === 'string' && e.data.length > 0) {
                const nfcStr = e.data.normalize('NFC');
                if (nfcStr !== e.data) {
                    e.preventDefault();
                    const ss = edi.selectionStart, se = edi.selectionEnd;
                    edi.setRangeText(nfcStr, ss, se, 'end');
                }
            }
        }, true);
        /* IME 조합 종료 시 문서 전체 NFC 정리(커서 위치 보존) */
        edi.addEventListener('compositionend', () => {
            const v0 = edi.value;
            const v1 = v0.normalize('NFC');
            if (v0 === v1) return;
            const ss = edi.selectionStart, se = edi.selectionEnd;
            const leftCtx = v0.slice(Math.max(0, ss - 30), ss).normalize('NFC');
            edi.value = v1;
            const pos = v1.indexOf(leftCtx);
            const newStart = pos >= 0 ? pos + leftCtx.length : Math.min(ss, v1.length);
            edi.setSelectionRange(newStart, newStart);
            if (typeof US !== 'undefined' && US.snap) US.snap();
            if (typeof TM !== 'undefined' && TM.markDirty) TM.markDirty();
            if (typeof App !== 'undefined' && App.render) App.render();
        });
        edi.addEventListener('input', () => {
            US.snap(); TM.markDirty(); this.render(); if (el('find-bar').classList.contains('vis') && el('fi').value) { clearTimeout(this._findHighlightT); this._findHighlightT = setTimeout(() => App.updateFindHighlight(), 120); } });
        edi.addEventListener('keydown', handleKey);
        /* Alt+5 / Alt+6: 캡처 단계에서 처리해 브라우저 메뉴 등에 빼앗기지 않도록 */
        document.addEventListener('keydown', e => {
            if (document.activeElement !== edi) return;
            if (!e.altKey || e.ctrlKey || e.metaKey) return;
            if (e.code === 'Digit5') { e.preventDefault(); e.stopPropagation(); ED.textToList(); }
            else if (e.code === 'Digit6') { e.preventDefault(); e.stopPropagation(); ED.textToNumberedList(); }
        }, true);
        edi.addEventListener('keyup', () => { this.updCursor(); SS.onCursor(); });
        edi.addEventListener('click', () => {
            this.updCursor(); SS.onCursor();
        });
        edi.addEventListener('scroll', () => { LN.update(); ScrollSync.onEditor(); const hl = document.getElementById('editor-find-highlight'); if (hl && hl.style.display === 'block') { hl.scrollTop = edi.scrollTop; hl.scrollLeft = edi.scrollLeft; } }, { passive: true });
        document.addEventListener('selectionchange', () => { if (document.activeElement === edi) this.updFmtBtns() });
        document.addEventListener('keydown', e => { if (document.activeElement !== edi) handleKey(e) });
        const fiEl = document.getElementById('fi');
        if (fiEl) { fiEl.addEventListener('input', () => { App._findStart = undefined; App.updateFindHighlight(); }); }
        el('doc-title').addEventListener('input', () => { TM.markDirty(); this.render(); });
        setInterval(() => PW.checkClosed(), 2000);

        // Build template grid
        el('tmpl-grid').innerHTML = TMPLS.map((t, i) => `<div class="tmpl-card" onclick="App.insertTmpl(${i})"><h4>${t.icon} ${t.name}</h4><p>${t.desc}</p></div>`).join('');

        if (!edi.value) edi.value = this.sample();
        this.render(); US.snap();

/* ── Split Resizer 초기화 ──────────────────────────────── */
(function initSplitResizer() {
    const resizer    = document.getElementById('split-resizer');
    const edPane     = document.getElementById('editor-pane');
    const pvPane     = document.getElementById('preview-pane');
    const wrap       = document.getElementById('editor-wrap');
    if (!resizer || !edPane || !pvPane || !wrap) return;

    /* 저장된 비율 복원 */
    const saved = parseFloat(localStorage.getItem('mdpro_split_ratio') || '0.5');
    function applyRatio(r) {
        r = Math.max(0.15, Math.min(0.85, r));
        edPane.style.flex  = 'none';
        pvPane.style.flex  = 'none';
        edPane.style.width = (r * 100).toFixed(2) + '%';
        pvPane.style.width = ((1 - r) * 100).toFixed(2) + '%';
    }
    applyRatio(saved);

    /* 숨김 패널일 때는 flex 리셋 */
    const resetFlex = () => {
        if (edPane.classList.contains('hidden')) { pvPane.style.flex = '1'; pvPane.style.width = ''; }
        else if (pvPane.classList.contains('hidden')) { edPane.style.flex = '1'; edPane.style.width = ''; }
    };

    let startX = 0, startEdW = 0, totalW = 0, dragging = false;

    function startDrag(clientX) {
        if (edPane.classList.contains('hidden') || pvPane.classList.contains('hidden')) return;
        dragging  = true;
        startX    = clientX;
        startEdW  = edPane.getBoundingClientRect().width;
        totalW    = wrap.getBoundingClientRect().width - resizer.offsetWidth;
        document.body.classList.add('resizing');
        resizer.classList.add('dragging');
    }
    function moveDrag(clientX) {
        if (!dragging) return;
        const dx    = clientX - startX;
        const newW  = Math.max(120, Math.min(totalW - 120, startEdW + dx));
        const ratio = newW / totalW;
        applyRatio(ratio);
    }
    function endDrag() {
        if (!dragging) return;
        dragging = false;
        document.body.classList.remove('resizing');
        resizer.classList.remove('dragging');
        const r = edPane.getBoundingClientRect().width / (wrap.getBoundingClientRect().width - resizer.offsetWidth);
        localStorage.setItem('mdpro_split_ratio', r.toFixed(4));
    }

    resizer.addEventListener('mousedown', e => {
        if (e.button !== 0) return;
        e.preventDefault();
        startDrag(e.clientX);
    });

    document.addEventListener('mousemove', e => {
        if (!dragging) return;
        moveDrag(e.clientX);
    });

    document.addEventListener('mouseup', e => {
        endDrag();
    });

    /* 터치: 모바일에서 에디터·미리보기 구분선 조절 (리사이저에서만 시작, UI 내에서만 동작) */
    resizer.addEventListener('touchstart', e => {
        if (e.touches.length !== 1) return;
        e.preventDefault();
        startDrag(e.touches[0].clientX);
    }, { passive: false });

    document.addEventListener('touchmove', e => {
        if (!dragging) return;
        if (e.touches.length !== 1) return;
        e.preventDefault();
        moveDrag(e.touches[0].clientX);
    }, { passive: false });

    document.addEventListener('touchend', endDrag);
    document.addEventListener('touchcancel', endDrag);

    /* 더블클릭: 50:50 리셋 */
    resizer.addEventListener('dblclick', () => {
        applyRatio(0.5);
        localStorage.setItem('mdpro_split_ratio', '0.5');
    });

    /* setView 호출 시 flex 리셋 필요 */
    const origSetView = App.setView.bind(App);
    App.setView = function(m) {
        origSetView(m);
        edPane.style.flex = ''; edPane.style.width = '';
        pvPane.style.flex = ''; pvPane.style.width = '';
        if (m === 'split') {
            const r = parseFloat(localStorage.getItem('mdpro_split_ratio') || '0.5');
            applyRatio(r);
        }
        resetFlex();
    };
})();
    },

    render() {
        const edi = el('editor'); const md = edi.value, title = el('doc-title').value;
        clearTimeout(this.rt);
        this.rt = setTimeout(() => { Render.run(md, title); }, 120);
        this.updCursor();
    },

    updCursor() { CursorUI.updCursor(); },
    updFmtBtns() { CursorUI.updFmtBtns(); },
    showErrs(errs) { const ec = el('error-count'), sep = el('ec-sep'), list = el('ep-list'), panel = el('error-panel'); if (!errs.length) { ec.textContent = ''; sep.style.display = 'none'; panel.classList.remove('vis'); return } ec.textContent = `⚠ ${errs.length}개 오류`; sep.style.display = 'block'; list.innerHTML = errs.map(e => `<div class="error-item">${e}</div>`).join('') },
    toggleErr() { el('error-panel').classList.toggle('vis') }, closeErr() { el('error-panel').classList.remove('vis') },
    toggleSidebar() { el('app').classList.toggle('ns') },
    setView(m) { el('editor-pane').classList.toggle('hidden', m === 'preview'); el('preview-pane').classList.toggle('hidden', m === 'editor') },
    setViewCycle(m) {
        this.setView(m);
        ['split', 'editor', 'preview'].forEach(v => { const b = el('vm-' + v); if (b) b.classList.toggle('active', v === m) });
    },
    toggleTheme() {
        const isLight = document.documentElement.dataset.theme === 'light';
        const nextLight = !isLight;
        document.documentElement.dataset.theme = nextLight ? 'light' : '';
        const ep = document.getElementById('editor-pane');
        if (ep) ep.dataset.editorTheme = nextLight ? 'light' : 'dark';
        if (typeof PV !== 'undefined' && PV.setDark) PV.setDark(!nextLight);
        try {
            localStorage.setItem('mdpro_theme', nextLight ? 'light' : 'dark');
            localStorage.setItem('mdpro_editor_theme', nextLight ? 'light' : 'dark');
        } catch (e) {}
        App._updateEditorThemeBtn();
    },
    setTheme(theme) {
        const isLight = theme === 'light';
        document.documentElement.dataset.theme = isLight ? 'light' : '';
        const ep = document.getElementById('editor-pane');
        if (ep) ep.dataset.editorTheme = isLight ? 'light' : 'dark';
        if (typeof PV !== 'undefined' && PV.setDark) PV.setDark(!isLight);
        try {
            localStorage.setItem('mdpro_theme', isLight ? 'light' : 'dark');
            localStorage.setItem('mdpro_editor_theme', isLight ? 'light' : 'dark');
        } catch (e) {}
        App._updateEditorThemeBtn();
    },
    toggleEditorTheme() {
        const ep = document.getElementById('editor-pane');
        if (!ep) return;
        const cur = ep.dataset.editorTheme || (document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');
        const next = cur === 'light' ? 'dark' : 'light';
        ep.dataset.editorTheme = next;
        try { localStorage.setItem('mdpro_editor_theme', next); } catch (e) {}
        App._updateEditorThemeBtn();
    },
    _updateEditorThemeBtn() {
        const ep = document.getElementById('editor-pane');
        const btn = document.getElementById('ed-theme-btn');
        if (!btn) return;
        const isLight = ep ? (ep.dataset.editorTheme === 'light') : (document.documentElement.dataset.theme === 'light');
        btn.textContent = isLight ? '◐' : '◑';
        btn.title = isLight ? '에디터 라이트 (클릭 시 다크)' : '에디터 다크 (클릭 시 라이트)';
    },
    toggleRM() { this.rm = !this.rm; el('rm-badge').classList.toggle('vis', this.rm); el('mode-ind').textContent = this.rm ? 'RESEARCH' : 'NORMAL'; PR.rm = this.rm; PW.setRM(this.rm); this.render() },
    showHK() { HK.open() }, hideHK() { HK.close() },
    showCode() { el('code-modal').classList.add('vis') },
    showLink() { el('link-modal').classList.add('vis'); setTimeout(() => el('link-text').focus(), 50) },
    showImg() {
        // reset drop zone
        el('img-drop-text').textContent = '🖼 클릭 또는 드래그';
        el('img-drop-text').style.color = '';
        el('img-dropzone').style.borderColor = ''; el('img-dropzone').style.background = '';
        if (typeof AiImage !== 'undefined') AiImage.switchTab('insert');
        _showImgpv(el('img-url') ? el('img-url').value.trim() : '');
        _bindImgUrlToImgpv();
        _bindImgCodeToPreview();
        el('image-modal').classList.add('vis'); setTimeout(() => el('img-alt').focus(), 50);
    },
    makeImageLink() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        let url = (ed.value.slice(s, e) || '').trim();
        if (!url) {
            alert('URL을 선택한 뒤 Alt+I를 누르거나 🖼 링크 버튼을 누르세요.');
            return;
        }
        if (!/^https?:\/\//i.test(url) && !/^data:image\//i.test(url)) {
            alert('선택한 내용이 URL이 아닙니다.\nhttps://... 또는 data:image/... 형식을 선택해 주세요.');
            return;
        }
        const isImageUrl = /^data:image\//i.test(url) || /\.(jpe?g|png|gif|webp|svg|bmp|ico)(\?.*)?$/i.test(url);
        let tag;
        if (isImageUrl) {
            const width = '500';
            const esc = url.replace(/"/g, '&quot;');
            tag = '<img src="' + esc + '" border="0" width="' + width + '">';
        } else {
            const label = prompt('링크 표시 텍스트 (비우면 URL 그대로 표시):', '');
            if (label === null) return;
            const text = label.trim() !== '' ? label.trim() : url;
            const escHref = url.replace(/"/g, '&quot;').replace(/&/g, '&amp;');
            const escText = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
            tag = '<a href="' + escHref + '">' + escText + '</a>';
        }
        if (typeof ED !== 'undefined' && typeof ED.ins === 'function') {
            ED.ins(ed, s, e, tag);
        } else {
            ed.setRangeText(tag, s, e, 'end');
        }
        if (typeof US !== 'undefined' && US.snap) US.snap();
        if (typeof TM !== 'undefined' && TM.markDirty) TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    openSelectionAsLink() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        const text = (ed.value.slice(s, e) || '').trim();
        if (!text) {
            alert('링크로 넣을 URL 또는 텍스트를 선택한 뒤 Shift+Alt+I를 누르거나 🔗 새창 버튼을 누르세요.');
            return;
        }
        let href, label;
        if (/^https?:\/\//i.test(text)) {
            href = text;
            const input = prompt('링크 표시 텍스트 (비우면 URL 그대로 표시):', '');
            if (input === null) return;
            label = input.trim() !== '' ? input.trim() : text;
        } else {
            const urlInput = prompt('링크 URL:', text);
            if (urlInput === null) return;
            href = (urlInput || '').trim() || text;
            const textInput = prompt('링크 표시 텍스트 (비우면 URL 표시):', text);
            if (textInput === null) return;
            label = (textInput || '').trim() !== '' ? textInput.trim() : href;
        }
        const escHref = href.replace(/"/g, '&quot;').replace(/&/g, '&amp;');
        const escLabel = label.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        const tag = '<a href="' + escHref + '" target="_blank" rel="noopener">' + escLabel + '</a>';
        if (typeof ED !== 'undefined' && typeof ED.ins === 'function') {
            ED.ins(ed, s, e, tag);
        } else {
            ed.setRangeText(tag, s, e, 'end');
        }
        ed.focus();
        if (typeof US !== 'undefined' && US.snap) US.snap();
        if (typeof TM !== 'undefined' && TM.markDirty) TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    showCite() { CM.open(); el('cite-modal').classList.add('vis') },
    showStats() { STATS.show() },
    /* ── 스마트 저장 (Ctrl+S) ──────────────────────────── */
    async smartSave() {
        const tab = TM.getActive();
        if (!tab) return;
        if (tab.ghPath) { App._openGHSaveModal(tab); return; }
        /* 파일핸들 있으면 바로 덮어쓰기 */
        if (tab._fileHandle) {
            try {
                const perm = await tab._fileHandle.queryPermission({ mode: 'readwrite' });
                if (perm === 'granted') {
                    const wr = await tab._fileHandle.createWritable();
                    await wr.write(el('editor').value);
                    await wr.close();
                    TM.markClean(tab.id); TM.renderTabs();
                    App._toast('\u{1F4BE} \uC800\uC7A5\uB428 \u2014 ' + tab.title);
                    return;
                }
            } catch(e) { /* 권한 없으면 폴백 */ }
        }
        App.showSaveDlg();
    },
    showSaveDlg() {
        const tab = TM.getActive();
        if (tab && tab.ghPath) { App._openGHSaveModal(tab); return; }
        const infoEl = el('save-current-info');
        const pathEl = el('save-current-path');
        if (infoEl && pathEl) {
            if (tab && (tab.filePath || tab._fileHandle)) {
                pathEl.textContent = tab.filePath || tab.title;
                infoEl.style.display = '';
            } else { infoEl.style.display = 'none'; }
        }
        el('save-modal').classList.add('vis');
    },
    /* ── GitHub 커밋 (저장 모달 → Git 버튼) ─────────── */
    async saveAndGitCommit() {
        App.hideModal('save-modal');
        const tab = TM.getActive();
        if (!tab) return;
        if (!GH.isConnected()) {
            alert('GitHub\uC774 \uC5F0\uACB0\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4.\n\uD83D\uDC19 GitHub \uD0ED \u2192 \uC124\uC815\uC5D0\uC11C \uBA3C\uC800 \uC5F0\uACB0\uD558\uC138\uC694.');
            return;
        }
        if (!tab.ghPath) {
            const ghCfg = GH.cfg;
            const titleHasExt = /\.[a-zA-Z0-9]+$/.test(tab.title || '');
            const fname = (tab.title || 'untitled') + (titleHasExt ? '' : '.md');
            const basePart = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
            const ghPath = basePart + fname;
            const ok = confirm(`GitHub에 새 파일로 커밋합니다.\n\n경로: ${ghPath}\n\n계속하시겠습니까?`);
            if (!ok) return;
            tab.ghPath   = ghPath;
            tab.ghBranch = ghCfg.branch;
        }
        App._openGHSaveModal(tab);
    },
    showModal(id)  { el(id).classList.add('vis'); },

    /* ── GitHub 저장 모달 열기 ──────────────────────────── */
    _openGHSaveModal(tab) {
        if (!tab) return;

        /* ── 전체 경로 계산 ──────────────────────────────────
           tab.ghPath 가 있으면 그대로 사용,
           없으면 GH basePath + title + .md 로 자동 조합
           ※ tab.title 에 이미 .md 가 있으면 중복 추가 방지  */
        const ghCfg    = GH.cfg || {};
        const basePart = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';

        let fullPath;
        if (tab.ghPath) {
            fullPath = tab.ghPath;
        } else {
            /* title에 확장자가 있으면 그대로, 없으면 .md 추가 */
            const titleHasExt = /\.[a-zA-Z0-9]+$/.test(tab.title || '');
            const fname = (tab.title || 'untitled') + (titleHasExt ? '' : '.md');
            fullPath = basePart + fname;
        }

        /* 파일 경로 입력란 — 전체 경로(폴더/파일명) 자동 채움 + 수정 가능 */
        const pathInput = el('gh-save-file-path');
        if (pathInput) pathInput.value = fullPath;

        /* 파일명 변경 감지 */
        const origPath  = tab.ghPath;
        const origName  = origPath ? origPath.split('/').pop().replace(/\.[^.]+$/, '') : null;
        const curName   = tab.title ? tab.title.replace(/\.[^.]+$/, '') : tab.title; // 확장자 제거 후 비교
        const nameChanged = origName && origName !== curName;

        const notice = el('gh-rename-notice');
        const detail = el('gh-rename-detail');
        if (notice && detail) {
            if (nameChanged) {
                const origExt  = origPath ? '.' + origPath.split('.').pop() : '.md';
                const newPath  = origPath.replace(/[^/]+$/, '') + curName + origExt;
                detail.textContent = `${origPath} → ${newPath}`;
                notice.style.display = '';
                notice.dataset.oldPath = origPath;
                notice.dataset.newPath = newPath;
                if (pathInput) pathInput.value = newPath;
            } else {
                notice.style.display = 'none';
            }
        }

        /* 기본 커밋 메시지 — 전체 경로 기준 */
        const msgInput = el('gh-save-commit-msg');
        if (msgInput) {
            const finalPath = (notice && notice.style.display !== 'none')
                ? notice.dataset.newPath : fullPath;
            msgInput.value = nameChanged
                ? `Rename ${origPath} → ${notice.dataset.newPath}`
                : `Update ${fullPath}`;
        }

        /* 커밋 버튼 레이블 */
        const commitBtn = el('gh-save-commit-btn');
        if (commitBtn) commitBtn.textContent = nameChanged ? '🐙 커밋 (파일명 변경)' : '🐙 GitHub 커밋';

        /* 기기명 자동 삽입 */
        const device = localStorage.getItem('mdpro_device_name');
        if (device && msgInput && !msgInput.value.includes('[device:')) {
            msgInput.value += ` [device:${device}]`;
        }

        el('gh-save-modal').classList.add('vis');
    },

    /* ── GitHub 커밋 실행 ───────────────────────────────── */
    async ghSaveCommit() {
        const tab = TM.getActive();
        if (!tab) return;
        const msg      = el('gh-save-commit-msg').value.trim();
        const notice   = el('gh-rename-notice');

        /* 경로 입력란에서 사용자가 수정했을 수 있으므로 최신값 읽기 */
        const pathInput = el('gh-save-file-path');
        const inputPath = pathInput ? pathInput.value.trim() : null;
        const origPath  = tab.ghPath;
        const pathChanged = inputPath && inputPath !== origPath;

        /* 경로가 변경된 경우 rename 처리, 아니면 nameChanged 기존 로직 유지 */
        const nameChanged = (!pathChanged) && notice && notice.style.display !== 'none';

        App.hideModal('gh-save-modal');

        if (pathChanged && origPath) {
            /* 경로(파일명/폴더) 변경 커밋 */
            const content = el('editor').value;
            try {
                const result = await GH.renameAndCommit(origPath, inputPath, content, msg || `Rename ${origPath} → ${inputPath}`);
                tab.ghPath  = inputPath;
                tab.ghSha   = null;
                TM.markClean(tab.id);
                TM.renderTabs();
                App._toast(`✓ 경로 변경 커밋 완료 #${result.commitSha}`);
            } catch(e) {
                alert(`커밋 실패: ${e.message}`);
            }
        } else if (pathChanged && !origPath) {
            /* 새 파일, 경로 직접 지정 */
            tab.ghPath = inputPath;
            const ghCfg = GH.cfg;
            tab.ghBranch = tab.ghBranch || ghCfg.branch;
            const ok = await GH.saveFile(tab.id, msg || `Add ${inputPath}`);
            if (ok) App._toast('✓ GitHub에 저장됨');
        } else if (nameChanged) {
            /* 파일명 변경 커밋 (기존 rename-notice 방식) */
            const oldPath = notice.dataset.oldPath;
            const newPath = notice.dataset.newPath;
            const content = el('editor').value;
            try {
                const result = await GH.renameAndCommit(oldPath, newPath, content, msg);
                tab.ghPath  = newPath;
                tab.ghSha   = null;
                TM.markClean(tab.id);
                TM.renderTabs();
                App._toast(`✓ 파일명 변경 커밋 완료 #${result.commitSha}`);
            } catch(e) {
                alert(`커밋 실패: ${e.message}`);
            }
        } else {
            /* 일반 커밋 — 경로도 그대로 */
            if (inputPath && !origPath) tab.ghPath = inputPath;
            const ok = await GH.saveFile(tab.id, msg || `Update ${tab.title}`);
            if (ok) App._toast('✓ GitHub에 저장됨');
        }
    },

    /* ── 로컬 저장 (.md 다운로드) ───────────────────────── */
    ghSaveLocal() {
        const tab  = TM.getActive();
        const name = tab ? tab.title : 'document';
        const c    = el('editor').value;
        dlBlob(c, name.replace(/[^a-z0-9가-힣\-_. ]/gi, '_') + '.md', 'text/markdown;charset=utf-8');
        App.hideModal('gh-save-modal');
        App._toast('💾 로컬에 저장됨');
    },

    /* ── GitHub 커밋 + md-viewer Push 동시 실행 ── */
    async ghSaveAndPushViewer() {
        /* 1) 먼저 GitHub 커밋 */
        await App.ghSaveCommit();
        /* 2) 이어서 md-viewer push */
        const tab = TM.getActive();
        if (!tab) return;
        const content = el('editor').value;
        await PVShare.quickPush({ name: tab.title || 'document', content });
    },
    deleteLine() {
        const ed = el('editor');
        if (!ed) return;
        const val = ed.value, pos = ed.selectionStart;
        const s = val.lastIndexOf('\n', pos - 1) + 1;
        let e2 = val.indexOf('\n', pos);
        e2 = (e2 === -1) ? val.length : e2 + 1;
        ed.value = val.slice(0, s) + val.slice(e2);
        ed.selectionStart = ed.selectionEnd = Math.min(s, ed.value.length);
        US.snap(); TM.markDirty(); App.render();
    },
    showCommitHistory() {
        App.showModal('gh-history-modal');
        GH.loadHistory(false);
    },
    /* ── 오늘 날짜 삽입 (Shift+Alt+D): 핫키는 오늘 날짜 직접 삽입 ── */
    insertDate() {
        const ed  = el('editor');
        if (!ed) return;
        const dateStr = formatDateTime(new Date());
        const pos = ed.selectionStart;
        const end = ed.selectionEnd;
        ed.setRangeText(dateStr, pos, end, 'end');
        US.snap(); TM.markDirty(); App.render();
    },
    /* ── 날짜 삽입 모달 (버튼 클릭 시): 달력에서 선택 후 삽입 ── */
    _dateInsertCurrent: null,
    _dateInsertShowTime: false,
    openDatePickerModal() {
        this._dateInsertCurrent = new Date();
        this._dateInsertShowTime = false;
        const chk = document.getElementById('date-insert-show-time');
        if (chk) chk.checked = false;
        this._dateInsertRefresh();
        App.showModal('date-insert-modal');
    },
    toggleDateInsertShowTime() {
        const chk = document.getElementById('date-insert-show-time');
        this._dateInsertShowTime = chk ? chk.checked : !this._dateInsertShowTime;
        this._dateInsertRefresh();
    },
    dateInsertAdjust(unit, delta) {
        const d = this._dateInsertCurrent;
        if (!d) return;
        if (unit === 'year') { d.setFullYear(d.getFullYear() + delta); }
        else if (unit === 'month') { d.setMonth(d.getMonth() + delta); }
        else if (unit === 'day') { d.setDate(d.getDate() + delta); }
        else if (unit === 'hour') { d.setHours(d.getHours() + delta); }
        else if (unit === 'min') { d.setMinutes(d.getMinutes() + delta); }
        this._dateInsertRefresh();
    },
    _dateInsertRefresh() {
        const d = this._dateInsertCurrent;
        if (!d) return;
        const y = document.getElementById('date-insert-year');
        const m = document.getElementById('date-insert-month');
        const day = document.getElementById('date-insert-day');
        const h = document.getElementById('date-insert-hour');
        const min = document.getElementById('date-insert-min');
        const preview = document.getElementById('date-insert-preview');
        const timeRow = document.getElementById('date-insert-time-row');
        const showTime = this._dateInsertShowTime;
        if (timeRow) timeRow.style.display = showTime ? '' : 'none';
        if (y) y.textContent = d.getFullYear();
        if (m) m.textContent = d.getMonth() + 1;
        if (day) day.textContent = d.getDate();
        if (h) h.textContent = d.getHours();
        if (min) min.textContent = String(d.getMinutes()).padStart(2, '0');
        if (preview) preview.textContent = showTime ? formatDateTime(d) : (() => { const w = ['일','월','화','수','목','금','토'][d.getDay()]; return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}(${w})`; })();
    },
    insertDateFromPicker() {
        const ed = el('editor');
        if (!ed) return;
        const d = this._dateInsertCurrent || new Date();
        const dateStr = this._dateInsertShowTime ? formatDateTime(d) : (() => { const w = ['일','월','화','수','목','금','토'][d.getDay()]; return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}(${w})`; })();
        const pos = ed.selectionStart;
        const end = ed.selectionEnd;
        ed.setRangeText(dateStr, pos, end, 'end');
        ed.focus();
        US.snap(); TM.markDirty(); App.render();
        App.hideModal('date-insert-modal');
    },

    _toast(msg, duration) {
        let t = document.getElementById('app-toast');
        if (!t) { t = document.createElement('div'); t.id = 'app-toast'; document.body.appendChild(t); }
        t.style.whiteSpace = 'pre-line';
        t.textContent = msg;
        t.classList.add('show');
        clearTimeout(t._tid);
        t._tid = setTimeout(() => t.classList.remove('show'), duration || 2200);
    },
    hideModal(id) {
        if (id === 'image-modal') {
            const box = el('image-modal-box');
            if (box) box.classList.remove('img-modal-maximized');
        }
        if (id === 'cite-modal') {
            const box = document.getElementById('cite-modal-box');
            if (box) box.classList.remove('cite-modal-maximized');
        }
        el(id).classList.remove('vis');
    },
    openColorPicker(m) { ColorPicker.open(m) },
    applyColor() { ColorPicker.apply() },
    showCaption(type) { CAP.show(type) },
    updateCapPreview() { CAP.updatePreview() },
    insertCaption() { CAP.insert() },
    showTmpl() { el('tmpl-modal').classList.add('vis') },
    insertTmpl(i) {
        const t = TMPLS[i];
        if (!confirm(`"${t.name}" 양식을 현재 문서에 추가하시겠습니까?`)) return;
        const edi = el('editor'); edi.value = (edi.value.trim() ? edi.value + '\n\n---\n\n' : '') + t.content;
        this.render(); US.snap(); App.hideModal('tmpl-modal');
    },
    insertSlideTmpl() {
        const style = parseInt(el('slide-tmpl-style').value, 10) || 1;
        const count = Math.max(1, Math.min(50, parseInt(el('slide-tmpl-count').value, 10) || 5));
        const parts = [];
        for (let i = 1; i <= count; i++) {
            const block = `# 제목${i}\n\n---\n\n- 내용`;
            parts.push(i < count ? block + '\n\n<div class="page-break"></div>' : block);
        }
        const content = parts.join('\n\n');
        const edi = el('editor');
        edi.value = (edi.value.trim() ? edi.value + '\n\n' : '') + content;
        PR.setSlideMode(true);
        const btn = document.getElementById('slide-mode-btn');
        if (btn) btn.classList.add('active');
        this.render(); US.snap(); App.hideModal('tmpl-modal');
    },

    toggleFind() {
        const bar = el('find-bar');
        const meBar = el('multi-edit-bar');
        if (meBar && meBar.classList.contains('vis')) meBar.classList.remove('vis');
        bar.classList.toggle('vis');
        if (bar.classList.contains('vis')) {
            const edi = el('editor');
            if (document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
                const sel = edi.value.substring(edi.selectionStart, edi.selectionEnd);
                if (sel) el('fi').value = sel;
            }
            el('fi').focus();
            App._findStart = undefined;
            App.updateFindHighlight();
        } else {
            App.updateFindHighlight(true);
        }
    },

    /** 다중선택 편집 바: 선택 시 에디터에 span 삽입(PV에서 하이라이트), 닫을 때 span 제거 후 마무리 */
    _multiEditSpanStyle: 'background:#ffcc80',
    _multiEditSavedSelection: null,
    _ME_SPANMETHOD_KEY: 'mdpro_me_spanmethod',
    _multiEditUseSpan() { return localStorage.getItem(this._ME_SPANMETHOD_KEY) !== '0'; },
    _multiEditSaveSelection() {
        const edi = el('editor');
        if (!edi || edi.selectionStart === edi.selectionEnd) return;
        const start = edi.selectionStart, end = edi.selectionEnd;
        const text = edi.value.substring(start, end);
        if (!text) return;
        this._multiEditSavedSelection = { start, end, text: text.normalize('NFC') };
    },

    toggleMultiEditBar() {
        const meBar = el('multi-edit-bar');
        const findBar = el('find-bar');
        if (!meBar) return;
        if (meBar.classList.contains('vis')) {
            if (this._multiEditUseSpan()) this._multiEditStripSpans();
            meBar.classList.remove('vis');
            App.updateFindHighlight(true);
            US.snap();
            TM.markDirty();
            this.render();
            return;
        }
        if (findBar && findBar.classList.contains('vis')) findBar.classList.remove('vis');
        const edi = el('editor');
        const selEl = el('me-select');
        const repEl = el('me-replace');
        const useSpan = this._multiEditUseSpan();
        let sel = '';
        if (edi && document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
            sel = edi.value.substring(edi.selectionStart, edi.selectionEnd).normalize('NFC');
        }
        if (!sel && this._multiEditSavedSelection && edi) {
            const s = this._multiEditSavedSelection;
            const current = edi.value.substring(s.start, s.end);
            if (current === s.text) sel = s.text;
        }
        if (sel && selEl) {
            selEl.value = sel;
            if (useSpan && edi) {
                if (document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
                    const wrap = '<span style="' + this._multiEditSpanStyle + '">' + sel + '</span>';
                    edi.value = edi.value.split(sel).join(wrap);
                } else if (this._multiEditSavedSelection) {
                    const wrap = '<span style="' + this._multiEditSpanStyle + '">' + sel + '</span>';
                    edi.value = edi.value.substring(0, this._multiEditSavedSelection.start) + wrap + edi.value.substring(this._multiEditSavedSelection.end);
                }
            }
        }
        this._multiEditSavedSelection = null;
        if (repEl) repEl.value = (selEl && selEl.value) || '';
        meBar.classList.add('vis');
        App.updateFindHighlight();
        if (repEl) repEl.focus();
        US.snap();
        TM.markDirty();
        this.render();
    },

    _multiEditStripSpans() {
        const edi = el('editor');
        if (!edi) return;
        const style = this._multiEditSpanStyle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        edi.value = edi.value.replace(new RegExp('<span\\s+style="' + style + '">([\\s\\S]*?)<\\/span>', 'g'), '$1');
    },
    multiEditBarKey(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            App.multiEditApply();
            return;
        }
        if (e.key === 'Escape') {
            e.preventDefault();
            App.toggleMultiEditBar();
        }
    },
    multiEditApply() {
        const selEl = el('me-select');
        const repEl = el('me-replace');
        const edi = el('editor');
        if (!selEl || !repEl || !edi) return;
        const q = (selEl.value || '').normalize('NFC');
        const r = (repEl.value ?? '').normalize('NFC');
        if (!q) return;
        const useSpan = this._multiEditUseSpan();
        if (useSpan) {
            const needle = '<span style="' + this._multiEditSpanStyle + '">' + q + '</span>';
            const replacement = '<span style="' + this._multiEditSpanStyle + '">' + r + '</span>';
            const parts = edi.value.split(needle);
            const cnt = parts.length - 1;
            if (cnt <= 0) return;
            edi.value = parts.join(replacement);
            const cntEl = el('me-cnt');
            if (cntEl) cntEl.textContent = cnt + '건 교체됨';
        } else {
            const literal = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const re = new RegExp(literal, 'g');
            const cnt = (edi.value.match(re) || []).length;
            if (cnt === 0) return;
            edi.value = edi.value.replace(re, r);
            const cntEl = el('me-cnt');
            if (cntEl) cntEl.textContent = cnt + '건 교체됨';
        }
        selEl.value = r;
        repEl.value = r;
        US.snap();
        TM.markDirty();
        this.render();
        App.updateFindHighlight();
    },

    findKey(e) { if (e.key === 'Enter') this.findNext(); if (e.key === 'Escape') this.toggleFind() },
    findNext() {
        const q = el('fi').value;
        if (!q) return;
        const edi = el('editor');
        const startFrom = (App._findStart != null) ? App._findStart : edi.selectionEnd;
        let idx = edi.value.indexOf(q, startFrom);
        if (idx === -1) idx = edi.value.indexOf(q);
        if (idx !== -1) {
            App._findStart = idx + q.length;
            edi.setSelectionRange(idx, idx + q.length);
            edi.focus();
        } else {
            App._findStart = undefined;
        }
        const cnt = (edi.value.match(new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
        el('fc-cnt').textContent = cnt ? `${cnt}건` : q ? '없음' : '';
    },
    replaceOne() { const q = el('fi').value, r = el('ri').value; if (!q) return; const edi = el('editor'), s = edi.selectionStart, e = edi.selectionEnd; if (edi.value.substring(s, e) === q) { edi.value = edi.value.substring(0, s) + r + edi.value.substring(e); App._findStart = s + r.length; this.render() } else this.findNext() },
    replaceAll() { const q = el('fi').value, r = el('ri').value; if (!q) return; const edi = el('editor'); const cnt = (edi.value.match(new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length; edi.value = edi.value.replaceAll(q, r); this.render(); US.snap(); el('fc-cnt').textContent = `${cnt}건 교체됨`; App._findStart = undefined; App.updateFindHighlight() },

    updateFindHighlight(clear) {
        const bar = document.getElementById('find-bar');
        const meBar = document.getElementById('multi-edit-bar');
        const fi = document.getElementById('fi');
        const meSelect = document.getElementById('me-select');
        const layer = document.getElementById('editor-find-highlight');
        const edi = document.getElementById('editor');
        if (!layer || !edi) return;
        if (clear) {
            layer.innerHTML = '';
            layer.style.display = 'none';
            App._applyPreviewFindHighlight(el('preview-container'), '');
            return;
        }
        if (meBar && meBar.classList.contains('vis') && meSelect && meSelect.value.trim()) {
            const q = meSelect.value.trim();
            const cnt = (edi.value.split(q).length - 1);
            const cntEl = document.getElementById('me-cnt');
            if (cntEl) cntEl.textContent = cnt ? cnt + '건' : '없음';
            return;
        }
        if (!bar || !bar.classList.contains('vis') || !fi || !fi.value.trim()) {
            layer.innerHTML = '';
            layer.style.display = 'none';
            App._applyPreviewFindHighlight(el('preview-container'), '');
            return;
        }
        const q = fi.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp(q, 'gi');
        const raw = edi.value;
        const escaped = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '\n');
        const withMark = escaped.replace(re, '<mark>$&</mark>');
        layer.innerHTML = withMark;
        layer.style.display = 'block';
        layer.scrollTop = edi.scrollTop;
        layer.scrollLeft = edi.scrollLeft;
        App._applyPreviewFindHighlight(el('preview-container'), fi.value.trim());
    },

    _applyPreviewFindHighlight(container, q) {
        if (!container) return;
        container.querySelectorAll('.find-highlight-pv').forEach(span => {
            const parent = span.parentNode;
            while (span.firstChild) parent.insertBefore(span.firstChild, span);
            parent.removeChild(span);
        });
        if (!q) return;
        const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
        const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null, false);
        const textNodes = [];
        let n;
        while ((n = walker.nextNode())) textNodes.push(n);
        textNodes.forEach(node => {
            const text = node.textContent;
            if (!text || text.trim() === '') return;
            re.lastIndex = 0;
            if (!re.test(text)) return;
            re.lastIndex = 0;
            const parts = [];
            let lastIndex = 0;
            let match;
            while ((match = re.exec(text)) !== null) {
                if (match.index > lastIndex) parts.push({ t: true, v: text.slice(lastIndex, match.index) });
                parts.push({ t: false, v: match[0] });
                lastIndex = match.index + match[0].length;
            }
            if (parts.length === 0) return;
            if (lastIndex < text.length) parts.push({ t: true, v: text.slice(lastIndex) });
            const frag = document.createDocumentFragment();
            parts.forEach(p => {
                if (p.t) frag.appendChild(document.createTextNode(p.v));
                else {
                    const span = document.createElement('span');
                    span.className = 'find-highlight-pv';
                    span.textContent = p.v;
                    frag.appendChild(span);
                }
            });
            node.parentNode.replaceChild(frag, node);
        });
    },

    saveMD() { const c = el('editor').value, t = el('doc-title').value.replace(/[^a-z0-9가-힣]/gi, '_'); dlBlob(c, `${t}.md`, 'text/markdown'); TM.markClean(); TM.persist(); this.hideModal('save-modal') },
    saveTXT() { const c = el('editor').value.replace(/[#*_`~>|]/g, '').replace(/\[(.*?)\]\(.*?\)/g, '$1').replace(/<[^>]+>/g, ''); dlBlob(c, (el('doc-title').value || 'document').replace(/[^a-z0-9가-힣]/gi, '_') + '.txt', 'text/plain;charset=utf-8'); TM.markClean(); TM.persist(); this.hideModal('save-modal') },
    saveHTML() {
        const md = el('editor').value; const title = el('doc-title').value;
        const showFn = el('show-footnotes-chk').checked;
        const pages = splitPages(md);
        const html = pages.map((p, i) => `<div class="preview-page${this.rm ? ' rm' : ''}" data-page="${i + 1}">${mdRender(p, showFn)}</div>`).join('');
        const CSS = `body{font-family:sans-serif;background:#6a6e7e;display:flex;flex-direction:column;align-items:center;padding:20px 0 40px}.preview-page{width:210mm;min-height:297mm;background:white;color:#1a1a2e;padding:22mm 18mm;box-shadow:0 4px 30px rgba(0,0,0,.4);font-family:'Libre Baskerville',Georgia,serif;font-size:11pt;line-height:1.8;word-break:break-word;position:relative;margin-bottom:20px}.preview-page::after{content:"— " attr(data-page) " —";position:absolute;bottom:10mm;left:50%;transform:translateX(-50%);font-family:sans-serif;font-size:9pt;color:#bbb}.preview-page h1{font-size:21pt;font-weight:700;margin:0 0 14px;border-bottom:2px solid #1a1a2e;padding-bottom:8px}.preview-page h2{font-size:15pt;margin:20px 0 10px;font-weight:700}.preview-page h3{font-size:12pt;margin:16px 0 7px;font-weight:700}.preview-page p{margin:0 0 11px}.preview-page ul,.preview-page ol{margin:0 0 11px;padding-left:22px}.preview-page table{width:100%;border-collapse:collapse;margin:11px 0;font-size:inherit}.preview-page th{background:#e8e8f0;color:#1a1a2e;padding:7px 11px;text-align:left;font-weight:600;border:1px solid #c0c0d8}.preview-page td{padding:6px 11px;border:1px solid #d0d0e0}.preview-page tr:nth-child(even) td{background:#f7f7fc}.preview-page code{font-family:monospace;font-size:9pt;background:#f0f0f8;padding:1px 4px;border-radius:3px;color:#5b4ce4}.preview-page pre{background:#1a1a2e;color:#e8e8f0;padding:14px;border-radius:6px;margin:11px 0;font-size:9pt}.preview-page pre code{background:none;color:inherit}.preview-page a{color:#5b4ce4}.preview-page img{max-width:100%}.preview-page .footnote-highlight{background:#f0f0f0;color:#1a1a2e;border-radius:2px;padding:0 2px}.preview-page .footnote-def{background:#f5f5f5;color:#1a1a2e;border-left:3px solid #bbb;padding:4px 10px;margin:4px 0;font-size:9.5pt}.preview-page .footnotes-section{border-top:1px solid #d0d0e0;margin-top:24px;padding-top:10px;font-size:9.5pt;color:#444}@media print{body{background:none;padding:0}.preview-page{box-shadow:none;margin:0;page-break-after:always;width:100%;min-height:0}.preview-page:last-child{page-break-after:auto}/* page number visible in print */.a4-rl,.a4-rl-label{display:none!important}}`;
        const fullHtml = `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>${title}</title><style>${CSS}</style></head><body>${html}</body></html>`;
        dlBlob(fullHtml, (el('doc-title').value || 'document').replace(/[^a-z0-9가-힣]/gi, '_') + '.html', 'text/html;charset=utf-8');
        TM.markClean(); TM.persist(); this.hideModal('save-modal');
    },
    printDoc() {
        const md = el('editor').value; const title = el('doc-title').value;
        const showFn = document.getElementById('show-footnotes-chk') ? el('show-footnotes-chk').checked : true;
        const pages = splitPages(md);
        const html = pages.map((p, i) => `<div class="preview-page${this.rm ? ' rm' : ''}" data-page="${i + 1}">${mdRender(p, showFn)}</div>`).join('');
        const CSS = `@import url('https://fonts.googleapis.com/css2?family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&family=JetBrains+Mono:wght@400;500&display=swap');*{box-sizing:border-box;margin:0;padding:0}body{font-family:sans-serif;background:#6a6e7e;display:flex;flex-direction:column;align-items:center;padding:20px 0 40px}.preview-page{width:210mm;min-height:297mm;background:white;color:#1a1a2e;padding:22mm 18mm;box-shadow:0 4px 30px rgba(0,0,0,.4);font-family:'Libre Baskerville',Georgia,serif;font-size:11pt;line-height:1.8;word-break:break-word;position:relative;margin-bottom:20px}.preview-page::after{content:"— " attr(data-page) " —";position:absolute;bottom:10mm;left:50%;transform:translateX(-50%);font-family:sans-serif;font-size:9pt;color:#bbb}.preview-page h1{font-size:21pt;font-weight:700;margin:0 0 14px;border-bottom:2px solid #1a1a2e;padding-bottom:8px}.preview-page h2{font-size:15pt;margin:20px 0 10px;font-weight:700}.preview-page h3{font-size:12pt;margin:16px 0 7px;font-weight:700}.preview-page p{margin:0 0 11px}.preview-page ul,.preview-page ol{margin:0 0 11px;padding-left:22px}.preview-page table{width:100%;border-collapse:collapse;margin:11px 0;font-size:inherit}.preview-page th{background:#e8e8f0;color:#1a1a2e;padding:7px 11px;text-align:left;font-weight:600;border:1px solid #c0c0d8}.preview-page td{padding:6px 11px;border:1px solid #d0d0e0}.preview-page tr:nth-child(even) td{background:#f7f7fc}.preview-page code{font-family:'JetBrains Mono',monospace;font-size:9pt;background:#f0f0f8;padding:1px 4px;border-radius:3px;color:#5b4ce4}.preview-page pre{background:#1a1a2e;color:#e8e8f0;padding:14px;border-radius:6px;margin:11px 0;font-size:9pt}.preview-page pre code{background:none;color:inherit}.preview-page img{max-width:100%}.preview-page a{color:#5b4ce4}.preview-page .footnote-highlight{background:#f0f0f0;color:#1a1a2e;border-radius:2px;padding:0 2px}.preview-page .footnote-def{background:#f5f5f5;color:#1a1a2e;border-left:3px solid #bbb;padding:4px 10px;margin:4px 0;font-size:9.5pt}.preview-page .footnotes-section{border-top:1px solid #d0d0e0;margin-top:24px;padding-top:10px;font-size:9.5pt;color:#444}@media print{body{background:none;padding:0}.preview-page{box-shadow:none;margin:0;page-break-after:always;width:100%;min-height:0}.preview-page:last-child{page-break-after:auto}/* page number visible in print */.a4-rl,.a4-rl-label{display:none!important}}`;
        const fullHtml = `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>${title}</title><style>${CSS}</style></head><body>${html}<script>window.onload=function(){window.print();}<\/script></body></html>`;
        const w = window.open('', '_blank', 'width=900,height=700');
        if (w) { w.document.open(); w.document.write(fullHtml); w.document.close(); }
        else { alert('팝업이 차단되었습니다. 팝업을 허용해 주세요.'); }
        this.hideModal('save-modal');
    },

    sample() {
        return `# Markdown PDF Editor Pro

**제작: 박중희(연세대 심리학과 겸임교수)**

- 논문 집필을 위한 에디터로 연구와 논문을 위한 도구입니다.
- 경기대학교 교육산업전공자
- 연세대학교 심리과학 이노베이션 대학원 심리트랙 전공자

## V20 업데이트 신기능

모든 기능이 통합된 **연구·논문 전용 에디터**입니다.

### 주요 기능 목록

| 기능 | 단축키 / 버튼 | 설명 |
| :-- | :-- | :-- |
| 코드 블록 (마지막 언어) | **Alt+C** | 마지막 사용 언어 즉시 삽입 |
| 코드 블록 (언어 선택) | ⌨ Code 버튼 | 언어 선택 모달 |
| 인용 삽입 | **Ctrl+Shift+C** | 참고문헌 관리자 |
| Research Mode | **Ctrl+Shift+R** | 단락 줄번호 표시 |
| 저장 | **Ctrl+S** | MD / TXT / HTML 선택 |
| **단축키 목록** | **Alt+?** | 단축키 표시 (편집 가능) |
| **표 HTML 정돈** | ✦ Tidy 버튼 | 병합 후 들여쓰기 정리 |
| **미리보기 복사** | 📋 복사 버튼 | 서식 있는 복사 (Word·구글독스) |
| **A4 구분선** | 📄 A4 버튼 | 297mm 위치에 빨간 점선 표시 |

---

### Research Mode 줄번호

**Ctrl+Shift+R** 또는 🔬 Research 버튼을 누르면 미리보기에서 각 단락에 줄번호가 표시됩니다.

이것은 두 번째 단락입니다. 줄번호가 왼쪽에 표시됩니다.

세 번째 단락입니다.

---

### 참고문헌 관리자

**📚 References** 버튼으로 APA 참고문헌을 붙여넣고 관리할 수 있습니다.

- **빈 줄 구분**: 여러 참고문헌을 빈 줄로 구분
- **엔터 구분**: 각 줄이 하나의 참고문헌

스타일 변환: APA → MLA 9 / Chicago / Vancouver 자동 변환을 지원합니다.

<div class="page-break"></div>

## 2페이지 — 캡션, 수식, 논문 양식

### 표 캡션 예시

<span class="tbl-caption"><표1> 연구대상 특성</span>

| 변수 | M | SD | n |
| :-- | :-- | :-- | :-- |
| 연령 | 24.5 | 3.2 | 120 |
| 학습시간 | 5.3 | 1.8 | 120 |

### 수식

$$
\\phi = \\frac{\\lambda_2}{c^2}
$$

### 논문 양식

**📋 양식** 버튼을 눌러 학위논문, SSCI/KCI, 단일/다중 연구, 메타분석 구조를 삽입하세요.

> \`Alt+?\` → 전체 단축키 목록
`}
};

/* ═══════════════════════════════════════════════════════════
   PWA — Service Worker + Manifest (인라인 생성)
   GitHub Pages 대응: blob: URL SW 미사용, scope 자동 감지
═══════════════════════════════════════════════════════════ */
(function () {
    // 1. Manifest 동적 생성 (blob: URL — 절대 URL 사용 시 start_url/scope 오류 감소)
    const origin = location.origin;
    const pathBase = location.pathname.replace(/[^/]*$/, '');
    const startPath = location.pathname || '/';
    const manifest = {
        name: 'Markdown PDF Editor Pro',
        short_name: 'MD PRO V20',
        description: '연구·논문 전용 마크다운 에디터',
        start_url: origin + startPath,
        scope: origin + pathBase,
        display: 'standalone',
        background_color: '#0f0f13',
        theme_color: '#1a1a24',
        icons: [
            { src: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192"><rect width="192" height="192" rx="24" fill="%237c6af7"/><text x="96" y="130" font-size="110" text-anchor="middle" font-family="monospace" fill="white">M</text></svg>', sizes: '192x192', type: 'image/svg+xml' },
            { src: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="60" fill="%237c6af7"/><text x="256" y="360" font-size="300" text-anchor="middle" font-family="monospace" fill="white">M</text></svg>', sizes: '512x512', type: 'image/svg+xml' }
        ]
    };
    try {
        const blob = new Blob([JSON.stringify(manifest)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.getElementById('pwa-manifest');
        if (link) link.href = url;
    } catch(e) {}

    // 2. Service Worker — blob: URL은 GitHub Pages에서 scope 오류 발생
    //    → sw.js 파일이 있을 때만 등록 (http/https에서만, file:// 제외)
    if ('serviceWorker' in navigator && (location.protocol === 'http:' || location.protocol === 'https:')) {
        // 기존에 blob: URL로 등록된 SW가 있으면 해제 (구버전 호환)
        navigator.serviceWorker.getRegistrations().then(regs => {
            regs.forEach(reg => {
                if (reg.active && reg.active.scriptURL.startsWith('blob:')) {
                    reg.unregister();
                }
            });
        }).catch(() => {});

        // sw.js 파일이 배포 루트에 있을 때만 등록
        const swPath = location.pathname.replace(/[^/]*$/, '') + 'sw.js';
        fetch(swPath, { method: 'HEAD' }).then(r => {
            if (r.ok) {
                navigator.serviceWorker.register(swPath).catch(() => {});
            }
        }).catch(() => {});
    }
})();

window.addEventListener('DOMContentLoaded', () => {
    App.init();
    AiApiKey.load().catch(() => {});
    ScholarApiKey.load().catch(() => {});
    ScholarApiKey.initPasteExtract();
    /* 전역 날짜·시간 라이브 갱신 (잠금 버튼 앞 표시) */
    const dtEl = el('app-datetime');
    if (dtEl) {
        dtEl.textContent = formatDateTime();
        setInterval(() => { if (dtEl) dtEl.textContent = formatDateTime(); }, 1000);
    }
    /* 앱 종료 시 외부 PV 창도 함께 닫기 (보안) */
    function closePvOnExit() { if (typeof PW !== 'undefined' && PW.closeWin) PW.closeWin(); }
    window.addEventListener('beforeunload', closePvOnExit);
    window.addEventListener('pagehide', closePvOnExit);
    FM.restore().catch(e => console.warn('FM restore failed:', e));
    GH.restore().then(() => {
        /* 앱 열 때: 새 커밋 알람 + 기기 활동 확인 */
        GH.checkNewCommits().catch(() => {});
        GH.loadDeviceActivity().catch(() => {});
    }).catch(e => console.warn('GH restore failed:', e));
    /* 문자표 단축키 및 Shift+Alt 단축키 */
    document.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'q') { e.preventDefault(); CharMap.show(); }
        if (e.shiftKey && e.altKey && (e.key === 'g' || e.key === 'G')) { e.preventDefault(); Translator.show(); }
        if (e.shiftKey && e.altKey && (e.key === 'm' || e.key === 'M')) { e.preventDefault(); SS.toggle(); }
        if (e.shiftKey && e.altKey && (e.key === 'a' || e.key === 'A')) { e.preventDefault(); if (typeof AuthorInfo !== 'undefined') AuthorInfo.insertIntoEditor(); }
        if (e.shiftKey && e.altKey && (e.key === 'd' || e.key === 'D')) { e.preventDefault(); App.insertDate(); }
    });

    /* ── gh-save-modal 리사이즈 드래그 ─────────────────── */
    (function initGhSaveResize() {
        const MIN_W = 400, MAX_W = Math.min(1200, window.innerWidth * 0.95);
        const MIN_H = 260;

        function makeResizable(handleEl, mode) {
            if (!handleEl) return;
            let startX, startY, startW, startH, boxEl;

            handleEl.addEventListener('mousedown', e => {
                boxEl = document.getElementById('gh-save-modal-box');
                if (!boxEl) return;
                e.preventDefault();
                startX = e.clientX;
                startY = e.clientY;
                startW = boxEl.offsetWidth;
                startH = boxEl.offsetHeight;

                function onMove(ev) {
                    const dX = ev.clientX - startX;
                    const dY = ev.clientY - startY;
                    if (mode === 'se' || mode === 'ew') {
                        const nw = Math.max(MIN_W, Math.min(MAX_W, startW + dX));
                        boxEl.style.width = nw + 'px';
                        boxEl.style.minWidth = nw + 'px';
                    }
                    if (mode === 'se') {
                        const nh = Math.max(MIN_H, startH + dY);
                        boxEl.style.maxHeight = nh + 'px';
                    }
                }
                function onUp() {
                    document.removeEventListener('mousemove', onMove);
                    document.removeEventListener('mouseup', onUp);
                }
                document.addEventListener('mousemove', onMove);
                document.addEventListener('mouseup', onUp);
            });
        }

        makeResizable(document.getElementById('gh-save-resize-handle'), 'se');
        makeResizable(document.getElementById('gh-save-resize-right'), 'ew');
    })();
});
/* ═══════════════════════════════════════════════════════════
   AI 질문 — Gemini 모델 선택 + 질문/답변 + thinking + 새 파일 삽입
═══════════════════════════════════════════════════════════ */
const DeepResearch = (() => {
    let _result = '';
    let _thinking = '';
    let _busy = false;
    let _newFileMode = false;
    let _currentTab = 'question';
    let _dragInit = false;
    let _abortController = null;
    const DB_NAME = 'mdlive-dr-history';
    const STORE_NAME = 'history';

    const $ = id => document.getElementById(id);

    function _openDB() {
        return new Promise((resolve, reject) => {
            const r = indexedDB.open(DB_NAME, 1);
            r.onerror = () => reject(r.error);
            r.onsuccess = () => resolve(r.result);
            r.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    const s = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
                    s.createIndex('createdAt', 'createdAt', { unique: false });
                }
            };
        });
    }

    async function _getAll() {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readonly');
            const store = t.objectStore(STORE_NAME);
            const req = store.getAll();
            req.onsuccess = () => {
                const raw = req.result || [];
                resolve(raw.filter(r => r.id !== '_historyOrder'));
            };
            req.onerror = () => reject(req.error);
        });
    }

    async function _getOrder() {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readonly');
            const req = t.objectStore(STORE_NAME).get('_historyOrder');
            req.onsuccess = () => resolve(Array.isArray(req.result?.order) ? req.result.order : []);
            req.onerror = () => reject(req.error);
        });
    }

    async function _setOrder(orderIds) {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readwrite');
            t.objectStore(STORE_NAME).put({ id: '_historyOrder', order: orderIds });
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
        });
    }

    async function _add(record) {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readwrite');
            t.objectStore(STORE_NAME).put(record);
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
        });
    }

    async function _delete(id) {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readwrite');
            t.objectStore(STORE_NAME).delete(id);
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
        });
    }

    function _renderHistoryList(items) {
        const list = $('dr-history-list');
        if (!list) return;
        list.textContent = '';
        list.removeAttribute('data-empty');
        if (!items.length) {
            list.setAttribute('data-empty', '질문 후 여기에 히스토리가 저장됩니다.');
            return;
        }
        items.forEach(item => {
            const row = document.createElement('div');
            row.className = 'dr-history-item';
            row.setAttribute('data-id', item.id);
            const title = document.createElement('span');
            title.className = 'dr-history-title';
            title.textContent = item.title || '(제목 없음)';
            const actions = document.createElement('span');
            actions.className = 'dr-history-actions';
            const renameBtn = document.createElement('button');
            renameBtn.type = 'button';
            renameBtn.className = 'btn-ic';
            renameBtn.title = '이름 변경';
            renameBtn.textContent = '✎';
            renameBtn.onclick = (e) => { e.stopPropagation(); DeepResearch.renameHistory(item.id); };
            const saveBtn = document.createElement('button');
            saveBtn.type = 'button';
            saveBtn.className = 'btn-ic';
            saveBtn.title = '이 항목만 .md 파일로 저장';
            saveBtn.textContent = '💾';
            saveBtn.onclick = (e) => { e.stopPropagation(); DeepResearch.saveHistoryItemToFile(item.id); };
            const delBtn = document.createElement('button');
            delBtn.type = 'button';
            delBtn.className = 'btn-ic';
            delBtn.title = '삭제';
            delBtn.textContent = '✕';
            delBtn.onclick = (e) => { e.stopPropagation(); DeepResearch.deleteHistory(item.id); };
            actions.append(renameBtn, saveBtn, delBtn);
            row.append(title, actions);
            row.onclick = () => DeepResearch.loadHistoryItem(item.id);
            list.appendChild(row);
        });
    }

    let _historyCache = [];
    let _historySearch = '';

    async function loadHistory() {
        try {
            const items = await _getAll();
            const orderIds = await _getOrder();
            const byId = new Map(items.map(it => [it.id, it]));
            const ordered = [];
            for (const id of orderIds) {
                if (byId.has(id)) {
                    ordered.push(byId.get(id));
                    byId.delete(id);
                }
            }
            const rest = [...byId.values()].sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
            _historyCache = ordered.concat(rest);
        } catch (_) {
            _historyCache = [];
        }
        filterHistory(_historySearch);
    }

    function filterHistory(query) {
        _historySearch = (query || '').trim().toLowerCase();
        let list = _historyCache;
        if (_historySearch) {
            list = list.filter(item => {
                const t = (item.title || '').toLowerCase();
                const p = (item.prompt || '').toLowerCase();
                const r = (item.result || '').toLowerCase();
                return t.includes(_historySearch) || p.includes(_historySearch) || r.includes(_historySearch);
            });
        }
        _renderHistoryList(list);
    }

    async function loadHistoryItem(id) {
        const list = _historyCache.filter(x => x.id === id);
        const item = list[0];
        if (!item) return;
        const inp = $('dr-prompt'), out = $('dr-output'), thinkEl = $('dr-thinking'), thinkBtn = $('dr-thinking-btn'), insBtn = $('dr-insert-btn'), modelSel = $('dr-model');
        if (inp) inp.value = item.prompt || '';
        if (out) out.value = item.result || '';
        _result = item.result || '';
        _thinking = item.thinking || '';
        if (thinkEl) {
            thinkEl.value = item.thinking || '';
            const wrap = $('dr-thinking-wrap');
            if (wrap) wrap.style.display = item.thinking ? 'flex' : 'none';
            if (thinkEl) thinkEl.style.display = item.thinking ? 'flex' : 'none';
        }
        if (thinkBtn) thinkBtn.style.display = item.thinking ? '' : 'none';
        const copyThinkBtn = document.getElementById('dr-copy-thinking-btn');
        if (copyThinkBtn) copyThinkBtn.style.display = item.thinking ? '' : 'none';
        const translateThinkBtn = document.getElementById('dr-translate-thinking-btn');
        if (translateThinkBtn) translateThinkBtn.style.display = item.thinking ? '' : 'none';
        const openThinkBtn = document.getElementById('dr-open-thinking-btn');
        if (openThinkBtn) openThinkBtn.style.display = item.thinking ? '' : 'none';
        if (insBtn) insBtn.disabled = !(item.result && item.result.length > 0);
        if (modelSel && item.modelId) {
            modelSel.value = item.modelId;
        }
        switchTab('question');
    }

    function renameHistory(id) {
        const item = _historyCache.find(x => x.id === id);
        if (!item) return;
        const newTitle = prompt('파일명(제목)을 입력하세요. 검색에 사용됩니다.', item.title || '');
        if (newTitle == null || newTitle === '') return;
        const title = newTitle.trim() || item.title;
        const updated = { ...item, title };
        _add(updated).then(() => {
            const idx = _historyCache.findIndex(x => x.id === id);
            if (idx >= 0) _historyCache[idx] = updated;
            filterHistory(_historySearch);
        }).catch(() => alert('저장 실패'));
    }

    function deleteHistory(id) {
        if (!confirm('이 히스토리를 삭제할까요?')) return;
        _delete(id).then(async () => {
            const orderIds = await _getOrder();
            const next = orderIds.filter(x => x !== id);
            await _setOrder(next);
            _historyCache = _historyCache.filter(x => x.id !== id);
            filterHistory(_historySearch);
        }).catch(() => alert('삭제 실패'));
    }

    function _drSafeFilename(title) {
        const t = (title || '제목없음').trim() || '제목없음';
        return t.replace(/\.md$/i, '').replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').slice(0, 200) + '.md';
    }

    function openHistorySaveModal() {
        const modal = $('dr-history-save-modal');
        if (modal) {
            modal.style.display = 'flex';
        }
    }

    function closeHistorySaveModal() {
        const modal = $('dr-history-save-modal');
        if (modal) modal.style.display = 'none';
    }

    function saveHistoryAsZip() {
        if (typeof JSZip === 'undefined') { alert('ZIP 라이브러리를 불러올 수 없습니다.'); return; }
        const items = _historyCache.filter(it => it.result && it.result.trim());
        if (!items.length) { alert('저장할 히스토리가 없습니다.'); return; }
        const zip = new JSZip();
        items.forEach((item, i) => {
            const name = _drSafeFilename(item.title || 'item-' + (i + 1));
            zip.file(name, item.result.trim(), { createFolders: false });
        });
        zip.generateAsync({ type: 'blob' }).then(blob => {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'dr-history-' + (new Date().toISOString().slice(0, 10)) + '.zip';
            a.click();
            URL.revokeObjectURL(a.href);
        }).catch(() => alert('ZIP 생성 실패'));
    }

    function saveHistoryBatch() {
        const items = _historyCache.filter(it => it.result && it.result.trim());
        if (!items.length) { alert('저장할 히스토리가 없습니다.'); return; }
        items.forEach((item, i) => {
            setTimeout(() => {
                const name = _drSafeFilename(item.title || 'item-' + (i + 1));
                const blob = new Blob([item.result.trim()], { type: 'text/markdown;charset=utf-8' });
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = name;
                a.click();
                URL.revokeObjectURL(a.href);
            }, i * 150);
        });
        if (items.length > 0) alert(items.length + '개 파일이 다운로드됩니다. (브라우저 기본 저장 위치 확인)');
    }

    function saveHistoryItemToFile(id) {
        const item = _historyCache.find(x => x.id === id
            
        );
        if (!item || !item.result || !item.result.trim()) {
            alert('저장할 내용이 없습니다.');
            return;
        }
        const hasThinking = !!(item.thinking && item.thinking.trim());
        if (hasThinking) {
            _pendingThinkingMode = 'save';
            _pendingSaveId = id;
            const chk = document.getElementById('dr-thinking-include-chk');
            const label = document.getElementById('dr-thinking-include-label');
            const btn = document.getElementById('dr-thinking-include-confirm-btn');
            const title = document.getElementById('dr-thinking-modal-title');
            if (chk) chk.checked = false;
            if (label) label.textContent = '생각 포함하여 저장';
            if (btn) btn.textContent = '저장';
            if (title) title.textContent = '저장 시 생각 포함';
            const modal = document.getElementById('dr-thinking-include-modal');
            if (modal) { modal.style.display = 'flex'; }
        } else {
            _doSaveHistoryItem(id, false);
        }
    }

    function _doSaveHistoryItem(id, includeThinking) {
        const item = _historyCache.find(x => x.id === id);
        if (!item || !item.result || !item.result.trim()) return;
        let content = item.result.trim();
        if (includeThinking && item.thinking && item.thinking.trim()) {
            content += '\n\n--- 생각 ---\n' + item.thinking.trim();
        }
        const name = _drSafeFilename(item.title);
        const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = name;
        a.click();
        URL.revokeObjectURL(a.href);
    }

    let _pendingThinkingMode = null;
    let _pendingSaveId = null;

    function openThinkingIncludeModal(mode, id) {
        _pendingThinkingMode = mode;
        _pendingSaveId = id || null;
    }

    function closeThinkingIncludeModal() {
        const modal = document.getElementById('dr-thinking-include-modal');
        if (modal) modal.style.display = 'none';
        _pendingThinkingMode = null;
        _pendingSaveId = null;
    }

    function confirmThinkingInclude() {
        const chk = document.getElementById('dr-thinking-include-chk');
        const include = chk ? chk.checked : false;
        if (_pendingThinkingMode === 'save' && _pendingSaveId) {
            _doSaveHistoryItem(_pendingSaveId, include);
        } else if (_pendingThinkingMode === 'insert') {
            _doInsert(include);
        } else if (_pendingThinkingMode === 'newfile') {
            _doInsertToNewFile(include);
        }
        closeThinkingIncludeModal();
    }

    function switchTab(tab) {
        _currentTab = tab;
        const q = $('dr-panel-question'), p = $('dr-panel-pro'), a = $('dr-panel-ai-search'), d = $('dr-panel-data-research');
        const tabs = document.querySelectorAll('#dr-tabs .tr-tab');
        if (q) q.style.display = tab === 'question' ? 'flex' : 'none';
        if (p) p.style.display = tab === 'pro-preview' ? 'flex' : 'none';
        if (a) a.style.display = tab === 'ai-search' ? 'flex' : 'none';
        if (d) d.style.display = tab === 'data-research' ? 'flex' : 'none';
        tabs.forEach(t => {
            const active = t.getAttribute('data-tab') === tab;
            t.classList.toggle('active', active);
        });
        const inp = tab === 'question' ? $('dr-prompt') : tab === 'pro-preview' ? $('dr-prompt-pro') : tab === 'ai-search' ? $('dr-ai-prompt') : $('dr-data-prompt');
        if (inp) setTimeout(() => inp.focus(), 50);
        if (tab === 'ai-search') {
            const presetTa = $('dr-ai-preset-text');
            if (presetTa && !presetTa.value.trim()) applyAiSearchPreset();
        }
        if (tab === 'data-research') {
            const presetTa = $('dr-data-preset-text');
            if (presetTa && !presetTa.value.trim()) applyDataResearchPreset();
        }
    }

    function _initDraggable() {
        if (_dragInit) return;
        _dragInit = true;
        const box = $('dr-modal-box'), handle = document.querySelector('.dr-modal-drag');
        if (!box || !handle) return;
        let dx = 0, dy = 0, startX = 0, startY = 0;
        handle.addEventListener('mousedown', (e) => {
            if (e.button !== 0) return;
            if (box.classList.contains('dr-modal-maximized')) return;
            startX = e.clientX - dx;
            startY = e.clientY - dy;
            const onMove = (ev) => {
                dx = ev.clientX - startX;
                dy = ev.clientY - startY;
                box.style.transform = `translate(${dx}px, ${dy}px)`;
            };
            const onUp = () => {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
            };
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
        });
    }

    function toggleMaximize() {
        const box = $('dr-modal-box');
        if (!box) return;
        const on = box.classList.toggle('dr-modal-maximized');
        box.style.transform = on ? '' : box.style.transform || '';
        if (!on) { box.style.transform = ''; }
        const btn = $('dr-maximize-btn');
        if (btn) btn.title = on ? '원래 크기' : '최대화';
    }

    async function _callApi(prompt, modelId, signal) {
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) throw new Error('AI API 키를 설정에서 입력·저장해 주세요.');
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(key)}`;
        const body = {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
                temperature: 0.5,
                maxOutputTokens: 8192,
                ...(modelId.includes('2.5-pro') && { thinkingConfig: { includeThoughts: true } })
            }
        };
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: signal || AbortSignal.timeout(120000)
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            throw new Error(err.error?.message || `HTTP ${r.status}`);
        }
        const d = await r.json();
        const parts = d.candidates?.[0]?.content?.parts || [];
        let text = '';
        let thoughts = '';
        for (const p of parts) {
            const t = p.text || '';
            if (p.thought) thoughts += t;
            else text += t;
        }
        return { text: text.trim(), thoughts: thoughts.trim() };
    }

    function stopRun() {
        if (_abortController) _abortController.abort();
    }

    function show() {
        const modal = $('deep-research-modal');
        if (!modal) return;
        const box = $('dr-modal-box');
        if (box) {
            box.classList.remove('dr-modal-maximized');
            box.style.transform = '';
        }
        _initDraggable();
        switchTab('question');
        const ed = $('editor');
        if (ed) {
            const sel = ed.value.substring(ed.selectionStart, ed.selectionEnd).trim();
            if (sel) {
                const inp = $('dr-prompt');
                if (inp) inp.value = sel;
            }
        }
        modal.classList.add('vis');
        _newFileMode = false;
        const hint = $('dr-insert-hint');
        if (hint) hint.textContent = '새파일로 삽입';
        loadHistory();
        setTimeout(() => { const inp = $('dr-prompt'); if (inp) inp.focus(); }, 60);
    }

    function hide() {
        const m = $('deep-research-modal');
        if (m) m.classList.remove('vis');
    }

    async function run() {
        if (_busy) return;
        const inp = $('dr-prompt'), out = $('dr-output'), thinkEl = $('dr-thinking');
        const loadEl = $('dr-loading'), thinkBtn = $('dr-thinking-btn'), insBtn = $('dr-insert-btn'), stopBtn = $('dr-stop-btn');
        let prompt = inp ? inp.value.trim() : '';
        if (!prompt) { alert('질문을 입력해 주세요.'); return; }
        prompt += _getStyleInstruction();
        const modelId = $('dr-model')?.value || 'gemini-2.5-pro';

        _busy = true;
        _abortController = new AbortController();
        const timeoutId = setTimeout(() => { if (_abortController) _abortController.abort(); }, 120000);
        if (loadEl) loadEl.style.display = 'flex';
        if (stopBtn) stopBtn.style.display = '';
        if (out) out.value = '답변 생성 중…';
        if (thinkEl) { thinkEl.value = ''; thinkEl.style.display = 'none'; }
        const drThinkingWrap = $('dr-thinking-wrap');
        if (drThinkingWrap) drThinkingWrap.style.display = 'none';
        if (thinkBtn) thinkBtn.style.display = 'none';
        const copyThinkBtn0 = document.getElementById('dr-copy-thinking-btn');
        if (copyThinkBtn0) copyThinkBtn0.style.display = 'none';
        const translateThinkBtn0 = document.getElementById('dr-translate-thinking-btn');
        if (translateThinkBtn0) translateThinkBtn0.style.display = 'none';
        const openThinkBtn0 = document.getElementById('dr-open-thinking-btn');
        if (openThinkBtn0) openThinkBtn0.style.display = 'none';
        if (insBtn) insBtn.disabled = true;

        try {
            const { text, thoughts } = await _callApi(prompt, modelId, _abortController.signal);
            _result = text;
            _thinking = thoughts;
            if (out) out.value = text || '(결과 없음)';
            if (thinkEl) thinkEl.value = thoughts;
            const drWrap = $('dr-thinking-wrap');
            if (drWrap) drWrap.style.display = thoughts ? 'flex' : 'none';
            if (thinkEl) thinkEl.style.display = thoughts ? 'flex' : 'none';
            if (thinkBtn) thinkBtn.style.display = thoughts ? '' : 'none';
            const copyThinkBtn = document.getElementById('dr-copy-thinking-btn');
            if (copyThinkBtn) copyThinkBtn.style.display = thoughts ? '' : 'none';
            const translateThinkBtn = document.getElementById('dr-translate-thinking-btn');
            if (translateThinkBtn) translateThinkBtn.style.display = thoughts ? '' : 'none';
            const openThinkBtn = document.getElementById('dr-open-thinking-btn');
            if (openThinkBtn) openThinkBtn.style.display = thoughts ? '' : 'none';
            if (insBtn) insBtn.disabled = !text;
            const title = prompt.slice(0, 50).trim() + (prompt.length > 50 ? '…' : '');
            const record = {
                id: 'dr-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9),
                title,
                prompt,
                result: text || '',
                thinking: thoughts || '',
                modelId,
                createdAt: Date.now()
            };
            await _add(record);
            const orderIds = await _getOrder();
            orderIds.unshift(record.id);
            await _setOrder(orderIds);
            _historyCache.unshift(record);
            filterHistory(_historySearch);
        } catch (e) {
            _result = '';
            _thinking = '';
            if (e.name === 'AbortError') {
                if (out) out.value = '⏹ 진행이 중지되었습니다.';
            } else {
                if (out) out.value = '⚠ ' + (e.message || String(e));
            }
            if (thinkBtn) thinkBtn.style.display = 'none';
            const wrapErr = $('dr-thinking-wrap');
            if (wrapErr) wrapErr.style.display = 'none';
            const copyThinkBtnErr = document.getElementById('dr-copy-thinking-btn');
            if (copyThinkBtnErr) copyThinkBtnErr.style.display = 'none';
            const translateThinkBtnErr = document.getElementById('dr-translate-thinking-btn');
            if (translateThinkBtnErr) translateThinkBtnErr.style.display = 'none';
            const openThinkBtnErr = document.getElementById('dr-open-thinking-btn');
            if (openThinkBtnErr) openThinkBtnErr.style.display = 'none';
            if (insBtn) insBtn.disabled = true;
        } finally {
            _busy = false;
            _abortController = null;
            clearTimeout(timeoutId);
            if (loadEl) loadEl.style.display = 'none';
            if (stopBtn) stopBtn.style.display = 'none';
        }
    }

    async function runPro() {
        const inp = $('dr-prompt-pro'), out = $('dr-output'), insBtn = $('dr-insert-btn');
        const prompt = inp ? inp.value.trim() : '';
        if (!prompt) { alert('리서치 질문을 입력해 주세요.'); return; }
        out.value = '⏳ Deep Research Pro Preview (deep-research-pro-preview-12-2025)는 Interactions API를 사용하며, 현재 서비스 준비 중입니다.';
        _result = out.value;
        if (insBtn) insBtn.disabled = false;
    }

    function toggleThinking() {
        const wrap = $('dr-thinking-wrap'), thinkEl = $('dr-thinking'), btn = $('dr-thinking-btn');
        if (!wrap || !btn) return;
        const show = wrap.style.display !== 'flex';
        wrap.style.display = show ? 'flex' : 'none';
        if (thinkEl) thinkEl.style.display = show ? 'flex' : 'none';
        btn.textContent = show ? '💭 생각 숨기기' : '💭 생각';
    }

    function _drFixedFilename() {
        const d = new Date();
        const y = d.getFullYear(), m = String(d.getMonth() + 1).padStart(2, '0'), day = String(d.getDate()).padStart(2, '0');
        const h = String(d.getHours()).padStart(2, '0'), min = String(d.getMinutes()).padStart(2, '0');
        return `dr-${y}-${m}-${day}-${h}${min}`;
    }

    function insertToNewFile() {
        const out = $('dr-output');
        const txt = out ? out.value.trim() : _result;
        if (!txt) {
            alert('삽입할 답변이 없습니다. 먼저 질문을 실행해 주세요.');
            return;
        }
        if (typeof TM === 'undefined') {
            alert('탭 기능을 사용할 수 없습니다.');
            return;
        }
        const hasThinking = !!(_thinking && _thinking.trim());
        if (hasThinking) {
            _pendingThinkingMode = 'newfile';
            _pendingSaveId = null;
            const chk = document.getElementById('dr-thinking-include-chk');
            const label = document.getElementById('dr-thinking-include-label');
            const btn = document.getElementById('dr-thinking-include-confirm-btn');
            const title = document.getElementById('dr-thinking-modal-title');
            if (chk) chk.checked = false;
            if (label) label.textContent = '생각 포함하여 새 파일로 삽입';
            if (btn) btn.textContent = '새 파일로 삽입';
            if (title) title.textContent = '새 파일로 삽입 시 생각 포함';
            const modal = document.getElementById('dr-thinking-include-modal');
            if (modal) modal.style.display = 'flex';
        } else {
            _doInsertToNewFile(false);
        }
    }

    function _doInsertToNewFile(includeThinking) {
        const out = $('dr-output');
        let txt = out ? out.value.trim() : _result;
        if (!txt) return;
        if (includeThinking && _thinking && _thinking.trim()) {
            txt = txt + '\n\n--- 생각 ---\n' + _thinking.trim();
        }
        const hintEl = $('dr-insert-hint');
        const customName = hintEl && hintEl.value ? hintEl.value.trim() : '';
        const name = customName !== '' ? customName.replace(/\.md$/i, '') : _drFixedFilename();
        TM.newTab(name, txt, 'md');
        hide();
    }

    function toggleNewFile() {
        _newFileMode = !_newFileMode;
        const fn = $('dr-filename'), hint = $('dr-insert-hint');
        if (fn) fn.style.display = _newFileMode ? 'inline-block' : 'none';
        if (hint) hint.textContent = '새파일로 삽입';
        if (_newFileMode && fn) fn.focus();
    }

    function insert() {
        const out = $('dr-output');
        const txt = out ? out.value.trim() : _result;
        if (!txt) return;

        const hasThinking = !!(_thinking && _thinking.trim());
        if (hasThinking) {
            _pendingThinkingMode = 'insert';
            _pendingSaveId = null;
            const chk = document.getElementById('dr-thinking-include-chk');
            const label = document.getElementById('dr-thinking-include-label');
            const btn = document.getElementById('dr-thinking-include-confirm-btn');
            const title = document.getElementById('dr-thinking-modal-title');
            if (chk) chk.checked = false;
            if (label) label.textContent = '생각 포함하여 삽입';
            if (btn) btn.textContent = '삽입';
            if (title) title.textContent = '삽입 시 생각 포함';
            const modal = document.getElementById('dr-thinking-include-modal');
            if (modal) modal.style.display = 'flex';
        } else {
            _doInsert(false);
        }
    }

    function _doInsert(includeThinking) {
        const out = $('dr-output');
        let txt = out ? out.value.trim() : _result;
        if (!txt) return;
        if (includeThinking && _thinking && _thinking.trim()) {
            txt = txt + '\n\n--- 생각 ---\n' + _thinking.trim();
        }
        const ed = $('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        ed.setRangeText(txt, s, e2, 'end');
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined') App.render();
        hide();
    }

    function copyResult() {
        const out = $('dr-output');
        const txt = out ? out.value.trim() : _result;
        if (!txt) return;
        navigator.clipboard.writeText(txt).then(() => alert('복사되었습니다.')).catch(() => {});
    }

    function clearOutput() {
        const out = $('dr-output');
        if (out) out.value = '';
        _result = '';
        const insBtn = $('dr-insert-btn');
        if (insBtn) insBtn.disabled = true;
    }

    function copyThinking() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) {
            alert('복사할 생각 내용이 없습니다.');
            return;
        }
        navigator.clipboard.writeText(txt).then(() => alert('생각 내용이 복사되었습니다.')).catch(() => {});
    }

    function openThinkingInNewWindow() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) {
            alert('표시할 생각 내용이 없습니다.');
            return;
        }
        let html;
        try {
            html = typeof mdRender === 'function' ? mdRender(txt, true) : (typeof marked !== 'undefined' ? marked.parse(txt) : txt.replace(/\n/g, '<br>'));
        } catch (e) {
            html = '<p style="color:red">' + (e.message || '렌더 오류') + '</p>';
        }
        html = (html || '').replace(/<\/script>/gi, '<\\/script>');
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        const w = window.open('', '_blank', 'width=900,height=700,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>생각 미리보기</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body class="dr-pv-window" style="margin:0;background:var(--bg1)">' +
            '<div id="preview-container" class="preview-container" style="position:absolute;inset:0;overflow:auto;padding:24px;box-sizing:border-box">' +
            '<div class="preview-page" data-page="1">' + html + '</div></div></body></html>'
        );
        w.document.close();
    }

    function openResultForTranslate() {
        const out = $('dr-output');
        const txt = out ? out.value.trim() : _result;
        if (!txt) { alert('번역할 결과가 없습니다.'); return; }
        hide();
        if (typeof Translator !== 'undefined') Translator.show(txt);
    }

    function openThinkingForTranslate() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) { alert('번역할 생각 내용이 없습니다.'); return; }
        hide();
        if (typeof Translator !== 'undefined') Translator.show(txt);
    }

    /** 텍스트가 주로 한국어면 ko→en, 아니면 en→ko. (en/ko 간단용) */
    function _drDetectEnKo(text) {
        if (!text || !text.length) return { sl: 'en', tl: 'ko' };
        let koCount = 0;
        for (let i = 0; i < text.length; i++) {
            const c = text.charCodeAt(i);
            if ((c >= 0xAC00 && c <= 0xD7A3) || (c >= 0x1100 && c <= 0x11FF) || (c >= 0x3130 && c <= 0x318F)) koCount++;
        }
        const ratio = koCount / text.length;
        return ratio > 0.15 ? { sl: 'ko', tl: 'en' } : { sl: 'en', tl: 'ko' };
    }

    /** #dr-thinking 안 툴바: 구글번역기 (en↔ko). 구글 스크래핑 없이 탭만 연다. */
    function thinkingTranslateGoogle() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) { alert('생각 내용이 없습니다.'); return; }
        if (typeof Translator === 'undefined') return;
        const { sl, tl } = _drDetectEnKo(txt);
        Translator.openBrowserWithText(txt, sl, tl);
    }

    /** #dr-thinking 안 툴바: 구글 스크래핑으로 번역 후 번역만 새창 (en↔ko). */
    function thinkingTranslateResultNewWindow() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) { alert('생각 내용이 없습니다.'); return; }
        if (typeof Translator === 'undefined') return;
        const { sl, tl } = _drDetectEnKo(txt);
        Translator.translateText(txt, sl, tl)
            .then(trans => Translator.openTranslationInNewWindowWithText(trans))
            .catch(e => alert('번역 실패: ' + (e.message || e)));
    }

    /** #dr-thinking 안 툴바: 구글 스크래핑으로 번역 후 원문+번역 새창 (en↔ko). */
    function thinkingTranslateBothNewWindow() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) { alert('생각 내용이 없습니다.'); return; }
        if (typeof Translator === 'undefined') return;
        const { sl, tl } = _drDetectEnKo(txt);
        Translator.translateText(txt, sl, tl)
            .then(trans => Translator.openOriginalAndTranslationInNewWindowWithText(txt, trans))
            .catch(e => alert('번역 실패: ' + (e.message || e)));
    }

    function openResultInNewWindow() {
        const out = $('dr-output');
        const txt = out ? out.value.trim() : _result;
        if (!txt) {
            alert('표시할 답변이 없습니다.');
            return;
        }
        let html;
        try {
            html = typeof mdRender === 'function' ? mdRender(txt, true) : (typeof marked !== 'undefined' ? marked.parse(txt) : txt.replace(/\n/g, '<br>'));
        } catch (e) {
            html = '<p style="color:red">' + (e.message || '렌더 오류') + '</p>';
        }
        html = (html || '').replace(/<\/script>/gi, '<\\/script>');
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        const w = window.open('', '_blank', 'width=900,height=700,scrollbars=yes,resizable=yes');
        if (!w) {
            alert('팝업이 차단되었을 수 있습니다. 새 창 허용 후 다시 시도해 주세요.');
            return;
        }
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>답변 미리보기</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body class="dr-pv-window" style="margin:0;background:var(--bg1)">' +
            '<div id="preview-container" class="preview-container" style="position:absolute;inset:0;overflow:auto;padding:24px;box-sizing:border-box">' +
            '<div class="preview-page" data-page="1">' + html + '</div></div></body></html>'
        );
        w.document.close();
    }

    async function runCiteAiSearch() {
        const presetEl = $('dr-ai-preset-text');
        const topicEl = $('dr-ai-topic');
        const yearsEl = $('dr-ai-years');
        const questionEl = $('dr-ai-prompt');
        const out = $('dr-output');
        const modelEl = $('dr-ai-model');
        if (!presetEl || !out) return;
        let prompt = (presetEl.value || '').trim();
        const topic = (topicEl && topicEl.value) ? topicEl.value.trim() : '';
        const years = (yearsEl && yearsEl.value) ? yearsEl.value.trim() : '';
        const question = (questionEl && questionEl.value) ? questionEl.value.trim() : '';
        if (!prompt) { out.value = '사전 프롬프트를 선택하거나 입력하세요.'; return; }
        prompt = prompt
            .replace(/\[여기에 주제 입력\]/g, topic || '[주제 미입력]')
            .replace(/\[연도 범위 입력\]/g, years || '[연도 미입력]')
            .replace(/\[연구주제\]/g, topic || '[주제 미입력]')
            .replace(/\[주제\]/g, topic || '[주제 미입력]');
        prompt += '\n\n' + _AI_SEARCH_VERIFICATION;
        if (question) prompt += '\n\n질문:\n' + question;
        prompt += _getStyleInstruction();
        const modelId = (modelEl && modelEl.value) ? modelEl.value : 'gemini-3-flash-preview';
        out.value = '🔄 AI 검색 중...';
        try {
            const { text } = await _callApi(prompt, modelId);
            out.value = text || '(결과 없음)';
        } catch (e) {
            out.value = '❌ ' + (e.message || String(e));
        }
    }

    function _getStyleInstruction() {
        const el = $('dr-style-tone');
        if (!el || !el.value) return '';
        const v = el.value;
        if (v === 'academic') return '\n\n답변은 반드시 학술체(~이다)로 작성하세요.';
        if (v === 'report') return '\n\n답변은 반드시 보고체(~임, ~함)로 작성하세요.';
        if (v === 'polite') return '\n\n답변은 반드시 일반체(존댓말)로 작성하세요.';
        return '';
    }

    async function runDataResearch() {
        const presetEl = $('dr-data-preset-text');
        const questionEl = $('dr-data-prompt');
        const out = $('dr-output');
        const modelEl = $('dr-data-model');
        if (!presetEl || !out) return;
        let prompt = (presetEl.value || '').trim();
        const question = (questionEl && questionEl.value) ? questionEl.value.trim() : '';
        if (!prompt) { out.value = '사전 프롬프트를 선택하거나 입력하세요.'; return; }
        prompt = prompt
            .replace(/\[여기에 주제 입력\]/g, question || '[주제 미입력]')
            .replace(/\[여기에 구체적 주제 입력\]/g, question || '[주제 미입력]')
            .replace(/\[연도 범위 입력\]/g, '[연도 범위 입력]')
            .replace(/\[연구주제\]/g, question || '[주제 미입력]')
            .replace(/\[주제\]/g, question || '[주제 미입력]');
        prompt += '\n\n' + _AI_SEARCH_VERIFICATION;
        if (question) prompt += '\n\n질문:\n' + question;
        prompt += _getStyleInstruction();
        const modelId = (modelEl && modelEl.value) ? modelEl.value : 'gemini-3-flash-preview';
        out.value = '🔄 AI자료조사 중...';
        try {
            const { text } = await _callApi(prompt, modelId);
            out.value = text || '(결과 없음)';
        } catch (e) {
            out.value = '❌ ' + (e.message || String(e));
        }
    }

    function applyDataResearchPreset() {
        const sel = $('dr-data-preset');
        const ta = $('dr-data-preset-text');
        if (!sel || !ta) return;
        const key = sel.value || 'basic';
        ta.value = _AI_SEARCH_PRESETS[key] || _AI_SEARCH_PRESETS.basic;
    }

    function openDataPresetTextWindow() {
        const ta = $('dr-data-preset-text');
        if (!ta) return;
        window.__drDataPresetApply = function(popupWin) {
            try {
                const pw = popupWin.document.getElementById('pw');
                if (pw) ta.value = pw.value;
            } catch (e) {}
            popupWin.close();
        };
        window.__drDataPresetText = function() { return ta ? ta.value : ''; };
        _openPresetWindowWithTools('__drDataPresetApply', '__drDataPresetText');
    }

    function _openPresetWindowWithTools(applyKey, getTextKey) {
        const w = window.open('', '_blank', 'width=720,height=520,resizable=yes,scrollbars=yes');
        if (!w) return;
        const applyQ = JSON.stringify(applyKey);
        const getQ = JSON.stringify(getTextKey);
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>사전 프롬프트</title><style>'
            + 'body{font-family:inherit;background:#1c1c26;color:#e8e8f0;margin:0;padding:12px;box-sizing:border-box;display:flex;flex-direction:column;height:100%;}'
            + '#pw-wrap{flex:1;min-height:0;overflow:auto;}'
            + 'textarea{width:100%;height:100%;min-height:280px;background:#16161d;border:1px solid #2e2e42;color:#e8e8f0;padding:10px;font-size:13px;line-height:1.5;resize:both;display:block;box-sizing:border-box;}'
            + '.btns{margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;flex-shrink:0;}'
            + 'button{padding:6px 12px;cursor:pointer;border-radius:4px;font-size:12px;}'
            + '.apply{background:#7c6af7;color:#fff;border:none;}'
            + '.close{background:#2a2a3a;color:#9090b0;border:1px solid #2e2e42;}'
            + '.tool{background:#3a3a4a;color:#c0c0e0;border:1px solid #2e2e42;}'
            + '</style></head><body>'
            + '<div id="pw-wrap"><textarea id="pw"></textarea></div>'
            + '<div class="btns">'
            + '<button class="tool" onclick="var t=document.getElementById(\'pw\');var s=parseInt(getComputedStyle(t).fontSize)||13;t.style.fontSize=Math.min(24,s+2)+\'px\'">확대</button>'
            + '<button class="tool" onclick="var t=document.getElementById(\'pw\');var s=parseInt(getComputedStyle(t).fontSize)||13;t.style.fontSize=Math.max(10,s-2)+\'px\'">축소</button>'
            + '<button class="tool" onclick="document.getElementById(\'pw-wrap\').scrollTop=0">맨 위로</button>'
            + '<button class="tool" onclick="window.print()">인쇄</button>'
            + '<button class="apply" onclick="opener[' + applyQ + '](window)">적용 후 닫기</button>'
            + '<button class="close" onclick="window.close()">닫기</button>'
            + '</div>'
            + '<script>document.getElementById("pw").value=opener[' + getQ + ']();<\/script></body></html>'
        );
        w.document.close();
    }

    function openPresetTextWindow() {
        const ta = $('dr-ai-preset-text');
        if (!ta) return;
        window.__drPresetApply = function(popupWin) {
            try {
                const pw = popupWin.document.getElementById('pw');
                if (pw) ta.value = pw.value;
            } catch (e) {}
            popupWin.close();
        };
        window.__drPresetText = function() { return ta ? ta.value : ''; };
        _openPresetWindowWithTools('__drPresetApply', '__drPresetText');
    }

    function applyCiteAiSearchPreset() {
        const sel = document.getElementById('cite-ai-preset');
        const ta = document.getElementById('cite-ai-preset-text');
        if (!sel || !ta) return;
        const key = sel.value || 'basic';
        ta.value = _AI_SEARCH_PRESETS[key] || _AI_SEARCH_PRESETS.basic;
    }

    function openCitePresetTextWindow() {
        const ta = document.getElementById('cite-ai-preset-text');
        if (!ta) return;
        window.__citePresetApply = function(popupWin) {
            try {
                const pw = popupWin.document.getElementById('pw');
                if (pw) ta.value = pw.value;
            } catch (e) {}
            popupWin.close();
        };
        window.__citePresetText = function() { return ta ? ta.value : ''; };
        _openPresetWindowWithTools('__citePresetApply', '__citePresetText');
    }

    async function runCiteAiSearchFromModal() {
        const presetEl = document.getElementById('cite-ai-preset-text');
        const questionEl = document.getElementById('cite-ai-prompt');
        const out = document.getElementById('cite-ai-out');
        const modelEl = document.getElementById('cite-ai-model');
        if (!presetEl || !out) return;
        let prompt = (presetEl.value || '').trim();
        const question = (questionEl && questionEl.value) ? questionEl.value.trim() : '';
        if (!prompt) { out.value = '사전 프롬프트를 선택하거나 입력하세요.'; return; }
        prompt = prompt
            .replace(/\[여기에 주제 입력\]/g, '[주제 미입력]')
            .replace(/\[연도 범위 입력\]/g, '[연도 미입력]')
            .replace(/\[연구주제\]/g, '[주제 미입력]')
            .replace(/\[주제\]/g, '[주제 미입력]');
        prompt += '\n\n' + _AI_SEARCH_VERIFICATION;
        if (question) prompt += '\n\n질문:\n' + question;
        prompt += _getStyleInstruction();
        const modelId = (modelEl && modelEl.value) ? modelEl.value : 'gemini-3-flash-preview';
        out.value = '🔄 AI 검색 중...';
        try {
            const { text } = await _callApi(prompt, modelId);
            out.value = text || '(결과 없음)';
        } catch (e) {
            out.value = '❌ ' + (e.message || String(e));
        }
    }

    function _getCiteModalOutText() {
        const out = document.getElementById('cite-ai-out');
        return out ? out.value.trim() : '';
    }

    function insertFromCiteModal() {
        const txt = _getCiteModalOutText();
        if (!txt) { alert('삽입할 답변이 없습니다.'); return; }
        const ed = document.getElementById('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        ed.setRangeText(txt, s, e2, 'end');
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined') App.render();
        if (typeof App !== 'undefined') App.hideModal('cite-modal');
    }

    function insertToNewFileFromCiteModal() {
        const txt = _getCiteModalOutText();
        if (!txt) { alert('삽입할 답변이 없습니다.'); return; }
        if (typeof TM === 'undefined') { alert('탭 기능을 사용할 수 없습니다.'); return; }
        const hintEl = document.getElementById('cite-ai-insert-hint');
        const customName = hintEl && hintEl.value ? hintEl.value.trim() : '';
        const name = customName || _drFixedFilename();
        TM.newTab(name, txt);
        if (hintEl) hintEl.value = '';
        if (typeof App !== 'undefined') App.hideModal('cite-modal');
    }

    function copyResultFromCiteModal() {
        const txt = _getCiteModalOutText();
        if (!txt) { alert('복사할 결과가 없습니다.'); return; }
        navigator.clipboard.writeText(txt).then(() => alert('복사되었습니다.')).catch(() => {});
    }

    function openResultInNewWindowFromCiteModal() {
        const txt = _getCiteModalOutText();
        if (!txt) { alert('표시할 답변이 없습니다.'); return; }
        let html;
        try {
            html = typeof mdRender === 'function' ? mdRender(txt, true) : (typeof marked !== 'undefined' ? marked.parse(txt) : txt.replace(/\n/g, '<br>'));
        } catch (e) {
            html = '<p style="color:red">' + (e.message || '렌더 오류') + '</p>';
        }
        html = (html || '').replace(/<\/script>/gi, '<\\/script>');
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        const w = window.open('', '_blank', 'width=900,height=700,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>답변 미리보기</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body class="dr-pv-window" style="margin:0;background:var(--bg1)">' +
            '<div id="preview-container" class="preview-container" style="position:absolute;inset:0;overflow:auto;padding:24px;box-sizing:border-box">' +
            '<div class="preview-page" data-page="1">' + html + '</div></div></body></html>'
        );
        w.document.close();
    }

    function openResultForTranslateFromCiteModal() {
        const txt = _getCiteModalOutText();
        if (!txt) { alert('번역할 결과가 없습니다.'); return; }
        if (typeof App !== 'undefined') App.hideModal('cite-modal');
        if (typeof Translator !== 'undefined') Translator.show(txt);
    }

    const _AI_SEARCH_PRESETS = {
        basic: `You are an academic research assistant.

Task:
Search for real, peer-reviewed journal articles on the following topic:
[여기에 주제 입력]

Search conditions:
- Publication years: [연도 범위 입력]
- Only include verifiable, existing journal articles.
- Do NOT fabricate citations.
- If bibliographic information is uncertain, explicitly state uncertainty.

Output requirements:
1. Format all references strictly in APA 7th edition.
2. Include DOI when available.
3. Indicate journal indexing status (SSCI/SCIE/ESCI/Scopus if known).
4. Separate domestic (Korean) and international studies if applicable.
5. For each article, provide 2–3 sentences summarizing:
   - Research purpose
   - Methodology (e.g., SEM, multilevel modeling, regression, meta-analysis)
   - Key findings
6. Focus on recent theoretical frameworks when relevant.`,
        research: `You are a doctoral-level research assistant.

Search for empirical studies on:
[연구주제]

Conditions:
- Years: 2023–2026
- Empirical quantitative studies only
- Clearly state:
    - Theoretical framework (e.g., Meyer & Allen model, JD-R model, SET)
    - Sample size and characteristics
    - Statistical method used (SEM, PLS-SEM, multilevel SEM, HLM, CFA, regression)
    - Model fit indices if SEM is used
- Provide citation count if available.
- APA 7 format with DOI required.
- No fabricated sources.`,
        meta: `Search for systematic reviews or meta-analyses on:
[주제]

Include:
- Effect sizes reported
- Number of studies included
- Statistical model used (random/fixed effects)
- Publication bias test methods
- DOI and APA 7 format

Exclude narrative reviews.`,
        recommend: `You are an academic research assistant.

Search for peer-reviewed empirical journal articles on:
[주제]

Years: 2023–2026

Requirements:
- Only real, verifiable articles.
- Verify existence through academic databases.
- APA 7th edition format.
- DOI required.
- State theoretical framework.
- Specify statistical method.
- Separate Korean and international studies.
- Provide 2–3 sentence structured summary.
- Do not fabricate citations.`,
        'data-survey': `You are a doctoral-level academic research assistant specializing in theoretical and conceptual analysis.

Task:
Conduct a structured theoretical literature investigation on the following topic:

[여기에 주제 입력]

Purpose:
This task is NOT for building a research model.
This task is for:
- Identifying core concepts
- Clarifying theoretical definitions
- Tracing conceptual evolution
- Collecting authoritative citations

Search Conditions:
- Publication years: [연도 범위 입력]
- Include foundational classical works and recent theoretical developments.
- Only include real, peer-reviewed journal articles or academic books.
- Do NOT fabricate citations.
- If bibliographic information is uncertain, clearly state uncertainty.
- Prioritize SSCI/SCIE/ESCI/Scopus-indexed journals when possible.

Required Output Structure:

I. Conceptual Definitions
- Provide multiple academic definitions.
- Compare differences in definition across scholars.
- Identify definitional debates if they exist.
- Clarify boundary conditions of the concept.

II. Theoretical Foundations
- Identify major theoretical frameworks underpinning the concept.
- Explain how each theory conceptualizes the construct.
- Indicate theoretical evolution over time.
- Distinguish normative, functional, and strategic perspectives where relevant.

III. Conceptual Structure
- Identify core dimensions or components.
- Indicate measurement traditions if applicable.
- Clarify conceptual overlaps with related constructs.

IV. Intellectual Genealogy
- Identify key scholars.
- Identify seminal works.
- Indicate how the concept has shifted historically.

V. Reference List
- Format strictly in APA 7th edition.
- Include DOI when available.
- Indicate journal indexing status (SSCI/SCIE/ESCI/Scopus if known).
- Separate domestic (Korean) and international literature if applicable.

Formatting Rules:
- Use formal academic tone.
- Avoid narrative summary.
- Structure analytically.
- Ensure terminological consistency.
- Do not generate fictional sources.

Explicitly distinguish between dictionary-style definitions and theory-based academic definitions.
Indicate which definitions are most frequently cited in SSCI literature.
Highlight conceptual ambiguities.`,
        'systematic-review': `You are a doctoral-level academic research assistant specializing in systematic literature review.

Task:
Conduct a structured literature review on the following topic:

[여기에 구체적 주제 입력]

Search Scope:
- Publication years: [연도 범위 입력]
- Include only real, peer-reviewed journal articles or academic books.
- Do NOT fabricate citations.
- If bibliographic details are uncertain, explicitly state uncertainty.
- Prioritize SSCI/SCIE/ESCI/Scopus-indexed journals when possible.
- Include both foundational classical theories and recent developments (post-2015).

Search Requirements:
- Identify major theoretical frameworks.
- Identify dominant research methodologies.
- Identify key dependent and independent variables used in prior studies.
- Highlight areas of consensus and debate.
- Identify research gaps.

Output Structure:

I. Theoretical Trends
- Major theoretical frameworks
- Evolution of key concepts
- Competing perspectives

II. Methodological Trends
- Dominant research designs (SEM, multilevel modeling, regression, meta-analysis, experimental, qualitative)
- Sample characteristics
- Measurement approaches

III. Empirical Findings Synthesis
- Consistent findings
- Contradictory findings
- Boundary conditions

IV. Research Gaps and Future Directions
- Theoretical gaps
- Methodological limitations
- Underexplored variables
- Suggestions for advanced modeling

V. Reference List
- APA 7th edition format
- Include DOI when available
- Indicate journal indexing status (if known)
- Separate domestic and international studies if applicable

Formatting Rules:
- Use formal academic tone.
- Avoid narrative storytelling.
- Structure analytically.
- Maintain conceptual precision.

Explicitly identify under-theorized areas.
Distinguish between statistical significance and theoretical contribution.
Indicate where longitudinal or multilevel modeling is needed.`,
        'academic-paper': `You are a doctoral-level academic research assistant specializing in education, organizational theory, and management research.

Task:
Produce three structured outputs on the following topic:

[여기에 구체적 주제 입력]
(e.g., Educational Industry Consulting and Organizational Outcomes)

The output must include:

------------------------------------------------------------
1. Conceptual and Theoretical Synthesis Sample
------------------------------------------------------------

Requirements:
- Define all key constructs clearly and academically.
- Compare competing definitions if they exist.
- Explain conceptual evolution over time.
- Identify theoretical linkages among constructs.
- Explicitly state theoretical foundations (e.g., systems theory, social exchange theory, human capital theory, organizational commitment theory).
- Maintain conceptual precision and terminological consistency.
- Avoid descriptive narration; structure analytically.

------------------------------------------------------------
2. Research Model Design Sample
------------------------------------------------------------

Requirements:
- Propose a logically grounded research model.
- Clearly identify:
  • Independent variables
  • Mediators (if applicable)
  • Dependent variables
  • Control variables (if relevant)
- Provide theoretical justification for each hypothesized path.
- Present 3–5 example hypotheses.
- Suggest appropriate methodology (e.g., SEM, multilevel modeling, mediation analysis).
- If possible, describe the conceptual framework in text-based diagram form.
- Indicate potential measurement scales if known.

------------------------------------------------------------
3. Empirical Evidence Review Sample (with APA references)
------------------------------------------------------------

Search Conditions:
- Publication years: [연도 범위 입력]
- Include only real, peer-reviewed journal articles or academic books.
- No fabricated citations.
- If bibliographic details are uncertain, explicitly state uncertainty.
- Prioritize SSCI/SCIE/ESCI/Scopus-indexed journals when possible.
- Include both classical foundational studies and recent developments (post-2015).

Output Requirements:
- Separate domestic (Korean) and international studies if applicable.
- For each cited study, briefly summarize:
  • Research purpose
  • Methodology
  • Key findings
- Format all references strictly in APA 7th edition.
- Include DOI when available.
- Indicate journal indexing status (if known).

------------------------------------------------------------
Formatting Rules:
------------------------------------------------------------
- Use formal academic tone.
- Ensure conceptual rigor.
- Maintain theoretical coherence.
- Do not generate fictional sources.
- Structure output using Roman numerals (I, II, III).

Prioritize conceptual and theoretical analysis over descriptive summaries.
Explicitly distinguish between normative, functional, and strategic perspectives.
Clarify differences between business consulting and educational consulting where relevant.`,
        citation: `You are an academic citation assistant.

Task:
Search for real, verifiable, peer-reviewed journal articles on:

[여기에 주제 입력]

Search Conditions:
- Publication years: [연도 범위 입력]
- Only include existing journal articles.
- Do NOT fabricate citations.
- If uncertain, clearly state uncertainty.

Output Requirements:
1. Format strictly in APA 7th edition.
2. Include DOI when available.
3. Indicate journal indexing status (SSCI/SCIE/ESCI/Scopus if known).
4. Separate domestic and international studies.
5. Provide 2–3 sentence structured summary for each:
   - Research purpose
   - Methodology
   - Key findings
6. Focus on theoretical and empirical contributions.

Formatting Rules:
- Do not include commentary.
- Only provide structured citation results.`
    };

    const _AI_SEARCH_VERIFICATION = `Before presenting results, verify that each article exists in recognized academic databases (Google Scholar, Crossref, Web of Science, Scopus, or official journal websites).
If verification is not possible, do not include the citation.`;

    function applyAiSearchPreset() {
        const sel = $('dr-ai-preset');
        const ta = $('dr-ai-preset-text');
        if (!sel || !ta) return;
        const key = sel.value || 'basic';
        ta.value = _AI_SEARCH_PRESETS[key] || _AI_SEARCH_PRESETS.basic;
    }

    function openCiteAiSearch() {
        hide();
        if (typeof App !== 'undefined' && App.showCite) App.showCite();
        if (typeof CM !== 'undefined' && CM.tab) setTimeout(() => CM.tab('ai-search'), 50);
    }

    return { show, hide, run, stopRun, runPro, switchTab, toggleMaximize, toggleThinking, toggleNewFile, insertToNewFile, insert, copyResult, copyThinking, clearOutput, openResultInNewWindow, openThinkingInNewWindow, openResultForTranslate, openThinkingForTranslate, thinkingTranslateGoogle, thinkingTranslateResultNewWindow, thinkingTranslateBothNewWindow, loadHistory, filterHistory, loadHistoryItem, renameHistory, deleteHistory, openHistorySaveModal, closeHistorySaveModal, saveHistoryAsZip, saveHistoryBatch, saveHistoryItemToFile, closeThinkingIncludeModal, confirmThinkingInclude, runCiteAiSearch, openCiteAiSearch, applyAiSearchPreset, openPresetTextWindow, applyCiteAiSearchPreset, openCitePresetTextWindow, runCiteAiSearchFromModal, insertFromCiteModal, insertToNewFileFromCiteModal, copyResultFromCiteModal, openResultInNewWindowFromCiteModal, openResultForTranslateFromCiteModal, runDataResearch, applyDataResearchPreset, openDataPresetTextWindow };
})();
window.DeepResearch = DeepResearch;

/* ═══════════════════════════════════════════════════════════
   TRANSLATOR — 번역기 (Shift+Alt+G)
   1순위: MyMemory API (무료·CORS OK·API키 불필요)
   2순위: 공개 LibreTranslate 인스턴스
═══════════════════════════════════════════════════════════ */
const Translator = (() => {
    let _lastResult = '';
    let _busy = false;
    let _currentTab = 'translate';

    /* ── Gemini API 호출 ─────────────────────────────────── */
    const _LANG_NAMES = { ko:'한국어', en:'영어', ja:'일본어', zh:'중국어', fr:'프랑스어', de:'독일어', es:'스페인어', ru:'러시아어', pt:'포르투갈어', it:'이탈리아어', ar:'아랍어' };
    async function _callGemini(prompt, userText, modelId) {
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) throw new Error('AI API 키를 설정에서 입력·저장해 주세요.');
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(key)}`;
        const body = {
            contents: [{ parts: [{ text: prompt + '\n\n' + userText }] }],
            generationConfig: { temperature: 0.4, maxOutputTokens: 8192 }
        };
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(60000)
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            throw new Error(err.error?.message || `HTTP ${r.status}`);
        }
        const d = await r.json();
        const txt = d.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!txt) throw new Error('AI 응답이 비어 있습니다.');
        return txt.trim();
    }

    /* ── MyMemory (1순위) ───────────────────────────────── */
    const _MM_CODE = { zh:'zh-CN', ko:'ko', en:'en', ja:'ja',
                       fr:'fr',   de:'de', es:'es', ru:'ru',
                       pt:'pt',   it:'it', ar:'ar' };

    async function _myMemory(text, sl, tl) {
        const sc = _MM_CODE[sl] || sl;
        const tc = _MM_CODE[tl] || tl;
        const url = `https://api.mymemory.translated.net/get` +
                    `?q=${encodeURIComponent(text)}&langpair=${sc}|${tc}`;
        const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const d = await r.json();
        if (d.responseStatus !== 200)
            throw new Error(d.responseDetails || d.responseStatus || 'MyMemory 오류');
        const t = d.responseData?.translatedText;
        /* MyMemory가 그대로 반환하거나 에러문 반환 시 예외 */
        if (!t || (typeof t === 'string' && t === text)) throw new Error('번역 결과 없음');
        return String(t);
    }

    /* ── LibreTranslate 공개 인스턴스 (2순위, #tr-translate-btn 시 사용) ─────────────── */
    const _LT_HOSTS = [
        'https://de.libretranslate.com',
        'https://libretranslate.de',
        'https://translate.cutie.dating',
    ];
    async function _libreTranslate(text, sl, tl) {
        for (const host of _LT_HOSTS) {
            try {
                const r = await fetch(`${host}/translate`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ q: text, source: sl, target: tl, format: 'text' }),
                    signal: AbortSignal.timeout(12000),
                });
                if (!r.ok) continue;
                const d = await r.json();
                const t = d.translatedText || d.translation;
                if (t) return t;
            } catch { /* 다음 서버 시도 */ }
        }
        throw new Error('모든 번역 서버에 접속할 수 없습니다');
    }

    /* ── 구글 번역 모바일 스크래핑 (R 방식: URL 요청 후 .result-container 파싱) ───────────── */
    async function _googleTranslateScrape(text, sl, tl) {
        const url = 'https://translate.google.com/m?sl=' + encodeURIComponent(sl) +
            '&hl=' + encodeURIComponent(tl) +
            '&q=' + encodeURIComponent(text);
        const proxyUrl = 'https://corsproxy.io/?' + encodeURIComponent(url);
        const r = await fetch(proxyUrl, {
            signal: AbortSignal.timeout(15000),
            headers: { 'Accept': 'text/html' }
        });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const html = await r.text();
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const selectors = ['.result-container', '.result-div', '.translated-ltr', '[data-result-index]'];
        let result = '';
        for (const sel of selectors) {
            const el = doc.querySelector(sel);
            if (el && (el.textContent || '').trim()) {
                result = el.textContent.trim();
                break;
            }
        }
        if (!result) throw new Error('구글 번역 결과를 찾을 수 없습니다');
        return result;
    }

    async function _doTranslate(text, sl, tl) {
        const engineEl = document.getElementById('tr-engine');
        const engine = (engineEl && engineEl.value) || 'google';
        if (engine === 'google') {
            return await _googleTranslateScrape(text, sl, tl);
        }
        if (engine === 'mymemory') {
            return await _myMemory(text, sl, tl);
        }
        if (engine === 'libre') {
            return await _libreTranslate(text, sl, tl);
        }
        return await _googleTranslateScrape(text, sl, tl);
    }

    /* ── UI 유틸 ──────────────────────────────────────── */
    const $ = id => document.getElementById(id);
    function _setStatus(msg, type) {
        const el = $('tr-status');
        if (!el) return;
        el.textContent = msg;
        el.style.color = type === 'ok'   ? 'var(--ok)'  :
                         type === 'err'  ? 'var(--er)'  :
                         type === 'warn' ? '#f7c060'    : 'var(--tx3)';
    }
    function _updateCount() {
        const inp = $('tr-input'), cnt = $('tr-input-count');
        if (inp && cnt) cnt.textContent = inp.value.length + '자';
    }

    /* ── 공개 API ─────────────────────────────────────── */
    function show(initialText) {
        const modal = $('translator-modal');
        if (!modal) return;
        const inp = $('tr-input');
        if (inp) {
            if (initialText != null && initialText !== '') {
                inp.value = typeof initialText === 'string' ? initialText : String(initialText);
                _updateCount();
            } else {
                const ed = $('editor');
                if (ed) {
                    const sel = ed.value.substring(ed.selectionStart, ed.selectionEnd).trim();
                    if (sel) { inp.value = sel; _updateCount(); }
                }
            }
        }
        modal.classList.add('vis');
        switchTab('translate');
        setTimeout(() => { const i = $('tr-input'); if (i) i.focus(); }, 60);
    }

    function openOriginalAndTranslationInNewWindow() {
        const inp = $('tr-input'), out = $('tr-output');
        const orig = inp ? inp.value.trim() : '';
        const trans = out ? out.value.trim() : '';
        if (!orig && !trans) {
            alert('원문 또는 번역 결과가 없습니다.');
            return;
        }
        const combined = trans ? (orig + '\n\n--- 번역 ---\n' + trans) : orig;
        const w = window.open('', '_blank', 'width=800,height=600,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>원문 + 번역</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;background:var(--bg3)">' +
            '<button type="button" onclick="var p=document.getElementById(\'tr-combined-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.min(24,s+2)+\'px\';var L=document.getElementById(\'tr-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx)">확대</button>' +
            '<button type="button" onclick="var p=document.getElementById(\'tr-combined-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.max(10,s-2)+\'px\';var L=document.getElementById(\'tr-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx)">축소</button>' +
            '<span id="tr-zoom-label" style="font-size:11px;color:var(--tx3);min-width:40px">100%</span>' +
            '</div>' +
            '<div style="flex:1;min-height:0;overflow:auto;padding:20px">' +
            '<pre id="tr-combined-content" style="white-space:pre-wrap;word-break:break-word;max-width:720px;margin:0 auto;font-size:13px;line-height:1.7;font-family:inherit"></pre>' +
            '</div></body></html>'
        );
        w.document.close();
        var el = w.document.getElementById('tr-combined-content');
        if (el) el.textContent = combined;
    }

    /** 번역 결과(tr-output)만 클립보드에 복사하고 새 창으로 띄움. 구글번역 등에서 붙여넣은 결과에 유용. */
    function openTranslationInNewWindow() {
        const out = $('tr-output');
        const txt = out ? out.value.trim() : _lastResult || '';
        if (!txt) {
            alert('번역 결과가 없습니다. 구글번역 등에서 번역한 뒤 여기에 붙여넣고 다시 시도하세요.');
            return;
        }
        navigator.clipboard.writeText(txt).catch(() => {});
        const w = window.open('', '_blank', 'width=800,height=600,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>번역 결과</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;background:var(--bg3)">' +
            '<span style="font-size:11px;color:var(--tx3)">번역 결과 (클립보드에 복사됨)</span>' +
            '<button type="button" onclick="var p=document.getElementById(\'tr-only-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.min(24,s+2)+\'px\';var L=document.getElementById(\'tr-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx)">확대</button>' +
            '<button type="button" onclick="var p=document.getElementById(\'tr-only-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.max(10,s-2)+\'px\';var L=document.getElementById(\'tr-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx)">축소</button>' +
            '<span id="tr-zoom-label" style="font-size:11px;color:var(--tx3);min-width:40px">100%</span>' +
            '</div>' +
            '<div style="flex:1;min-height:0;overflow:auto;padding:20px">' +
            '<pre id="tr-only-content" style="white-space:pre-wrap;word-break:break-word;max-width:720px;margin:0 auto;font-size:13px;line-height:1.7;font-family:inherit"></pre>' +
            '</div></body></html>'
        );
        w.document.close();
        const el = w.document.getElementById('tr-only-content');
        if (el) el.textContent = txt;
        _setStatus('번역 결과를 복사했고 새 창을 열었습니다.', 'ok');
        setTimeout(() => _setStatus(''), 3000);
    }

    /** (en/ko 간단용) 구글 스크래핑으로 번역만 수행. 외부(DR 생각 등)에서 호출. */
    function translateText(text, sl, tl) {
        return _googleTranslateScrape(text, sl || 'en', tl || 'ko');
    }

    /** (en/ko 간단용) 텍스트만으로 구글 번역 탭 열기. 번역기 모달 구글번역기 버튼과 동일한 데스크톱 URL 사용. */
    function openBrowserWithText(text, sl, tl) {
        const s = sl || 'en', t = tl || 'ko';
        window.open(
            'https://translate.google.com/?sl=' + encodeURIComponent(s) + '&tl=' + encodeURIComponent(t) + '&text=' + encodeURIComponent(text) + '&op=translate',
            '_blank'
        );
    }

    /** (en/ko 간단용) 번역문만 새 창으로 띄움. */
    function openTranslationInNewWindowWithText(txt) {
        if (!txt) return;
        navigator.clipboard.writeText(txt).catch(() => {});
        const w = window.open('', '_blank', 'width=800,height=600,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>번역 결과</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;background:var(--bg3)">' +
            '<span style="font-size:11px;color:var(--tx3)">번역 결과 (클립보드에 복사됨)</span>' +
            '</div>' +
            '<div style="flex:1;min-height:0;overflow:auto;padding:20px">' +
            '<pre style="white-space:pre-wrap;word-break:break-word;max-width:720px;margin:0 auto;font-size:13px;line-height:1.7;font-family:inherit"></pre>' +
            '</div></body></html>'
        );
        w.document.close();
        const pre = w.document.querySelector('pre');
        if (pre) pre.textContent = txt;
    }

    /** (en/ko 간단용) 원문+번역 새 창으로 띄움. */
    function openOriginalAndTranslationInNewWindowWithText(orig, trans) {
        const combined = (orig || '') + (trans ? '\n\n--- 번역 ---\n' + trans : '');
        if (!combined.trim()) return;
        const w = window.open('', '_blank', 'width=800,height=600,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>원문 + 번역</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);background:var(--bg3)"></div>' +
            '<div style="flex:1;min-height:0;overflow:auto;padding:20px">' +
            '<pre style="white-space:pre-wrap;word-break:break-word;max-width:720px;margin:0 auto;font-size:13px;line-height:1.7;font-family:inherit"></pre>' +
            '</div></body></html>'
        );
        w.document.close();
        const pre = w.document.querySelector('pre');
        if (pre) pre.textContent = combined;
    }

    function hide() {
        const m = $('translator-modal');
        if (m) m.classList.remove('vis');
        const inner = document.getElementById('translator-modal-inner');
        if (inner) inner.classList.remove('tr-maximized');
    }

    function toggleFullscreen() {
        const el = document.getElementById('translator-modal-inner');
        if (!el) return;
        const on = el.classList.toggle('tr-maximized');
        const btn = document.getElementById('tr-fullscreen-btn');
        if (btn) {
            btn.textContent = on ? '전체화면 해제' : '전체화면';
            btn.title = on ? '전체화면 해제' : '전체화면';
        }
    }

    function switchTab(tab) {
        _currentTab = tab;
        document.querySelectorAll('#tr-tabs .tr-tab').forEach(b => {
            b.classList.toggle('active', b.dataset.tab === tab);
        });
        const aiTrans = $('tr-ai-translate-panel'), aiWrite = $('tr-ai-write-panel'), langRow = $('tr-lang-row'), engineRow = $('tr-engine-row'), transBtn = $('tr-translate-btn');
        if (aiTrans) aiTrans.style.display = (tab === 'ai-translate') ? 'flex' : 'none';
        if (aiWrite) aiWrite.style.display = (tab === 'ai-write') ? 'flex' : 'none';
        if (langRow) langRow.style.display = (tab === 'translate' || tab === 'ai-translate') ? 'flex' : 'none';
        if (engineRow) engineRow.style.display = (tab === 'translate') ? 'flex' : 'none';
        if (transBtn) {
            transBtn.textContent = tab === 'ai-translate' ? '🤖 AI 번역' : '🌐 번역';
            transBtn.onclick = () => (tab === 'ai-translate' ? aiTranslate() : translate());
        }
    }

    async function aiTranslate() {
        if (_busy) return;
        const inp = $('tr-input'), out = $('tr-output');
        const loadEl = $('tr-loading'), insBtn = $('tr-insert-btn');
        const text = inp ? inp.value.trim() : '';
        if (!text) { _setStatus('⚠ 번역할 텍스트를 입력해 주세요.', 'warn'); return; }
        const sl = $('tr-src-lang')?.value, tl = $('tr-tgt-lang')?.value;
        if (sl === tl) { _setStatus('⚠ 원본/번역 언어가 같습니다.', 'warn'); return; }
        const prompt = ($('tr-ai-translate-prompt')?.value || '').trim() || '넌 대학교수, 연구자야 이 번역을 학술연구자에 맞는 용어로 번역해';
        const model = $('tr-model')?.value || 'gemini-2.5-flash';
        const fullPrompt = `${prompt}\n\n다음 텍스트를 ${_LANG_NAMES[sl] || sl}에서 ${_LANG_NAMES[tl] || tl}로 번역해:`;

        _busy = true;
        if (loadEl) loadEl.style.display = 'flex';
        if (out) out.value = 'AI 번역 중…';
        if (insBtn) insBtn.disabled = true;
        _setStatus('');
        try {
            const result = await _callGemini(fullPrompt, text, model);
            _lastResult = result;
            if (out) out.value = result;
            if (insBtn) insBtn.disabled = false;
            _setStatus(`✅ 완료 · ${result.length}자`, 'ok');
        } catch (e) {
            _lastResult = '';
            if (out) out.value = `⚠ ${e.message}`;
            _setStatus('❌ 오류', 'err');
        } finally {
            _busy = false;
            if (loadEl) loadEl.style.display = 'none';
        }
    }

    async function aiWrite() {
        if (_busy) return;
        const inp = $('tr-input'), out = $('tr-output');
        const loadEl = $('tr-loading'), insBtn = $('tr-insert-btn');
        const text = inp ? inp.value.trim() : '';
        if (!text) { _setStatus('⚠ 텍스트를 입력해 주세요.', 'warn'); return; }
        const prompt = ($('tr-ai-write-prompt')?.value || '').trim() || '넌 대학교수, 연구자야 이 번역을 학술연구자에 맞는 글로 다시 써줘. 문장은 ~이다 체로 용어를 학술적용어에 맞게, 대학원이상수준의 글로 써줘';
        const model = $('tr-model-write')?.value || 'gemini-2.5-flash';

        _busy = true;
        if (loadEl) loadEl.style.display = 'flex';
        if (out) out.value = 'AI 글쓰기 중…';
        if (insBtn) insBtn.disabled = true;
        _setStatus('');
        try {
            const result = await _callGemini(prompt, text, model);
            _lastResult = result;
            if (out) out.value = result;
            if (insBtn) insBtn.disabled = false;
            _setStatus(`✅ 완료 · ${result.length}자`, 'ok');
        } catch (e) {
            _lastResult = '';
            if (out) out.value = `⚠ ${e.message}`;
            _setStatus('❌ 오류', 'err');
        } finally {
            _busy = false;
            if (loadEl) loadEl.style.display = 'none';
        }
    }

    async function translate() {
        if (_busy) return;
        const inp = $('tr-input'), out = $('tr-output');
        const loadEl = $('tr-loading'), insBtn = $('tr-insert-btn');
        const srcSel = $('tr-src-lang'), tgtSel = $('tr-tgt-lang');
        const text = inp ? inp.value.trim() : '';
        if (!text) { _setStatus('⚠ 번역할 텍스트를 입력해 주세요.', 'warn'); return; }
        if (!srcSel || !tgtSel) { _setStatus('⚠ 언어 선택 요소를 찾을 수 없습니다.', 'err'); return; }
        const sl = srcSel.value, tl = tgtSel.value;
        if (sl === tl) { _setStatus('⚠ 원본/번역 언어가 같습니다.', 'warn'); return; }

        _busy = true;
        if (loadEl) loadEl.style.display = 'flex';
        if (out) out.value = '번역 중…';
        if (insBtn) insBtn.disabled = true;
        _setStatus('');

        const t0 = Date.now();
        try {
            const result = await _doTranslate(text, sl, tl);
            _lastResult = result;
            if (out) out.value = result;
            if (insBtn) insBtn.disabled = false;
            _setStatus(`✅ 완료 (${((Date.now()-t0)/1000).toFixed(1)}s) · ${result.length}자`, 'ok');
        } catch (e) {
            _lastResult = '';
            const msg = e.message || String(e);
            const hint = msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('CORS')
                ? '네트워크 연결 또는 CORS를 확인하세요. (로컬 파일 실행 시 브라우저가 차단할 수 있습니다)'
                : '네트워크 상태 또는 언어 조합을 확인하세요.';
            if (out) out.value = `⚠ 번역 실패: ${msg}\n${hint}`;
            _setStatus('❌ 오류', 'err');
        } finally {
            _busy = false;
            if (loadEl) loadEl.style.display = 'none';
        }
    }

    function swapLang() {
        const src = $('tr-src-lang'), tgt = $('tr-tgt-lang');
        if (!src || !tgt) return;
        [src.value, tgt.value] = [tgt.value, src.value];
        const inp = $('tr-input'), out = $('tr-output');
        if (inp && _lastResult) {
            const prev = inp.value;
            inp.value = _lastResult;
            if (out) out.value = prev;
            _lastResult = prev;
            _updateCount();
        }
    }

    function insertResult() {
        const out = $('tr-output');
        const txt = out ? out.value.trim() : _lastResult;
        if (!txt) return;
        const ed = $('editor');
        if (!ed) return;
        const mode = ($('tr-insert-mode') || {}).value || 'replace';
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        const orig = ed.value.substring(s, e2);
        const insertTxt = mode === 'replace' ? txt
                  : mode === 'after'   ? orig + txt
                  : mode === 'newline' ? (orig ? orig + '\n' : '') + '\n' + txt
                  : orig + '\n\n> ' + txt;  /* both */
        ed.setRangeText(insertTxt, s, e2, 'end');
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined') App.render();
        const insertMsg = $('tr-insert-msg');
        if (insertMsg) { insertMsg.textContent = '✔ 에디터에 삽입되었습니다.'; insertMsg.style.display = ''; insertMsg.style.color = 'var(--ok)'; }
        _setStatus('');
        setTimeout(() => { if (insertMsg) { insertMsg.textContent = ''; insertMsg.style.display = 'none'; } hide(); }, 500);
    }

    function copyResult() {
        const out = $('tr-output');
        const txt = out ? out.value.trim() : _lastResult;
        if (!txt) return;
        navigator.clipboard.writeText(txt)
            .then(() => _setStatus('📋 복사되었습니다.', 'ok'))
            .catch(() => {
                const ta = document.createElement('textarea');
                ta.value = txt;
                document.body.appendChild(ta);
                ta.select(); document.execCommand('copy');
                document.body.removeChild(ta);
                _setStatus('📋 복사 완료', 'ok');
            });
    }

    function openBrowser() {
        const inp = $('tr-input');
        const text = inp ? inp.value.trim() : '';
        const sl = $('tr-src-lang').value, tl = $('tr-tgt-lang').value;
        window.open(
            `https://translate.google.com/?sl=${sl}&tl=${tl}&text=${encodeURIComponent(text)}&op=translate`,
            '_blank'
        );
    }

    function clearInput() {
        const inp = $('tr-input');
        if (inp) { inp.value = ''; _updateCount(); }
        _lastResult = '';
        const out = $('tr-output');
        if (out) out.value = '';
        const insBtn = $('tr-insert-btn');
        if (insBtn) insBtn.disabled = true;
        _setStatus('');
    }

    function onInput() { _updateCount(); }

    function onOutputInput() {
        const out = $('tr-output'), insBtn = $('tr-insert-btn');
        if (out) _lastResult = out.value;
        if (insBtn) insBtn.disabled = !(out && out.value.trim());
    }

    /* Ctrl+Enter → 번역/AI */
    document.addEventListener('DOMContentLoaded', () => {
        AppLock.init();
        const inp = $('tr-input');
        if (inp) {
            inp.addEventListener('keydown', e => {
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                    e.preventDefault();
                    if (_currentTab === 'ai-translate') aiTranslate();
                    else if (_currentTab === 'ai-write') aiWrite();
                    else translate();
                }
            });
        }
    });

    return { show, hide, toggleFullscreen, translate, swapLang, insertResult, copyResult, openBrowser, openOriginalAndTranslationInNewWindow, openTranslationInNewWindow, translateText, openBrowserWithText, openTranslationInNewWindowWithText, openOriginalAndTranslationInNewWindowWithText, clearInput, onInput, onOutputInput, switchTab, aiTranslate, aiWrite };
})();

/* ═══════════════════════════════════════════════════════════
   CHARMAP — 문자표 (Windows 문자표 스타일 특수문자 삽입)
═══════════════════════════════════════════════════════════ */
const CharMap = (() => {
    let _selected = null;
    let _currentCat = 0;

    const CATS = [
        { name: '자주 사용', chars: [
            { ch: '©', name: '저작권', code: 'U+00A9' },
            { ch: '®', name: '등록상표', code: 'U+00AE' },
            { ch: '™', name: '상표', code: 'U+2122' },
            { ch: '°', name: '도', code: 'U+00B0' },
            { ch: '±', name: '플러스마이너스', code: 'U+00B1' },
            { ch: '×', name: '곱하기', code: 'U+00D7' },
            { ch: '÷', name: '나누기', code: 'U+00F7' },
            { ch: '≈', name: '근사값', code: 'U+2248' },
            { ch: '≠', name: '같지않음', code: 'U+2260' },
            { ch: '≤', name: '이하', code: 'U+2264' },
            { ch: '≥', name: '이상', code: 'U+2265' },
            { ch: '∞', name: '무한대', code: 'U+221E' },
            { ch: '√', name: '루트', code: 'U+221A' },
            { ch: '∑', name: '시그마', code: 'U+2211' },
            { ch: '∏', name: '파이적분', code: 'U+220F' },
            { ch: '∫', name: '적분', code: 'U+222B' },
            { ch: '→', name: '오른쪽화살표', code: 'U+2192' },
            { ch: '←', name: '왼쪽화살표', code: 'U+2190' },
            { ch: '↑', name: '위쪽화살표', code: 'U+2191' },
            { ch: '↓', name: '아래화살표', code: 'U+2193' },
            { ch: '•', name: '점(불릿)', code: 'U+2022' },
            { ch: '…', name: '말줄임표', code: 'U+2026' },
            { ch: '「', name: '왼낫표', code: 'U+300C' },
            { ch: '」', name: '오른낫표', code: 'U+300D' },
            { ch: '『', name: '이중왼낫표', code: 'U+300E' },
            { ch: '』', name: '이중오른낫표', code: 'U+300F' },
            { ch: '【', name: '굵은왼괄호', code: 'U+3010' },
            { ch: '】', name: '굵은오른괄호', code: 'U+3011' },
            { ch: '§', name: '섹션기호', code: 'U+00A7' },
            { ch: '¶', name: '단락기호', code: 'U+00B6' },
            { ch: '†', name: '단검표', code: 'U+2020' },
            { ch: '‡', name: '이중단검표', code: 'U+2021' },
        ]},
        { name: '화살표', chars: [
            { ch: '→', name: '오른쪽', code: 'U+2192' }, { ch: '←', name: '왼쪽', code: 'U+2190' },
            { ch: '↑', name: '위쪽', code: 'U+2191' }, { ch: '↓', name: '아래쪽', code: 'U+2193' },
            { ch: '↔', name: '좌우', code: 'U+2194' }, { ch: '↕', name: '상하', code: 'U+2195' },
            { ch: '↖', name: '왼위', code: 'U+2196' }, { ch: '↗', name: '오른위', code: 'U+2197' },
            { ch: '↘', name: '오른아래', code: 'U+2198' }, { ch: '↙', name: '왼아래', code: 'U+2199' },
            { ch: '⇒', name: '오른쪽이중', code: 'U+21D2' }, { ch: '⇐', name: '왼쪽이중', code: 'U+21D0' },
            { ch: '⇑', name: '위쪽이중', code: 'U+21D1' }, { ch: '⇓', name: '아래이중', code: 'U+21D3' },
            { ch: '⇔', name: '좌우이중', code: 'U+21D4' }, { ch: '⇕', name: '상하이중', code: 'U+21D5' },
            { ch: '➡', name: '채운오른쪽', code: 'U+27A1' }, { ch: '⬅', name: '채운왼쪽', code: 'U+2B05' },
            { ch: '⬆', name: '채운위쪽', code: 'U+2B06' }, { ch: '⬇', name: '채운아래', code: 'U+2B07' },
            { ch: '↩', name: '되돌아', code: 'U+21A9' }, { ch: '↪', name: '앞으로', code: 'U+21AA' },
            { ch: '↻', name: '시계방향', code: 'U+21BB' }, { ch: '↺', name: '반시계', code: 'U+21BA' },
        ]},
        { name: '수학 기호', chars: [
            { ch: '±', name: '플러스마이너스', code: 'U+00B1' }, { ch: '∓', name: '마이너스플러스', code: 'U+2213' },
            { ch: '×', name: '곱하기', code: 'U+00D7' }, { ch: '÷', name: '나누기', code: 'U+00F7' },
            { ch: '√', name: '제곱근', code: 'U+221A' }, { ch: '∛', name: '세제곱근', code: 'U+221B' },
            { ch: '∜', name: '네제곱근', code: 'U+221C' }, { ch: '∞', name: '무한대', code: 'U+221E' },
            { ch: '≈', name: '근사', code: 'U+2248' }, { ch: '≠', name: '같지않음', code: 'U+2260' },
            { ch: '≡', name: '항등', code: 'U+2261' }, { ch: '≤', name: '이하', code: 'U+2264' },
            { ch: '≥', name: '이상', code: 'U+2265' }, { ch: '≪', name: '훨씬작음', code: 'U+226A' },
            { ch: '≫', name: '훨씬큼', code: 'U+226B' }, { ch: '∑', name: '합계', code: 'U+2211' },
            { ch: '∏', name: '곱', code: 'U+220F' }, { ch: '∫', name: '적분', code: 'U+222B' },
            { ch: '∬', name: '이중적분', code: 'U+222C' }, { ch: '∂', name: '편미분', code: 'U+2202' },
            { ch: '∇', name: '나블라', code: 'U+2207' }, { ch: '∈', name: '원소', code: 'U+2208' },
            { ch: '∉', name: '비원소', code: 'U+2209' }, { ch: '⊂', name: '부분집합', code: 'U+2282' },
            { ch: '⊃', name: '초집합', code: 'U+2283' }, { ch: '∪', name: '합집합', code: 'U+222A' },
            { ch: '∩', name: '교집합', code: 'U+2229' }, { ch: '∅', name: '공집합', code: 'U+2205' },
            { ch: '∝', name: '비례', code: 'U+221D' }, { ch: '⊕', name: 'XOR', code: 'U+2295' },
            { ch: 'α', name: '알파', code: 'U+03B1' }, { ch: 'β', name: '베타', code: 'U+03B2' },
            { ch: 'γ', name: '감마', code: 'U+03B3' }, { ch: 'δ', name: '델타', code: 'U+03B4' },
            { ch: 'ε', name: '엡실론', code: 'U+03B5' }, { ch: 'θ', name: '세타', code: 'U+03B8' },
            { ch: 'λ', name: '람다', code: 'U+03BB' }, { ch: 'μ', name: '뮤', code: 'U+03BC' },
            { ch: 'π', name: '파이', code: 'U+03C0' }, { ch: 'σ', name: '시그마(소)', code: 'U+03C3' },
            { ch: 'φ', name: '파이(소)', code: 'U+03C6' }, { ch: 'ω', name: '오메가(소)', code: 'U+03C9' },
            { ch: 'Γ', name: '감마(대)', code: 'U+0393' }, { ch: 'Δ', name: '델타(대)', code: 'U+0394' },
            { ch: 'Σ', name: '시그마(대)', code: 'U+03A3' }, { ch: 'Ω', name: '오메가(대)', code: 'U+03A9' },
        ]},
        { name: '도형·기호', chars: [
            { ch: '■', name: '채운사각', code: 'U+25A0' }, { ch: '□', name: '빈사각', code: 'U+25A1' },
            { ch: '▪', name: '작은채운사각', code: 'U+25AA' }, { ch: '▫', name: '작은빈사각', code: 'U+25AB' },
            { ch: '▲', name: '위삼각', code: 'U+25B2' }, { ch: '▼', name: '아래삼각', code: 'U+25BC' },
            { ch: '◀', name: '왼삼각', code: 'U+25C0' }, { ch: '▶', name: '오른삼각', code: 'U+25B6' },
            { ch: '●', name: '채운원', code: 'U+25CF' }, { ch: '○', name: '빈원', code: 'U+25CB' },
            { ch: '◉', name: '과녁원', code: 'U+25C9' }, { ch: '◎', name: '이중원', code: 'U+25CE' },
            { ch: '★', name: '채운별', code: 'U+2605' }, { ch: '☆', name: '빈별', code: 'U+2606' },
            { ch: '◆', name: '채운다이아', code: 'U+25C6' }, { ch: '◇', name: '빈다이아', code: 'U+25C7' },
            { ch: '♦', name: '다이아카드', code: 'U+2666' }, { ch: '♠', name: '스페이드', code: 'U+2660' },
            { ch: '♥', name: '하트', code: 'U+2665' }, { ch: '♣', name: '클럽', code: 'U+2663' },
            { ch: '✓', name: '체크', code: 'U+2713' }, { ch: '✔', name: '굵은체크', code: 'U+2714' },
            { ch: '✗', name: 'X표시', code: 'U+2717' }, { ch: '✘', name: '굵은X', code: 'U+2718' },
            { ch: '⊙', name: '점원', code: 'U+2299' }, { ch: '⊚', name: '이중점원', code: 'U+229A' },
            { ch: '⊞', name: '더하기상자', code: 'U+229E' }, { ch: '⊟', name: '빼기상자', code: 'U+229F' },
        ]},
        { name: '구두점·기타', chars: [
            { ch: '—', name: '줄표(em)', code: 'U+2014' }, { ch: '–', name: '반줄표(en)', code: 'U+2013' },
            { ch: '…', name: '말줄임표', code: 'U+2026' }, { ch: '·', name: '가운뎃점', code: 'U+00B7' },
            { ch: '\u2010', name: '하이픈', code: 'U+2010' }, { ch: '\u201C', name: '왼큰따옴표', code: 'U+201C' },
            { ch: '\u201D', name: '오른큰따옴표', code: 'U+201D' }, { ch: '\u2018', name: '왼작은따옴표', code: 'U+2018' },
            { ch: '\u2019', name: '오른작은따옴표', code: 'U+2019' }, { ch: '\u00AB', name: '이중꺾쇠왼', code: 'U+00AB' },
            { ch: '\u2019', name: '오른작은따옴표', code: 'U+2019' }, { ch: '\u00AB', name: '이중꺾쇠왼', code: 'U+00AB' },
            { ch: '»', name: '이중꺾쇠오른', code: 'U+00BB' }, { ch: '‹', name: '꺾쇠왼', code: 'U+2039' },
            { ch: '›', name: '꺾쇠오른', code: 'U+203A' }, { ch: '§', name: '섹션', code: 'U+00A7' },
            { ch: '¶', name: '단락', code: 'U+00B6' }, { ch: '†', name: '단검표', code: 'U+2020' },
            { ch: '‡', name: '이중단검', code: 'U+2021' }, { ch: '※', name: '참고', code: 'U+203B' },
            { ch: '′', name: '프라임(분)', code: 'U+2032' }, { ch: '″', name: '이중프라임(초)', code: 'U+2033' },
            { ch: '°', name: '도', code: 'U+00B0' }, { ch: '℃', name: '섭씨', code: 'U+2103' },
            { ch: '℉', name: '화씨', code: 'U+2109' }, { ch: '㎡', name: '제곱미터', code: 'U+33A1' },
            { ch: '㎞', name: '킬로미터', code: 'U+339E' }, { ch: '㎝', name: '센티미터', code: 'U+339D' },
            { ch: '㎜', name: '밀리미터', code: 'U+339C' }, { ch: '㎏', name: '킬로그램', code: 'U+338F' },
        ]},
        { name: '통화·특수', chars: [
            { ch: '₩', name: '원', code: 'U+20A9' }, { ch: '$', name: '달러', code: 'U+0024' },
            { ch: '€', name: '유로', code: 'U+20AC' }, { ch: '£', name: '파운드', code: 'U+00A3' },
            { ch: '¥', name: '엔', code: 'U+00A5' }, { ch: '¢', name: '센트', code: 'U+00A2' },
            { ch: '₿', name: '비트코인', code: 'U+20BF' }, { ch: '฿', name: '바트', code: 'U+0E3F' },
            { ch: '©', name: '저작권', code: 'U+00A9' }, { ch: '®', name: '등록상표', code: 'U+00AE' },
            { ch: '™', name: '상표', code: 'U+2122' }, { ch: '℠', name: '서비스마크', code: 'U+2120' },
            { ch: '☎', name: '전화', code: 'U+260E' }, { ch: '✉', name: '이메일', code: 'U+2709' },
            { ch: '♻', name: '재활용', code: 'U+267B' }, { ch: '⚠', name: '경고', code: 'U+26A0' },
            { ch: '☐', name: '빈체크박스', code: 'U+2610' }, { ch: '☑', name: '체크박스', code: 'U+2611' },
            { ch: '☒', name: 'X체크박스', code: 'U+2612' }, { ch: '♂', name: '남성', code: 'U+2642' },
            { ch: '♀', name: '여성', code: 'U+2640' }, { ch: '⚡', name: '번개', code: 'U+26A1' },
        ]},
        { name: '학술·연구', chars: [
            { ch: 'p', name: 'p값', code: 'U+0070' }, { ch: 'F', name: 'F통계량', code: 'U+0046' },
            { ch: 't', name: 't통계량', code: 'U+0074' }, { ch: 'χ', name: '카이(소)', code: 'U+03C7' },
            { ch: 'χ²', name: '카이제곱', code: 'U+03C7 U+00B2' }, { ch: 'η²', name: '에타제곱', code: 'U+03B7 U+00B2' },
            { ch: 'ω²', name: '오메가제곱', code: 'U+03C9 U+00B2' }, { ch: 'β', name: '베타계수', code: 'U+03B2' },
            { ch: 'r', name: '상관계수', code: 'U+0072' }, { ch: 'R²', name: 'R제곱', code: 'U+0052 U+00B2' },
            { ch: 'M', name: '평균', code: 'U+004D' }, { ch: 'SD', name: '표준편차', code: '' },
            { ch: 'SE', name: '표준오차', code: '' }, { ch: 'CI', name: '신뢰구간', code: '' },
            { ch: '¹', name: '위첨자1', code: 'U+00B9' }, { ch: '²', name: '위첨자2', code: 'U+00B2' },
            { ch: '³', name: '위첨자3', code: 'U+00B3' }, { ch: '⁴', name: '위첨자4', code: 'U+2074' },
            { ch: '₁', name: '아래첨자1', code: 'U+2081' }, { ch: '₂', name: '아래첨자2', code: 'U+2082' },
            { ch: '₃', name: '아래첨자3', code: 'U+2083' }, { ch: '₄', name: '아래첨자4', code: 'U+2084' },
            { ch: 'Å', name: '옹스트롬', code: 'U+00C5' }, { ch: '‰', name: '퍼밀', code: 'U+2030' },
        ]},
    ];

    let _allChars = [];
    CATS.forEach(cat => { _allChars = _allChars.concat(cat.chars.map(c => ({...c, cat: cat.name}))); });

    function _buildCatTabs() {
        const el2 = document.getElementById('cm-cat-tabs');
        if (!el2) return;
        el2.innerHTML = '';
        CATS.forEach((cat, i) => {
            const btn = document.createElement('button');
            btn.className = 'btn btn-g btn-sm' + (i === _currentCat ? ' active' : '');
            btn.textContent = cat.name;
            btn.style.cssText = 'font-size:10px;padding:2px 8px;' + (i === _currentCat ? 'background:var(--ac);color:#fff;border-color:var(--ac)' : '');
            btn.onclick = () => { _currentCat = i; document.getElementById('cm-search').value = ''; _buildCatTabs(); _renderChars(CATS[i].chars); };
            el2.appendChild(btn);
        });
    }

    function _renderChars(chars) {
        const grid = document.getElementById('cm-grid');
        if (!grid) return;
        grid.innerHTML = '';
        chars.forEach(item => {
            const div = document.createElement('div');
            div.className = 'cm-char-cell';
            div.textContent = item.ch;
            div.title = item.name + ' ' + item.code;
            div.onclick = () => _select(item);
            div.ondblclick = () => { _select(item); insert(); };
            grid.appendChild(div);
        });
    }

    function _select(item) {
        _selected = item;
        const prev = document.getElementById('cm-preview');
        const name = document.getElementById('cm-name');
        const code = document.getElementById('cm-code');
        const btn  = document.getElementById('cm-insert-btn');
        if (prev) prev.textContent = item.ch;
        if (name) name.textContent = item.name;
        if (code) code.textContent = item.code;
        if (btn)  btn.disabled = false;
        /* 선택 표시 */
        document.querySelectorAll('.cm-char-cell.sel').forEach(c => c.classList.remove('sel'));
        event.currentTarget && event.currentTarget.classList.add('sel');
    }

    function search(q) {
        if (!q.trim()) { _renderChars(CATS[_currentCat].chars); return; }
        const kw = q.trim().toLowerCase();
        const res = _allChars.filter(c =>
            c.name.toLowerCase().includes(kw) ||
            c.ch.includes(q) ||
            (c.code && c.code.toLowerCase().includes(kw))
        );
        _renderChars(res);
    }

    function insert() {
        if (!_selected) return;
        const ed = document.getElementById('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        ed.setRangeText(_selected.ch, s, e2, 'end');
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined') App.render();
        hide();
    }

    function show() {
        const modal = document.getElementById('charmap-modal');
        if (!modal) return;
        modal.classList.add('vis');
        _buildCatTabs();
        _renderChars(CATS[_currentCat].chars);
        setTimeout(() => { const s = document.getElementById('cm-search'); if(s) s.focus(); }, 50);
    }

    function hide() {
        const modal = document.getElementById('charmap-modal');
        if (modal) modal.classList.remove('vis');
    }

    return { show, hide, search, insert };
})();

/* ═══════════════════════════════════════════════════════
   SIDEBAR RESIZER — 사이드바 너비 드래그 조절
   ═══════════════════════════════════════════════════════ */
(function () {
    const MIN_W = 160;
    const MAX_W = 520;
    const DEFAULT_W = 240;
    const STORAGE_KEY = 'md_sidebar_width';

    let _dragging = false;
    let _startX = 0;
    let _startW = 0;

    function getEl() { return document.getElementById('sidebar-resizer'); }

    function getSidebarW() {
        const style = getComputedStyle(document.documentElement);
        const val = style.getPropertyValue('--sw').trim();
        return parseInt(val) || DEFAULT_W;
    }

    function setWidth(w) {
        w = Math.max(MIN_W, Math.min(MAX_W, w));
        document.documentElement.style.setProperty('--sw', w + 'px');
        positionResizer(w);
        try { localStorage.setItem(STORAGE_KEY, w); } catch(e) {}
    }

    function positionResizer(w) {
        const el = getEl();
        if (!el) return;
        const half = el.offsetWidth / 2;
        el.style.left = (w - half) + 'px';
        /* 앱 UI 영역(사이드바·메인 행) 안에서만 높이/위치 적용 — 모바일에서 화면 전체 터치 방지 */
        const main = document.getElementById('main');
        if (main) {
            const rect = main.getBoundingClientRect();
            el.style.top = rect.top + 'px';
            el.style.height = rect.height + 'px';
        }
    }

    function onMouseDown(e) {
        if (e.button !== 0) return;
        _dragging = true;
        _startX = e.clientX;
        _startW = getSidebarW();
        getEl().classList.add('dragging');
        document.body.classList.add('resizing');
        e.preventDefault();
    }

    function onTouchStart(e) {
        if (e.touches.length !== 1) return;
        _dragging = true;
        _startX = e.touches[0].clientX;
        _startW = getSidebarW();
        getEl().classList.add('dragging');
        document.body.classList.add('resizing');
    }

    function onTouchMove(e) {
        if (!_dragging) return;
        if (e.touches.length !== 1) return;
        e.preventDefault();
        const dx = e.touches[0].clientX - _startX;
        setWidth(_startW + dx);
    }

    function onTouchEnd() {
        if (!_dragging) return;
        _dragging = false;
        getEl().classList.remove('dragging');
        document.body.classList.remove('resizing');
    }

    function onMouseMove(e) {
        if (!_dragging) return;
        const dx = e.clientX - _startX;
        setWidth(_startW + dx);
    }

    function onMouseUp() {
        if (!_dragging) return;
        _dragging = false;
        getEl().classList.remove('dragging');
        document.body.classList.remove('resizing');
    }

    function init() {
        try {
            const saved = parseInt(localStorage.getItem(STORAGE_KEY));
            if (saved && saved >= MIN_W && saved <= MAX_W) {
                document.documentElement.style.setProperty('--sw', saved + 'px');
            }
        } catch(e) {}

        const el = getEl();
        if (!el) return;

        positionResizer(getSidebarW());
        el.addEventListener('mousedown', onMouseDown);
        el.addEventListener('touchstart', onTouchStart, { passive: true });
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
        document.addEventListener('touchmove', onTouchMove, { passive: false });
        document.addEventListener('touchend', onTouchEnd);
        document.addEventListener('touchcancel', onTouchEnd);

        el.addEventListener('dblclick', () => setWidth(DEFAULT_W));

        const appEl = document.getElementById('app');
        if (appEl) {
            new MutationObserver(() => positionResizer(getSidebarW()))
                .observe(appEl, { attributes: true, attributeFilter: ['class'] });
        }
        window.addEventListener('resize', () => positionResizer(getSidebarW()));
        window.addEventListener('load', () => positionResizer(getSidebarW()));
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();

/* ═══════════════════════════════════════════════════════════
   ScrollSync — 에디터 ↔ 미리보기 스크롤 동기화
   에디터 스크롤 비율을 preview-container에 반영
═══════════════════════════════════════════════════════════ */
/* ScrollSync는 SS 모듈(헤딩 기반)이 담당 — 별도 구현 불필요 */
const ScrollSync = (() => {
    function onEditor() { /* SS.init()에서 이미 에디터 scroll 이벤트 처리 */ }
    function onPreview() { /* SS.init()에서 이미 미리보기 scroll 이벤트 처리 */ }
    function init() { /* SS.init()에 위임 */ }
    return { onEditor, onPreview, init };
})();


/* ═══════════════════════════════════════════════════════════
   PVShare — md-viewer 공유 관리 시스템
   
   구조:
     [PV 패널 🔗 공유 버튼] → openModal() → md-viewer 관리 창
     [GH 파일행 📤 버튼]    → quickPush() → md-viewer에 바로 push

   md-viewer 관리 창:
     ┌────────────────────────────────────────────┐
     │ ⚙설정  🔄새로고침  ⬇Pull  ⬆Push  📋Clone  │
     │ ─────────────────────────────────────────  │
     │ 📁 폴더                                    │
     │   📄 파일.md    [🔗 링크복사] [🗑]         │
     │   📄 파일2.md   [🔗 링크복사] [🗑]         │
     │ [＋ 새파일] [📁 새폴더]                    │
     └────────────────────────────────────────────┘
═══════════════════════════════════════════════════════════ */
const PVShare = (() => {
    const CFG_KEY     = 'mdpro_viewer_cfg';
    const BTN_ID      = 'pv-share-btn';
    const VIEWER_URL  = 'https://shoutjoy.github.io/md-viewer/view.html';
    const LF_IDB_NAME = 'pvshare_local_db';
    const LF_FOLDER_KEY = 'pvshare_local_folder'; // localStorage: 폴더명 기억

    /* ── 설정 ── */
    function _loadCfg() {
        try { return JSON.parse(localStorage.getItem(CFG_KEY) || 'null'); }
        catch(e) { return null; }
    }
    function _saveCfg(c) {
        try { localStorage.setItem(CFG_KEY, JSON.stringify(c)); } catch(e) {}
    }

    /* ══════════════════════════════════════════════════
       PVShare 전용 로컬 폴더 관리 (FM과 완전 독립)
    ══════════════════════════════════════════════════ */
    let _pvDirHandle  = null;   // FileSystemDirectoryHandle
    let _pvFolderName = '';     // 폴더 표시명
    let _pvFiles      = [];     // { name, path, folder, content, size }

    /* ── 로컬 폴더명 localStorage 저장/복원 ── */
    function _pvSaveFolderName(name) {
        try { localStorage.setItem(LF_FOLDER_KEY, name || ''); } catch(e) {}
    }
    function _pvLoadFolderName() {
        try { return localStorage.getItem(LF_FOLDER_KEY) || ''; } catch(e) { return ''; }
    }

    /* ── 디렉터리 재귀 스캔 ── */
    async function _pvScanDir(handle, basePath, depth, out) {
        if (depth > 6) return;
        for await (const [entryName, entry] of handle.entries()) {
            if (entryName.startsWith('.')) continue;
            const relPath = basePath ? basePath + '/' + entryName : entryName;
            if (entry.kind === 'directory') {
                /* 서브폴더 스캔 → 결과 없으면 빈 폴더 항목 추가 */
                const lenBefore = out.length;
                await _pvScanDir(entry, relPath, depth + 1, out);
                if (out.length === lenBefore) {
                    /* .gitkeep 전용이거나 완전히 빈 폴더 */
                    out.push({ name: entryName, path: relPath,
                                folder: basePath || '', content: null,
                                size: 0, isDir: true });
                }
            } else {
                /* 텍스트 기반 파일은 content 바로 로드 */
                let content = null;
                let fileSize = 0;
                if (entryName.match(/\.(md|txt|markdown|html|json|yaml|yml|csv)$/i)) {
                    try {
                        const file = await entry.getFile();
                        fileSize = file.size;
                        content = await file.text();
                    } catch(e) { content = ''; }
                } else {
                    try {
                        const file = await entry.getFile();
                        fileSize = file.size;
                    } catch(e) {}
                }
                out.push({
                    name: entryName,
                    path: relPath,
                    folder: basePath || '',
                    content,
                    size: fileSize,
                    isDir: false,
                });
            }
        }
    }

    /* ── 폴더 선택 (PVShare 전용) ── */
    async function _pvSelectFolder() {
        if (!window.showDirectoryPicker) {
            App._toast('⚠ 이 브라우저는 로컬 폴더 접근을 지원하지 않습니다');
            return false;
        }
        try {
            const h = await window.showDirectoryPicker({ mode: 'readwrite' });
            _pvDirHandle  = h;
            _pvFolderName = h.name;
            _pvSaveFolderName(h.name);
            App._toast('⟳ 공개노트 폴더 스캔 중…');
            await _pvSync();
            return true;
        } catch(e) {
            if (e.name !== 'AbortError') App._toast('⚠ 폴더 선택 실패: ' + e.message);
            return false;
        }
    }

    /* ── 핸들에서 파일 목록 동기화 ── */
    async function _pvSync() {
        if (!_pvDirHandle) return;
        const fresh = [];
        await _pvScanDir(_pvDirHandle, '', 0, fresh);
        _pvFiles = fresh;
        App._toast('✅ 공개노트 폴더 동기화 완료: ' + _pvFiles.length + '개');
    }

    /* ── 권한 재요청 (재시작 후 핸들 복원 시) ── */
    async function _pvRequestPermission() {
        if (!_pvDirHandle) return false;
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            return perm === 'granted';
        } catch(e) { return false; }
    }

    /* ── GitHub API (viewer 저장소) ── */
    async function _api(path, opts = {}) {
        const token = GH.cfg?.token;
        if (!token) throw new Error('GitHub 토큰이 없습니다 (GH 설정 확인)');
        const cfg  = _loadCfg();
        const repo = cfg?.repo || 'shoutjoy/md-viewer';
        const base = `https://api.github.com/repos/${repo}`;
        const url  = path.startsWith('http') ? path : base + path;
        const res  = await fetch(url, {
            ...opts,
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'X-GitHub-Api-Version': '2022-11-28',
                ...(opts.headers || {}),
            },
        });
        if (res.status === 204) return {};
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(`GitHub ${res.status}: ${err.message || res.statusText}`);
        }
        return res.json();
    }

    /* ── 파일 목록 조회 ── */
    async function _listPath(path = '') {
        return _api(`/contents/${path ? encodeURIComponent(path) : ''}`);
    }

    /* ── 파일 내용 조회 ── */
    async function _getFile(path) {
        return _api(`/contents/${encodeURIComponent(path)}`);
    }

    /* ── 파일 쓰기 (PUT) ── */
    async function _putFile(path, content, message, sha = null) {
        const body = {
            message,
            content: btoa(unescape(encodeURIComponent(content))),
            branch: _loadCfg()?.branch || 'main',
        };
        if (sha) body.sha = sha;
        return _api(`/contents/${encodeURIComponent(path)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
    }

    /* ── 파일 삭제 ── */
    async function _deleteFile(path, sha, message) {
        return _api(`/contents/${encodeURIComponent(path)}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message,
                sha,
                branch: _loadCfg()?.branch || 'main',
            }),
        });
    }

    /* ── 브랜치 HEAD SHA ── */
    async function _getHeadSHA(branch = 'main') {
        const ref = await _api(`/git/ref/heads/${branch}`);
        return ref.object.sha;
    }

    /* ── 폴더 내 파일 전체 삭제 (Trees API) ── */
    async function _deleteFolderContents(folderPath, allItems) {
        const cfg    = _loadCfg();
        const branch = cfg?.branch || 'main';
        const repo   = cfg?.repo || 'shoutjoy/md-viewer';
        const token  = GH.cfg?.token;

        const headSHA  = await _getHeadSHA(branch);
        const commitRes = await fetch(`https://api.github.com/repos/${repo}/git/commits/${headSHA}`, {
            headers: { 'Authorization': `token ${token}`, 'Accept': 'application/vnd.github.v3+json' }
        }).then(r => r.json());
        const baseTreeSHA = commitRes.tree.sha;

        const delItems = allItems
            .filter(f => f.type === 'blob' && f.path.startsWith(folderPath + '/'))
            .map(f => ({ path: f.path, mode: '100644', type: 'blob', sha: null }));

        if (!delItems.length) return;

        const treeRes = await fetch(`https://api.github.com/repos/${repo}/git/trees`, {
            method: 'POST',
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ base_tree: baseTreeSHA, tree: delItems }),
        }).then(r => r.json());

        const newCommit = await fetch(`https://api.github.com/repos/${repo}/git/commits`, {
            method: 'POST',
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                message: `Delete folder: ${folderPath}`,
                tree: treeRes.sha,
                parents: [headSHA],
            }),
        }).then(r => r.json());

        await fetch(`https://api.github.com/repos/${repo}/git/refs/heads/${branch}`, {
            method: 'PATCH',
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ sha: newCommit.sha }),
        });
    }

    /* ── 링크 생성 ── */
    function _makeLink(filePath) {
        const cfg  = _loadCfg();
        const repo = cfg?.repo || 'shoutjoy/md-viewer';
        const branch = cfg?.branch || 'main';
        /* docs/ 안의 파일이면 ?doc= 방식 (정적 fetch) */
        if (filePath.startsWith('docs/')) {
            const docName = filePath.replace(/^docs\//, '').replace(/\.md$/i, '');
            return `${VIEWER_URL}?doc=${encodeURIComponent(docName)}`;
        }
        /* 그 외는 repo+path 방식 */
        return `${VIEWER_URL}?repo=${repo}&branch=${branch}&path=${encodeURIComponent(filePath)}`;
    }

    /* ── 버튼 표시/숨김 ── */
    function refresh() {
        const btn = document.getElementById(BTN_ID);
        if (!btn) return;
        const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
        btn.style.display = tab ? '' : 'none';
    }

    /* ══════════════════════════════════════════════════
       메인 모달 열기
    ══════════════════════════════════════════════════ */
    function openModal() {
        const existing = document.getElementById('pvshare-overlay');
        if (existing) { existing.remove(); return; }

        const vcfg = _loadCfg();

        const ov = document.createElement('div');
        ov.id = 'pvshare-overlay';
        ov.style.cssText = [
            'position:fixed;inset:0;z-index:9100',
            'background:rgba(0,0,0,.65)',
            'display:flex;align-items:center;justify-content:center;padding:16px',
        ].join(';');

        ov.innerHTML = `
        <div id="pvs-box" style="
            background:var(--bg2);border:1px solid var(--bd);border-radius:14px;
            width:540px;max-width:95vw;max-height:88vh;
            display:flex;flex-direction:column;
            box-shadow:0 16px 60px rgba(0,0,0,.7);overflow:hidden">

          <!-- 헤더 -->
          <div style="display:flex;align-items:center;gap:8px;
              padding:12px 16px;border-bottom:1px solid var(--bd);
              background:var(--bg3);flex-shrink:0">
            <span style="font-size:13px;font-weight:700;color:#58c8f8">📤 공개노트 설정</span>
            <a id="pvs-repo-name" href="${vcfg ? `https://github.com/${vcfg.repo}` : '#'}"
                target="_blank" rel="noopener noreferrer"
                title="GitHub 저장소 열기"
                style="font-size:11px;color:#a090ff;flex:1;
                    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
                    text-decoration:none;cursor:pointer;
                    padding:2px 6px;border-radius:4px;
                    background:rgba(160,144,255,.1);
                    border:1px solid rgba(160,144,255,.2);
                    transition:background .15s"
                onmouseover="this.style.background='rgba(160,144,255,.22)'"
                onmouseout="this.style.background='rgba(160,144,255,.1)'">
              ${vcfg ? vcfg.repo : '저장소 미설정'} ↗</a>
            <button onclick="PVShare._showSettings()" title="저장소 설정"
                style="background:rgba(255,255,255,.08);border:1px solid var(--bd);
                    border-radius:5px;color:var(--tx2);font-size:11px;
                    padding:3px 9px;cursor:pointer">⚙ 설정</button>
            <button id="pvs-close" style="background:none;border:none;cursor:pointer;
                color:var(--tx3);font-size:18px;padding:0 4px;line-height:1">✕</button>
          </div>

          <!-- 툴바 -->
          <div style="display:flex;align-items:center;gap:6px;
              padding:8px 14px;border-bottom:1px solid var(--bd);
              background:var(--bg3);flex-shrink:0;flex-wrap:wrap">
            <button onclick="PVShare._refresh()" title="새로고침"
                style="background:rgba(255,255,255,.07);border:1px solid var(--bd);
                    border-radius:5px;color:var(--tx2);font-size:11px;
                    padding:4px 10px;cursor:pointer">↻ 새로고침</button>
            <button onclick="PVShare._pull()" title="원격 변경사항 반영"
                style="background:rgba(88,200,248,.1);border:1px solid rgba(88,200,248,.3);
                    border-radius:5px;color:#58c8f8;font-size:11px;
                    padding:4px 10px;cursor:pointer">⬇ Pull</button>
            <button onclick="PVShare._pushCurrent()" title="현재 에디터 문서 Push"
                style="background:rgba(106,247,176,.1);border:1px solid rgba(106,247,176,.3);
                    border-radius:5px;color:#6af7b0;font-size:11px;
                    padding:4px 10px;cursor:pointer">⬆ Push</button>
            <button onclick="PVShare._cloneModal()" title="저장소 Clone"
                style="background:rgba(106,247,176,.1);border:1px solid rgba(106,247,176,.28);
                    border-radius:5px;color:#6af7b0;font-size:11px;
                    padding:4px 10px;cursor:pointer">⎘ Clone</button>
            <span id="pvs-status" style="font-size:10px;color:var(--tx3);margin-left:6px"></span>
          </div>

          <!-- 로컬 / GitHub 탭 -->
          <div style="display:flex;border-bottom:1px solid var(--bd);background:var(--bg3);flex-shrink:0">
            <button id="pvs-tab-local" onclick="PVShare._switchTab('local')"
                style="flex:1;padding:9px;font-size:12px;font-weight:600;border:none;cursor:pointer;
                    border-bottom:2px solid #58c8f8;
                    background:rgba(88,200,248,.08);color:#58c8f8;
                    transition:all .15s">
                💻 로컬</button>
            <button id="pvs-tab-github" onclick="PVShare._switchTab('github')"
                style="flex:1;padding:9px;font-size:12px;font-weight:600;border:none;cursor:pointer;
                    border-bottom:2px solid transparent;
                    background:transparent;color:var(--tx3);
                    transition:all .15s">
                🐙 GitHub</button>
          </div>

          <!-- 검색 -->
          <div style="padding:8px 14px;border-bottom:1px solid var(--bd);flex-shrink:0">
            <input id="pvs-search" type="text" placeholder="파일 검색…"
                oninput="PVShare._search(this.value)"
                style="width:100%;background:var(--bg3);border:1px solid var(--bd);
                    border-radius:6px;color:var(--tx);font-size:12px;
                    padding:6px 10px;outline:none;box-sizing:border-box">
          </div>

          <!-- 파일 목록 -->
          <div id="pvs-list" style="flex:1;overflow-y:auto;padding:6px 0;min-height:120px">
            <div style="text-align:center;padding:30px;color:var(--tx3);font-size:12px">
              ⟳ 파일 목록 불러오는 중…
            </div>
          </div>

          <!-- 하단 액션: [새파일] [새폴더] [자동새로고침] [25s] {설정} -->
          <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;
              border-top:1px solid var(--bd);background:var(--bg3);flex-shrink:0;flex-wrap:wrap">
            <button id="pvs-btn-newfile" onclick="PVShare._dispatchNewFile()" title="새 파일 만들기"
                style="flex:1;min-width:90px;padding:7px;border-radius:6px;
                    background:rgba(255,255,255,.06);border:1px solid var(--bd);
                    color:var(--tx2);font-size:12px;cursor:pointer">
                새 파일</button>
            <button id="pvs-btn-newfolder" onclick="PVShare._dispatchNewFolder()" title="새 폴더 만들기"
                style="flex:1;min-width:90px;padding:7px;border-radius:6px;
                    background:rgba(255,255,255,.06);border:1px solid var(--bd);
                    color:var(--tx2);font-size:12px;cursor:pointer">
                새 폴더</button>
            <button id="pvs-ar-btn" onclick="PVShare._toggleAutoRefresh()"
                title="GitHub 폴더 목록 자동 새로고침 ON/OFF"
                style="border-radius:5px;font-size:11px;padding:4px 10px;cursor:pointer;
                    font-weight:600;transition:all .2s;
                    color:#6af7b0;border:1px solid rgba(106,247,176,.35);
                    background:rgba(106,247,176,.1)">🔄 자동새로고침 ON</button>
            <span id="pvs-ar-countdown"
                style="font-size:11px;color:var(--tx3);min-width:28px;text-align:center;display:none"></span>
            <button onclick="PVShare._showArIntervalSetting()" title="자동 새로고침 간격(초) 설정"
                style="padding:6px 12px;border-radius:5px;border:1px solid var(--bd);
                    background:rgba(255,255,255,.06);color:var(--tx2);font-size:11px;cursor:pointer">
                ⚙ 설정</button>
          </div>
        </div>`;

        document.body.appendChild(ov);

        /* 닫기 */
        document.getElementById('pvs-close').onclick = () => {
            _stopAutoRefresh();
            ov.remove();
        };
        /* 모달 열릴 때 자동새로고침 버튼 상태 반영 + 시작 */
        setTimeout(() => {
            _arUpdateBtn();
            if (_arEnabled) _startAutoRefresh();
        }, 50);
        ov.onclick = (e) => { if (e.target === ov) ov.remove(); };

        /* 기본 탭: 로컬 탭 활성 */
        setTimeout(() => { _switchTab('local'); }, 0);
    }

    /* ── 파일 목록 렌더 ── */
    let _allFiles = [];
    let _searchQ  = '';
    let _currentGitHubPath = '';  /* GitHub 탭에서 현재 보고 있는 경로 (자동새로고침용) */

    async function _loadList(path = '') {
        const listEl = document.getElementById('pvs-list');
        if (!listEl) return;
        _currentGitHubPath = path;  /* 자동새로고침 시 같은 경로로 재요청 */
        _setStatus('불러오는 중…');

        const vcfg = _loadCfg();
        if (!vcfg?.repo) {
            listEl.innerHTML = `
            <div style="text-align:center;padding:30px;color:#f7c060;font-size:12px">
                ⚠ 저장소가 설정되지 않았습니다.<br>
                <button onclick="PVShare._showSettings()"
                    style="margin-top:10px;padding:6px 14px;border-radius:6px;
                        background:rgba(247,192,96,.15);border:1px solid rgba(247,192,96,.3);
                        color:#f7c060;font-size:12px;cursor:pointer">⚙ 설정하기</button>
            </div>`;
            _setStatus('');
            return;
        }

        try {
            const items = await _listPath(path);
            _allFiles = Array.isArray(items) ? items : [];
            _renderList(_allFiles);
            _setStatus('');
        } catch(e) {
            listEl.innerHTML = `
            <div style="text-align:center;padding:20px;color:#f76a6a;font-size:12px">
                ❌ ${e.message}<br>
                <button onclick="PVShare._loadList()"
                    style="margin-top:8px;padding:5px 12px;border-radius:5px;
                        background:rgba(247,106,106,.1);border:1px solid rgba(247,106,106,.3);
                        color:#f76a6a;font-size:11px;cursor:pointer">다시 시도</button>
            </div>`;
            _setStatus('오류');
        }
    }

    function _renderList(items) {
        const listEl = document.getElementById('pvs-list');
        if (!listEl) return;

        const q = _searchQ.toLowerCase();
        const filtered = q ? items.filter(f => f.name.toLowerCase().includes(q)) : items;

        if (!filtered.length) {
            listEl.innerHTML = `<div style="text-align:center;padding:24px;
                color:var(--tx3);font-size:12px">파일이 없습니다</div>`;
            return;
        }

        /* 폴더 먼저, 파일 나중 */
        const sorted = [...filtered].sort((a, b) => {
            if (a.type === b.type) return a.name.localeCompare(b.name);
            return a.type === 'dir' ? -1 : 1;
        });

        listEl.innerHTML = sorted.map(f => {
            const isDir  = f.type === 'dir';
            const icon   = isDir ? '📁' : (f.name.endsWith('.md') ? '📄' : '📎');
            const link   = isDir ? '' : _makeLink(f.path);
            const linkBtn = isDir ? '' : `
                <button onclick="event.stopPropagation();PVShare._copyLink('${_escQ(link)}',this)"
                    title="뷰어 링크 복사"
                    style="background:rgba(88,200,248,.12);border:1px solid rgba(88,200,248,.3);
                        border-radius:4px;color:#58c8f8;font-size:10px;
                        padding:2px 7px;cursor:pointer;flex-shrink:0">🔗</button>`;

            return `<div class="pvs-item" data-path="${_escQ(f.path)}" data-type="${f.type}"
                data-sha="${f.sha || ''}"
                style="display:flex;align-items:center;gap:6px;
                    padding:5px 14px;cursor:pointer;border-radius:4px;
                    transition:background .1s"
                onmouseover="this.style.background='rgba(255,255,255,.05)'"
                onmouseout="this.style.background=''"
                onclick="PVShare._itemClick(this)">
              <span style="flex-shrink:0;font-size:13px">${icon}</span>
              <span style="flex:1;font-size:12px;color:var(--tx);
                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(f.name)}</span>
              ${linkBtn}
              <button onclick="event.stopPropagation();PVShare._moveFile(this)"
                  data-path="${_escQ(f.path)}" data-type="${f.type}"
                  title="이동"
                  style="background:rgba(255,255,255,.06);border:1px solid var(--bd);
                      border-radius:4px;color:var(--tx3);font-size:10px;
                      padding:2px 7px;cursor:pointer;flex-shrink:0">↗</button>
              <button onclick="event.stopPropagation();PVShare._deleteItem(this)"
                  data-path="${_escQ(f.path)}" data-type="${f.type}"
                  data-sha="${_escQ(f.sha || '')}" data-name="${_escQ(f.name)}"
                  title="삭제"
                  style="background:rgba(247,106,106,.1);border:1px solid rgba(247,106,106,.25);
                      border-radius:4px;color:#f76a6a;font-size:10px;
                      padding:2px 7px;cursor:pointer;flex-shrink:0">🗑</button>
            </div>`;
        }).join('');
    }

    function _escQ(s) { return String(s).replace(/'/g,"\\'").replace(/"/g,'&quot;'); }
    function _esc(s)  { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

    /* ── 아이템 클릭: 폴더면 하위 목록, 파일이면 열기 ── */
    function _itemClick(row) {
        const path = row.dataset.path;
        const type = row.dataset.type;
        if (type === 'dir') {
            _loadList(path);
        }
    }

    /* ── 검색 ── */
    function _search(q) {
        _searchQ = q;
        _renderList(_allFiles);
    }

    /* ── 링크 복사 ── */
    function _copyLink(url, btn) {
        navigator.clipboard.writeText(url).then(() => {
            const orig = btn.textContent;
            btn.textContent = '✅';
            btn.style.color = '#6af7b0';
            setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 2000);
            App._toast('🔗 링크 복사됨: ' + url);
        }).catch(() => {
            prompt('링크를 복사하세요:', url);
        });
    }

    /* ── 상태 텍스트 ── */
    function _setStatus(msg) {
        const el = document.getElementById('pvs-status');
        if (el) el.textContent = msg;
    }

    /* ── 새로고침 ── */
    function _refresh() { _loadList(); }

    /* ── Pull: 원격 최신 파일 목록 갱신 ── */
    function _pull() {
        _setStatus('Pull 중…');
        _loadList().then(() => App._toast('⬇ Pull 완료'));
    }

    /* ── Push: 현재 에디터 문서를 docs/ 에 push ── */
    async function _pushCurrent() {
        const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
        if (!tab) { App._toast('⚠ 열린 문서가 없습니다'); return; }

        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); return; }

        const defaultName = (tab.title || '문서')
            .replace(/[^a-zA-Z0-9가-힣._-]/g,'_')
            .replace(/\.md$/i,'') + '.md';

        const name = prompt('저장할 파일명 (docs/ 안에 저장됩니다):', defaultName);
        if (!name) return;

        const filePath = 'docs/' + name;
        const content  = document.getElementById('editor')?.value || '';
        _setStatus('Push 중…');

        try {
            let sha = null;
            try { const ex = await _getFile(filePath); sha = ex.sha; } catch(e) {}
            await _putFile(filePath, content, `Publish: ${name}`, sha);
            _setStatus('');
            _loadList();
            const link = _makeLink(filePath);
            App._toast('✅ Push 완료');
            _showLinkResult(link, name);
        } catch(e) {
            _setStatus('오류');
            alert('Push 실패: ' + e.message);
        }
    }

    /* ── 로컬 / GitHub 탭 전환 ── */
    let _activeTab = 'local';   /* 현재 활성 탭: 'local' | 'github' */

    /* ── 자동 새로고침 ─────────────────────────────────────── */
    const AR_KEY      = 'pvs_auto_refresh';   // localStorage 키
    const AR_INTERVAL_KEY = 'pvs_ar_interval'; // 간격(초) 저장 키
    function _getArInterval() { return Math.max(10, parseInt(localStorage.getItem(AR_INTERVAL_KEY) || '30', 10) || 30); }
    let _arEnabled    = localStorage.getItem(AR_KEY) !== 'off'; // 기본 ON
    let _arTimer      = null;   // setInterval ID
    let _arCountdown  = 0;      // 남은 초
    let _arTick       = null;   // 카운트다운 ticker

    function _arSaveState() {
        localStorage.setItem(AR_KEY, _arEnabled ? 'on' : 'off');
    }

    function _arUpdateBtn() {
        const btn = document.getElementById('pvs-ar-btn');
        if (!btn) return;
        if (_arEnabled) {
            btn.textContent = '🔄 자동새로고침 ON';
            btn.style.color      = '#6af7b0';
            btn.style.borderColor = 'rgba(106,247,176,.35)';
            btn.style.background  = 'rgba(106,247,176,.1)';
        } else {
            btn.textContent = '🔄 자동새로고침 OFF';
            btn.style.color      = 'var(--tx3)';
            btn.style.borderColor = 'var(--bd)';
            btn.style.background  = 'rgba(255,255,255,.04)';
        }
    }

    function _arUpdateCountdown() {
        const el = document.getElementById('pvs-ar-countdown');
        if (!el) return;
        if (_arEnabled && _arCountdown > 0) {
            el.textContent = _arCountdown + 's';
            el.style.display = 'inline';
        } else {
            el.style.display = 'none';
        }
    }

    function _startAutoRefresh() {
        _stopAutoRefresh();
        if (!_arEnabled) return;
        const intervalSec = _getArInterval();
        _arCountdown = intervalSec;
        _arUpdateCountdown();

        // 카운트다운 ticker (1초마다)
        _arTick = setInterval(() => {
            _arCountdown--;
            _arUpdateCountdown();
            if (_arCountdown <= 0) {
                // GitHub 탭 활성 상태일 때만 GitHub 폴더 목록 새로고침 (현재 경로 유지)
                if (_activeTab === 'github') {
                    _loadList(_currentGitHubPath).catch(() => {});
                }
                _arCountdown = _getArInterval();
            }
        }, 1000);
    }

    function _stopAutoRefresh() {
        if (_arTimer)  { clearInterval(_arTimer);  _arTimer   = null; }
        if (_arTick)   { clearInterval(_arTick);   _arTick    = null; }
        _arCountdown = 0;
        _arUpdateCountdown();
    }

    function _toggleAutoRefresh() {
        _arEnabled = !_arEnabled;
        _arSaveState();
        _arUpdateBtn();
        if (_arEnabled) {
            _startAutoRefresh();
            App._toast('🔄 자동새로고침 ON (' + _getArInterval() + '초마다 GitHub 폴더)');
        } else {
            _stopAutoRefresh();
            App._toast('🔄 자동새로고침 OFF');
        }
    }

    /* 자동새로고침 간격(초) 설정 */
    function _showArIntervalSetting() {
        const cur = _getArInterval();
        const v = prompt('자동 새로고침 간격 (초)\nGitHub 탭에서 이 간격마다 폴더 목록을 갱신합니다.', String(cur));
        if (v == null) return;
        const num = parseInt(v, 10);
        if (!(num >= 10 && num <= 600)) {
            App._toast('⚠ 10~600 초 사이로 입력하세요');
            return;
        }
        localStorage.setItem(AR_INTERVAL_KEY, String(num));
        if (_arEnabled) _startAutoRefresh();
        App._toast('✅ 간격 ' + num + '초로 저장');
    }

    function _switchTab(tab) {
        _activeTab = tab;
        const localBtn  = document.getElementById('pvs-tab-local');
        const githubBtn = document.getElementById('pvs-tab-github');
        if (!localBtn || !githubBtn) return;

        if (tab === 'local') {
            localBtn.style.borderBottomColor  = '#58c8f8';
            localBtn.style.background         = 'rgba(88,200,248,.08)';
            localBtn.style.color              = '#58c8f8';
            githubBtn.style.borderBottomColor = 'transparent';
            githubBtn.style.background        = 'transparent';
            githubBtn.style.color             = 'var(--tx3)';
            _renderLocalFiles();
        } else {
            githubBtn.style.borderBottomColor = '#a090ff';
            githubBtn.style.background        = 'rgba(160,144,255,.08)';
            githubBtn.style.color             = '#a090ff';
            localBtn.style.borderBottomColor  = 'transparent';
            localBtn.style.background         = 'transparent';
            localBtn.style.color              = 'var(--tx3)';
            _loadList();
        }
        /* 하단 버튼 라벨을 탭에 맞게 갱신 */
        _updateBottomBtns(tab);
    }

    /* 하단 새파일/새폴더 버튼 라벨 갱신 */
    function _updateBottomBtns(tab) {
        const btnFile   = document.getElementById('pvs-btn-newfile');
        const btnFolder = document.getElementById('pvs-btn-newfolder');
        if (!btnFile || !btnFolder) return;
        if (tab === 'local') {
            btnFile.textContent   = '새 파일';
            btnFolder.textContent = '새 폴더';
            btnFile.title   = '로컬 공개노트 폴더에 새 파일 생성';
            btnFolder.title = '로컬 공개노트 폴더에 새 폴더 생성';
        } else {
            btnFile.textContent   = '새 파일';
            btnFolder.textContent = '새 폴더';
            btnFile.title   = 'md-viewer GitHub 저장소에 새 파일 생성';
            btnFolder.title = 'md-viewer GitHub 저장소에 새 폴더 생성';
        }
    }

    /* ── 로컬 탭 파일 목록 렌더 ── */
    /* ══════════════════════════════════════════════════
       공개노트 로컬 탭 — PVShare 전용 폴더 렌더
    ══════════════════════════════════════════════════ */
    function _renderLocalFiles() {
        const list = document.getElementById('pvs-list');
        if (!list) return;

        const curFolder = _pvFolderName || _pvLoadFolderName() || '';
        const files     = _pvFiles || [];

        /* ── 폴더 상태 헤더 (sticky) ── */
        const folderBar = `
            <div id="pvs-local-folderbar" style="display:flex;align-items:center;gap:8px;
                padding:8px 14px;background:var(--bg3);border-bottom:1px solid var(--bd);
                position:sticky;top:0;z-index:2;flex-shrink:0">
              <span style="font-size:12px">📂</span>
              <span id="pvs-local-foldername" style="flex:1;font-size:11px;font-weight:600;
                  color:${curFolder ? 'var(--tx)' : 'var(--tx3)'};
                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                  ${curFolder || '공개노트 폴더 미선택'}</span>
              <button onclick="PVShare._selectLocalFolder()"
                  style="padding:3px 11px;border-radius:5px;white-space:nowrap;flex-shrink:0;
                      border:1px solid rgba(88,200,248,.45);font-size:10.5px;cursor:pointer;
                      background:rgba(88,200,248,.1);color:#58c8f8">
                  ${curFolder ? '📂 변경' : '📂 폴더 선택'}</button>
              ${curFolder ? `<button onclick="PVShare._pvRefresh()"
                  title="폴더 새로고침"
                  style="padding:3px 8px;border-radius:5px;border:1px solid var(--bd);
                      background:rgba(255,255,255,.06);color:var(--tx3);font-size:11px;cursor:pointer">↻</button>` : ''}
              ${curFolder ? `<button onclick="PVShare._pvOpenLocalDir()"
                  title="연결된 로컬 폴더 탐색기에서 열기"
                  style="padding:3px 9px;border-radius:5px;border:1px solid rgba(247,201,106,.4);
                      background:rgba(247,201,106,.1);color:#f7c96a;font-size:10.5px;cursor:pointer;white-space:nowrap">📂 열기</button>` : ''}
            </div>`;

        /* 폴더 없거나 파일 없음 */
        if (!files.length) {
            list.innerHTML = folderBar + `
                <div style="text-align:center;padding:30px 16px;color:var(--tx3);font-size:12px;line-height:1.8">
                  ${curFolder
                    ? '<span style="font-size:22px">📭</span><br>파일이 없거나 스캔 중입니다.<br><button onclick="PVShare._pvRefresh()" style="margin-top:8px;padding:4px 14px;border-radius:5px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:11px;cursor:pointer">↻ 다시 스캔</button>'
                    : '<span style="font-size:22px">💻</span><br>공개노트(md-viewer)와 공유할<br>로컬 폴더를 선택하세요.'
                  }
                </div>`;
            return;
        }

        /* 폴더 → 파일 구분 정렬: .md 먼저, 나머지 나중 / isDir 빈폴더 별도 */
        const emptyDirs = files.filter(f => f.isDir);
        const realFiles = files.filter(f => !f.isDir);
        const mdFiles   = realFiles.filter(f => f.name.match(/\.md$/i));
        const others    = realFiles.filter(f => !f.name.match(/\.md$/i));
        const sorted    = [...mdFiles, ...others];

        /* 폴더 그룹핑 (folder 값 기준) */
        const grouped = {};
        sorted.forEach(f => {
            const grp = f.folder || '';
            if (!grouped[grp]) grouped[grp] = [];
            grouped[grp].push(f);
        });

        /* 빈 폴더: 아직 grouped 에 없는 경우 빈 배열로 등록 */
        emptyDirs.forEach(d => {
            /* d.folder = 부모 경로, d.path = 이 폴더 경로 */
            /* 빈 폴더를 부모 그룹 아래 배치 */
            const grp = d.folder || '';
            if (!grouped[grp]) grouped[grp] = [];
            grouped[grp].push(d);   /* isDir:true 항목 포함 */
        });

        let html = folderBar;

        Object.keys(grouped).sort().forEach(grpKey => {
            /* 서브폴더 헤더 */
            if (grpKey) {
                html += `<div style="display:flex;align-items:center;
                    padding:5px 14px 3px;font-size:10.5px;color:var(--tx3);
                    font-weight:600;background:rgba(255,255,255,.02);
                    border-bottom:1px solid rgba(255,255,255,.04)">
                  <span style="flex:1">📁 ${_escL(grpKey)}</span>
                  <button
                      onclick="event.stopPropagation();PVShare._pvCreateFileInFolder('${_escQL(grpKey)}')"
                      title="이 폴더에 새 파일 만들기"
                      style="padding:1px 7px;border-radius:4px;font-size:11px;cursor:pointer;flex-shrink:0;
                          border:1px solid rgba(106,247,176,.3);background:rgba(106,247,176,.07);color:#6af7b0;
                          line-height:1.4">📄＋</button>
                  <button
                      onclick="event.stopPropagation();PVShare._pvCreateFolderIn('${_escQL(grpKey)}')"
                      title="이 폴더 안에 새 하위 폴더 만들기"
                      style="padding:1px 7px;border-radius:4px;font-size:11px;cursor:pointer;flex-shrink:0;
                          border:1px solid rgba(247,201,106,.3);background:rgba(247,201,106,.07);color:#f7c96a;
                          line-height:1.4">📁＋</button>
                </div>`;
            }
            grouped[grpKey].forEach(f => {
                /* ── 빈 폴더 항목 (isDir:true) ── */
                if (f.isDir) {
                    html += `<div class="pvs-local-item pvs-empty-dir"
                        data-path="${_escQL(f.path)}"
                        data-name="${_escQL(f.name)}"
                        data-folder="${_escQL(f.folder || '')}"
                        style="display:flex;align-items:center;gap:6px;
                            padding:5px 14px 5px 24px;
                            border-bottom:1px solid rgba(255,255,255,.025);
                            font-size:11.5px;color:var(--tx3)">
                      <span style="font-size:12px;flex-shrink:0">📁</span>
                      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-style:italic">${_escL(f.name)}</span>
                      <span style="font-size:10px;background:rgba(255,255,255,.06);padding:1px 6px;border-radius:4px;flex-shrink:0">빈 폴더</span>
                    </div>`;
                    return;
                }
                const icon = f.name.match(/\.md$/i) ? '📝' : '📄';
                /* data-path / data-name 에 경로 저장 → 함수에서 closest로 읽음
                   JSON.stringify를 onclick 속성에 직접 삽입하면
                   큰따옴표 충돌로 HTML이 깨지므로 btn-only 방식 사용 */
                html += `
                <div class="pvs-local-item"
                    data-path="${_escQL(f.path)}"
                    data-name="${_escQL(f.name)}"
                    data-folder="${_escQL(f.folder || '')}"
                    style="display:flex;align-items:center;gap:6px;
                        padding:6px 14px;border-bottom:1px solid rgba(255,255,255,.035);
                        font-size:12px;color:var(--tx2);cursor:pointer;transition:background .1s"
                    onmouseover="this.style.background='rgba(255,255,255,.045)'"
                    onmouseout="this.style.background=''"
                    onclick="PVShare._pvOpenFile(this)"
                    ontouchstart="(function(row,ev){
                        if(ev.target.closest('button')){return;}
                        var already=row.classList.contains('touch-sel');
                        document.querySelectorAll('.pvs-local-item.touch-sel').forEach(function(el){if(el!==row)el.classList.remove('touch-sel');});
                        if(already){PVShare._pvOpenFile(row);row.classList.remove('touch-sel');}
                        else{row.classList.add('touch-sel');ev.preventDefault();}
                    })(this,event)">
                  <span style="font-size:12px;flex-shrink:0">${icon}</span>
                  <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">${_escL(f.name)}</span>
                  <!-- 비공개 커밋 (mdliveData GH) -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvPushPrivate(this)"
                      title="비공개 저장소(mdliveData)에 커밋"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(160,144,255,.35);background:rgba(160,144,255,.1);color:#a090ff">🐙</button>
                  <!-- 공개 커밋 (md-viewer GitHub) -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvPushPublic(this)"
                      title="공개 저장소(md-viewer)에 커밋"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(106,247,176,.35);background:rgba(106,247,176,.1);color:#6af7b0">📤</button>
                  <!-- 이동 -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvMoveFile(this)"
                      title="파일 이동 (로컬 폴더)"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.05);color:var(--tx3)">↗</button>
                  <!-- 삭제 -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvDeleteFile(this)"
                      title="파일 삭제 (로컬)"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(247,106,106,.3);background:rgba(247,106,106,.08);color:#f76a6a">🗑</button>
                </div>`;
            });
        });

        list.innerHTML = html;
    }

    /* ── 공개노트 로컬 폴더를 탐색기에서 열기 ── */
    function _pvOpenLocalDir() {
        if (!_pvDirHandle) { App._toast('⚠ 폴더를 먼저 선택하세요'); return; }
        /* 브라우저 보안 정책 상 직접 탐색기 실행 불가.
           폴더 이름과 경로를 알려주고 선택을 유도 */
        const name = _pvFolderName || _pvDirHandle.name || '?';
        App._toast('📂 폴더: ' + name + ' — 탐색기에서 해당 폴더를 찾아 여세요');
    }

    /* ── 로컬 폴더 새로고침 ── */
    async function _pvRefresh() {
        if (!_pvDirHandle) {
            App._toast('⚠ 폴더가 선택되지 않았습니다');
            return;
        }
        const ok = await _pvRequestPermission();
        if (!ok) { App._toast('⚠ 폴더 접근 권한이 필요합니다'); return; }
        App._toast('⟳ 스캔 중…');
        await _pvSync();
        _renderLocalFiles();
    }

    /* ── 로컬 파일 에디터로 열기 ── */
    /* btnOrRow: .pvs-local-item 행 자체 또는 그 안의 요소 */
    function _pvOpenFile(btnOrRow) {
        const row  = btnOrRow?.closest ? (btnOrRow.closest('.pvs-local-item') || btnOrRow) : btnOrRow;
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        const f = _pvFiles.find(x => x.path === path);
        if (!f) { App._toast('⚠ 파일을 찾을 수 없습니다: ' + path); return; }
        if (f.content === null || f.content === undefined) {
            App._toast('⚠ 내용을 읽을 수 없는 파일입니다');
            return;
        }
        if (typeof TM !== 'undefined') {
            TM.newTab({ title: name, content: f.content, path: f.path });
        } else if (typeof App !== 'undefined') {
            const ed = document.getElementById('editor');
            if (ed) { ed.value = f.content; App.render(); }
        }
        App._toast('📝 열기: ' + name);
    }

    /* ── 폴더 경로 → FileSystemDirectoryHandle 탐색 헬퍼 ── */
    /* create=true 이면 경로 상의 폴더가 없어도 생성하면서 진행 */
    async function _pvGetDirHandle(folderPath, create = false) {
        let h = _pvDirHandle;
        if (!folderPath) return h;
        const parts = folderPath.split('/');
        for (const part of parts) {
            if (!part) continue;
            h = await h.getDirectoryHandle(part, { create });
        }
        return h;
    }

    /* ── 파일 내용 헬퍼 ── */
    async function _pvGetContent(path) {
        /* 1) 이미 스캔된 파일에서 가져오기 (빈 문자열도 유효) */
        const cached = _pvFiles.find(x => x.path === path);
        if (cached && cached.content !== null && cached.content !== undefined) {
            return cached.content;
        }
        /* 2) dirHandle 통해 직접 읽기 */
        if (!_pvDirHandle) throw new Error('폴더 핸들 없음 — 폴더를 다시 선택하세요');
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'read' });
            if (perm !== 'granted') throw new Error('읽기 권한이 거부되었습니다');
        } catch(e) { /* 이미 granted인 경우 에러 무시 */ }
        const parts = path.split('/');
        let h = _pvDirHandle;
        for (let i = 0; i < parts.length - 1; i++) {
            h = await h.getDirectoryHandle(parts[i]);
        }
        const fileH = await h.getFileHandle(parts[parts.length - 1]);
        const file  = await fileH.getFile();
        return file.text();
    }

    /* ── 비공개 커밋 (mdliveData GH 저장소) ── */
    async function _pvPushPrivate(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn.closest('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        if (!GH.isConnected()) { App._toast('⚠ GH(mdliveData) 연결 설정이 필요합니다'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const origTxt = btn.textContent;
        btn.textContent = '⟳'; btn.disabled = true;
        try {
            /* 권한 확인 */
            const perm = await _pvDirHandle.requestPermission({ mode: 'read' });
            if (perm !== 'granted') throw new Error('폴더 읽기 권한이 필요합니다');

            const content = await _pvGetContent(path);
            if (content === null || content === undefined) throw new Error('파일 내용을 읽을 수 없습니다');

            const ghCfg  = GH.cfg;
            const base   = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
            const ghPath = base + name;

            let sha = null;
            try {
                const info = await fetch(
                    `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(ghPath)}?ref=${ghCfg.branch}`,
                    { headers: { 'Authorization': `token ${ghCfg.token}`, 'Accept': 'application/vnd.github.v3+json' } }
                ).then(r => r.ok ? r.json() : null);
                if (info?.sha) sha = info.sha;
            } catch(e) {}

            const b64  = btoa(unescape(encodeURIComponent(content)));
            const body = { message: `Upload: ${name}`, content: b64, branch: ghCfg.branch };
            if (sha) body.sha = sha;

            const res = await fetch(
                `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(ghPath)}`,
                {
                    method : 'PUT',
                    headers: {
                        'Authorization': `token ${ghCfg.token}`,
                        'Accept': 'application/vnd.github.v3+json',
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(body),
                }
            );
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(`GitHub ${res.status}: ${err.message || res.statusText}`);
            }
            btn.textContent = origTxt; btn.disabled = false;
            App._toast(`🐙 비공개 커밋 완료: ${name}`);
        } catch(e) {
            btn.textContent = origTxt; btn.disabled = false;
            App._toast('❌ 비공개 커밋 실패: ' + e.message);
        }
    }

    /* ── 공개 커밋 (md-viewer GitHub 저장소) ── */
    async function _pvPushPublic(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn?.closest?.('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); App._toast('⚠ md-viewer 저장소 미설정'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const origTxt = (btn && btn.textContent) || '📤';
        if (btn) { btn.textContent = '⟳'; btn.disabled = true; }
        try {
            /* 권한 확인 */
            const perm = await _pvDirHandle.requestPermission({ mode: 'read' });
            if (perm !== 'granted') throw new Error('폴더 읽기 권한이 필요합니다');

            const content  = await _pvGetContent(path);
            if (content === null || content === undefined) throw new Error('파일 내용을 읽을 수 없습니다');

            const filePath = 'docs/' + name;
            let sha = null;
            try { const ex = await _getFile(filePath); if (ex?.sha) sha = ex.sha; } catch(e) {}

            await _putFile(filePath, content, `Publish: ${name}`, sha);
            if (btn) { btn.textContent = origTxt; btn.disabled = false; }

            const link = _makeLink(filePath);
            navigator.clipboard.writeText(link).catch(() => {});
            App._toast(`📤 공개 커밋 완료: ${name}  🔗링크 복사됨`);
        } catch(e) {
            if (btn) { btn.textContent = origTxt; btn.disabled = false; }
            App._toast('❌ 공개 커밋 실패: ' + e.message);
        }
    }

    /* ── 이동 모달 UI (PVShare 전용) ── */
    function _pvShowMoveModal(fileName, folderOptions) {
        return new Promise(resolve => {
            const existing = document.getElementById('pvs-move-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'pvs-move-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9600;background:rgba(0,0,0,.68);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📦 파일 이동</span>
                    <button id="pvmov-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="font-size:12px;color:var(--tx2);margin-bottom:12px;padding:8px 10px;background:var(--bg3);border-radius:6px">
                    📝 <b>${_escL(fileName)}</b>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">이동할 폴더 선택</label>
                    <select id="pvmov-dest" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions.map(o => `<option value="${o.value}">${o.label}</option>`).join('')}
                    </select>
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="pvmov-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="pvmov-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 이동</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('pvmov-close').onclick  = () => close(null);
            document.getElementById('pvmov-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('pvmov-ok').onclick = () => {
                close(document.getElementById('pvmov-dest').value);
            };
        });
    }

    /* ── 로컬 파일 이동 (파일시스템 직접 이동) ── */
    async function _pvMoveFile(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn.closest('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const f = _pvFiles.find(x => x.path === path);
        if (!f) { App._toast('⚠ 파일을 찾을 수 없습니다'); return; }

        /* 이동 가능한 폴더 목록 수집 — 모든 상위 경로 + isDir 빈폴더 포함 */
        const currentFolder = f.folder || '';
        const folderSet = new Set(['']);  /* 루트 항상 포함 */
        _pvFiles.forEach(x => {
            const parts = (x.folder || '').split('/');
            let acc = '';
            for (const p of parts) {
                if (!p) continue;
                acc = acc ? acc + '/' + p : p;
                folderSet.add(acc);
            }
            if (x.isDir) folderSet.add(x.path);
        });

        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet]
            .filter(p => p !== '' && p !== currentFolder)
            .sort()
            .forEach(folderPath => {
                const depth = (folderPath.match(/\//g) || []).length;
                const label = '📂 ' + '  '.repeat(depth) + folderPath.split('/').pop() + '  (' + folderPath + ')';
                folderOptions.push({ label, value: folderPath });
            });

        const destFolder = await _pvShowMoveModal(name, folderOptions);
        if (destFolder === null) return; /* 취소 */

        const destPath = destFolder ? destFolder + '/' + name : name;
        if (destPath === path) { App._toast('ℹ 같은 폴더입니다'); return; }

        const origTxt = btn.textContent;
        btn.textContent = '⟳'; btn.disabled = true;
        try {
            /* 쓰기 권한 요청 */
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

            /* 원본 파일 내용 읽기 */
            const content = await _pvGetContent(path);

            /* 대상 폴더 핸들 */
            const destDirH = await _pvGetDirHandle(destFolder);

            /* 대상 위치에 파일 쓰기 */
            const newFH = await destDirH.getFileHandle(name, { create: true });
            const wr    = await newFH.createWritable();
            await wr.write(content);
            await wr.close();

            /* 원본 삭제 */
            const srcDirH = await _pvGetDirHandle(f.folder || '');
            await srcDirH.removeEntry(name);

            /* 목록 재스캔 & UI 갱신 */
            await _pvSync();
            _renderLocalFiles();
            App._toast(`✅ "${name}" → "${destFolder || '루트'}" 이동 완료`);
        } catch(e) {
            btn.textContent = origTxt; btn.disabled = false;
            App._toast('❌ 이동 실패: ' + e.message);
        }
    }

    /* ── 로컬 파일 삭제 (파일시스템 + 목록 갱신) ── */
    async function _pvDeleteFile(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn.closest('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const f = _pvFiles.find(x => x.path === path);
        if (!f) { App._toast('⚠ 파일을 찾을 수 없습니다'); return; }

        /* DelConfirm 모달 사용 */
        DelConfirm.show({
            name,
            path,
            type: 'local',
            onConfirm: async () => {
                try {
                    const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
                    if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

                    /* 부모 폴더 핸들 탐색 */
                    const parentH = await _pvGetDirHandle(f.folder || '');
                    await parentH.removeEntry(name);

                    /* 메모리 목록 즉시 갱신 */
                    _pvFiles = _pvFiles.filter(x => x.path !== path);
                    _renderLocalFiles();
                    App._toast(`🗑 "${name}" 삭제 완료`);
                } catch(e) {
                    alert('삭제 실패: ' + (e.message || e));
                }
            },
        });
    }

    function _escQL(s) { return String(s).replace(/'/g, "\\'").replace(/"/g, '&quot;'); }
    function _escL(s)  { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

    /* ── Clone 안내 모달 ── */
    /* ── Clone 안내 모달 ── */
    function _cloneModal() {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { App._toast('⚠ 저장소 미설정'); return; }
        const cloneUrl = `https://github.com/${vcfg.repo}.git`;

        navigator.clipboard.writeText(cloneUrl).catch(() => {});

        const ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;inset:0;z-index:9500;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
        ov.innerHTML = `
        <div style="background:var(--bg2);border:1px solid rgba(160,144,255,.35);border-radius:12px;
            padding:20px 22px;max-width:460px;width:100%;box-shadow:0 12px 50px rgba(0,0,0,.7)">
          <div style="font-size:13px;font-weight:700;color:#a090ff;margin-bottom:10px">📋 Clone URL 복사됨</div>
          <div style="font-size:11px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
            터미널에서 아래 명령으로 로컬에 Clone하세요:
          </div>
          <div style="background:var(--bg3);border:1px solid var(--bd);border-radius:6px;
              padding:9px 12px;font-family:var(--fm);font-size:11px;color:#a090ff;
              margin-bottom:14px;word-break:break-all;user-select:all">
            git clone ${cloneUrl}
          </div>
          <div style="font-size:10.5px;color:var(--tx3);margin-bottom:14px;line-height:1.6">
            Clone 후 <b style="color:var(--tx2)">로컬 폴더 열기</b>로 해당 폴더를 선택하면<br>
            Pull / Push로 GitHub와 동기화할 수 있습니다.
          </div>
          <div style="background:rgba(247,201,106,.1);border:1px solid rgba(247,201,106,.3);
              border-radius:6px;padding:8px 12px;margin-bottom:14px;
              display:flex;align-items:center;gap:10px">
            <div style="flex:1;font-size:10.5px;color:#f7c96a;line-height:1.6">
              📂 <b>폴더 찾기</b> — 해당 폴더에서 <code style="background:rgba(0,0,0,.3);padding:1px 4px;border-radius:3px">cmd</code>를 실행하여 이 코드를 실행하세요 (자동복사됩니다)
            </div>
            <button id="pvs-clone-folder-btn"
                style="padding:5px 12px;border-radius:5px;border:1px solid rgba(247,201,106,.4);
                    background:rgba(247,201,106,.12);color:#f7c96a;font-size:11px;
                    cursor:pointer;white-space:nowrap;flex-shrink:0">
                📂 폴더 찾기</button>
          </div>
          <div style="display:flex;justify-content:flex-end">
            <button id="pvs-clone-close" style="padding:6px 16px;border-radius:6px;
                border:1px solid var(--bd);background:var(--bg3);
                color:var(--tx2);font-size:12px;cursor:pointer">닫기</button>
          </div>
        </div>`;
        document.body.appendChild(ov);
        App._toast('📋 Clone URL 복사됨: ' + cloneUrl);

        document.getElementById('pvs-clone-close').onclick = () => ov.remove();
        ov.onclick = e => { if (e.target === ov) ov.remove(); };

        /* 폴더 찾기 — 파일 선택창으로 폴더 열기 */
        document.getElementById('pvs-clone-folder-btn').onclick = () => {
            const input = document.createElement('input');
            input.type = 'file';
            input.webkitdirectory = true;
            input.onchange = () => {
                if (input.files.length) {
                    const path = input.files[0].webkitRelativePath.split('/')[0];
                    App._toast(`📂 폴더 선택됨: ${path} — 로컬 탭에서 이 폴더를 열기하세요`);
                    ov.remove();
                    /* FM의 폴더 선택 연결 */
                    if (typeof FM !== 'undefined') FM.selectFolder();
                }
            };
            input.click();
        };
    }

    /* ── Clone URL 복사 (구형, 하위 호환) ── */
    function _clone() { _cloneModal(); }

    /* ── 새 파일 ── */
    /* ── 탭 분기: 로컬 vs GitHub ── */
    function _dispatchNewFile()   { _activeTab === 'local' ? _pvNewFile()   : _newFile(); }
    function _dispatchNewFolder() { _activeTab === 'local' ? _pvNewFolder() : _newFolder(); }

    /* ══════════════════════════════════════════════════
       PVShare 로컬 폴더 파일/폴더 생성 (FM 방식 차용)
    ══════════════════════════════════════════════════ */

    /* ── 특정 폴더 안에 새 하위 폴더 만들기 (폴더 헤더 📁+ 버튼) ── */
    async function _pvCreateFolderIn(parentPath) {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* parentPath 를 기본 선택한 채 폴더 이름 입력 모달 */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            const parts = (f.folder || '').split('/');
            let acc = '';
            for (const p of parts) { if (!p) continue; acc = acc ? acc + '/' + p : p; folderSet.add(acc); }
            if (f.isDir) folderSet.add(f.path);
        });
        const parentOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            parentOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const result = await _pvShowNewFolderModal(parentOptions, parentPath);
        if (!result) return;

        const { parentVal, name } = result;
        if (!name.trim()) return;
        const safe  = name.trim().replace(/[/\\:*?"<>|]/g, '_');
        const where = parentVal ? parentVal + '/' + safe : safe;

        try {
            const parentDirH = await _pvGetDirHandle(parentVal, true);
            const newDirH = await parentDirH.getDirectoryHandle(safe, { create: true });
            /* .gitkeep 생성 */
            try {
                const kh = await newDirH.getFileHandle('.gitkeep', { create: true });
                const kw = await kh.createWritable();
                await kw.write(''); await kw.close();
            } catch(e) {}
            App._toast('📁 "' + where + '" 폴더 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 폴더 생성 실패: ' + e.message);
        }
    }

    /* ── 특정 폴더에 새 파일 만들기 (폴더 헤더 + 버튼) ── */
    async function _pvCreateFileInFolder(folderPath) {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* folderPath 를 기본 위치로 선택한 채 모달 열기 */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            const parts = (f.folder || '').split('/');
            let acc = '';
            for (const p of parts) { if (!p) continue; acc = acc ? acc + '/' + p : p; folderSet.add(acc); }
            if (f.isDir) folderSet.add(f.path);
        });
        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            folderOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        /* 모달 표시 — folderPath 를 기본 선택값으로 */
        const chosen = await _pvShowNewFileModal(folderOptions, folderPath);
        if (!chosen) return;

        const { folderVal, filename } = chosen;
        let fname = filename.trim();
        if (!fname) return;
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe  = fname.replace(/[/\:*?"<>|]/g, '_');
        const where = folderVal ? folderVal + '/' + safe : safe;

        try {
            const destDirH = await _pvGetDirHandle(folderVal, true);
            const fh = await destDirH.getFileHandle(safe, { create: true });
            const wr = await fh.createWritable();
            await wr.write('# ' + safe.replace(/\.md$/i,'') + '\n\n내용을 입력하세요.\n');
            await wr.close();
            App._toast('📄 "' + where + '" 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 파일 생성 실패: ' + e.message);
        }
    }

    /* ── 로컬 새 파일 생성 모달 ── */
    async function _pvNewFile() {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 — 버튼 클릭 직후(사용자 제스처 컨텍스트) */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* 폴더 목록 수집 (isDir 빈 폴더 포함) */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            if (f.folder) folderSet.add(f.folder);
            if (f.isDir)  folderSet.add(f.path);   /* 빈 폴더도 선택 가능 */
        });
        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            folderOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const chosen = await _pvShowNewFileModal(folderOptions);
        if (!chosen) return;

        const { folderVal, filename } = chosen;
        let fname = filename.trim();
        if (!fname) return;
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe = fname.replace(/[/\\:*?"<>|]/g, '_');
        const where = folderVal ? folderVal + '/' + safe : safe;

        try {
            /* create=true: 대상 폴더가 없으면 생성 */
            const destDirH = await _pvGetDirHandle(folderVal, true);
            const fh = await destDirH.getFileHandle(safe, { create: true });
            const wr = await fh.createWritable();
            await wr.write('# ' + safe.replace(/\.md$/i,'') + '\n\n내용을 입력하세요.\n');
            await wr.close();

            App._toast('📄 "' + where + '" 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 파일 생성 실패: ' + e.message);
        }
    }

    /* ── 로컬 새 폴더 생성 모달 ── */
    async function _pvNewFolder() {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 — 버튼 클릭 직후(사용자 제스처 컨텍스트) */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* 폴더 목록 수집 (isDir 빈 폴더 포함) */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            if (f.folder) folderSet.add(f.folder);
            if (f.isDir)  folderSet.add(f.path);   /* 빈 폴더도 상위로 선택 가능 */
        });
        const parentOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            parentOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const result = await _pvShowNewFolderModal(parentOptions);
        if (!result) return;

        const { parentVal, name } = result;
        const safe  = name.replace(/[/\\:*?"<>|]/g, '_');
        const where = parentVal ? parentVal + '/' + safe : safe;

        try {
            /* create=true: 부모 경로가 없어도 생성 */
            const parentDirH = await _pvGetDirHandle(parentVal, true);
            const newDirH = await parentDirH.getDirectoryHandle(safe, { create: true });

            /* .gitkeep 생성 (빈 폴더 Git 추적용) */
            try {
                const kh = await newDirH.getFileHandle('.gitkeep', { create: true });
                const kw = await kh.createWritable();
                await kw.write('');
                await kw.close();
            } catch(e) {}

            App._toast('📁 "' + where + '" 폴더 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 폴더 생성 실패: ' + e.message);
        }
    }

    /* ── 로컬 새 파일 모달 UI (FM._showNewFileModal 방식 차용) ── */
    function _pvShowNewFileModal(folderOptions, defaultFolder) {
        return new Promise(resolve => {
            const existing = document.getElementById('pvs-newfile-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'pvs-newfile-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9700;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.5)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">💻 새 파일 만들기 (로컬)</span>
                    <button id="pvnf-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">위치 (저장 폴더)</label>
                    <select id="pvnf-folder" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions.map(o => '<option value="' + o.value + '"' + (defaultFolder !== undefined && o.value === defaultFolder ? ' selected' : '') + '>' + o.label + '</option>').join('')}
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">파일 이름 (확장자 없으면 .md 자동)</label>
                    <input id="pvnf-name" type="text" value="새파일.md" autocomplete="off"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="pvnf-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="pvnf-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 생성</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const nameInput = document.getElementById('pvnf-name');
            setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('pvnf-close').onclick   = () => close(null);
            document.getElementById('pvnf-cancel').onclick  = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('pvnf-ok').onclick = () => {
                const filename  = nameInput.value.trim();
                if (!filename) { nameInput.focus(); return; }
                const folderVal = document.getElementById('pvnf-folder').value;
                close({ folderVal, filename });
            };
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('pvnf-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });
    }

    /* ── 로컬 새 폴더 모달 UI ── */
    function _pvShowNewFolderModal(parentOptions, defaultParent) {
        return new Promise(resolve => {
            const existing = document.getElementById('pvs-newfolder-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'pvs-newfolder-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9700;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.5)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">💻 새 폴더 만들기 (로컬)</span>
                    <button id="pvnd-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">위치 (부모 폴더)</label>
                    <select id="pvnd-parent" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${parentOptions.map(o => '<option value="' + o.value + '">' + o.label + '</option>').join('')}
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">폴더 이름</label>
                    <input id="pvnd-name" type="text" value="새폴더" autocomplete="off"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="pvnd-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="pvnd-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 생성</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const nameInput = document.getElementById('pvnd-name');
            setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('pvnd-close').onclick  = () => close(null);
            document.getElementById('pvnd-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('pvnd-ok').onclick = () => {
                const name = nameInput.value.trim();
                if (!name) { nameInput.focus(); return; }
                const parentVal = document.getElementById('pvnd-parent').value;
                close({ parentVal, name });
            };
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('pvnd-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });
    }

    /* ─────────────────────────────────────────────────── */
    /* GitHub 탭 새 파일/폴더 (기존 유지) */
    /* ─────────────────────────────────────────────────── */
    async function _newFile() {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); return; }

        const name = prompt('새 파일명 (예: docs/새파일.md):','docs/새파일.md');
        if (!name) return;

        try {
            _setStatus('생성 중…');
            let sha = null;
            try { const ex = await _getFile(name); sha = ex.sha; } catch(e) {}
            await _putFile(name, '# 새 문서\n\n내용을 입력하세요.\n', `Create: ${name}`, sha);
            _setStatus('');
            _loadList();
            App._toast('📄 파일 생성: ' + name);
        } catch(e) {
            _setStatus('오류');
            alert('생성 실패: ' + e.message);
        }
    }

    /* ── 새 폴더 (.gitkeep) ── */
    async function _newFolder() {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); return; }

        const name = prompt('새 폴더명 (예: docs/강의자료):','docs/');
        if (!name) return;

        const keepPath = name.replace(/\/$/, '') + '/.gitkeep';
        try {
            _setStatus('생성 중…');
            await _putFile(keepPath, '', `Create folder: ${name}`, null);
            _setStatus('');
            _loadList();
            App._toast('📁 폴더 생성: ' + name);
        } catch(e) {
            _setStatus('오류');
            alert('폴더 생성 실패: ' + e.message);
        }
    }

    /* ── 파일/폴더 삭제 ── */
    async function _deleteItem(btn) {
        const path = btn.dataset.path;
        const type = btn.dataset.type;
        const name = btn.dataset.name;
        const sha  = btn.dataset.sha;

        if (!confirm(`"${name}"을(를) 삭제하시겠습니까?`)) return;

        try {
            _setStatus('삭제 중…');
            if (type === 'dir') {
                /* 폴더: 하위 파일 전체 가져와서 Trees API로 삭제 */
                const items = await _api(`/git/trees/${_loadCfg()?.branch || 'main'}?recursive=1`);
                const tree  = (items.tree || []).filter(f => f.type === 'blob' && f.path.startsWith(path + '/'));
                await _deleteFolderContents(path, tree);
            } else {
                await _deleteFile(path, sha, `Delete: ${name}`);
            }
            _setStatus('');
            _loadList();
            App._toast(`🗑 삭제: ${name}`);
        } catch(e) {
            _setStatus('오류');
            alert('삭제 실패: ' + e.message);
        }
    }

    /* ── 파일/폴더 이동 ── */
    async function _moveFile(btn) {
        const path = btn.dataset.path;
        const type = btn.dataset.type;
        const name = path.split('/').pop();

        const newPath = prompt('이동할 경로 (전체 경로 입력):', path);
        if (!newPath || newPath === path) return;

        try {
            _setStatus('이동 중…');
            if (type === 'dir') {
                App._toast('⚠ 폴더 이동은 지원되지 않습니다. 파일을 직접 이동해 주세요.');
                _setStatus('');
                return;
            }
            /* 파일: 새 경로에 쓰고 기존 경로 삭제 */
            const oldFile = await _getFile(path);
            const content = decodeURIComponent(escape(atob(oldFile.content.replace(/\n/g,''))));
            let newSha = null;
            try { const ex = await _getFile(newPath); newSha = ex.sha; } catch(e) {}
            await _putFile(newPath, content, `Move: ${name} → ${newPath}`, newSha);
            await _deleteFile(path, oldFile.sha, `Move (cleanup): ${name}`);
            _setStatus('');
            _loadList();
            App._toast(`↗ 이동 완료: ${path} → ${newPath}`);
        } catch(e) {
            _setStatus('오류');
            alert('이동 실패: ' + e.message);
        }
    }

    /* ── GH 파일행 📤 버튼에서 직접 push ── */
    async function quickPush({ name, content }) {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) {
            if (confirm('md-viewer 저장소가 설정되지 않았습니다. 지금 설정하시겠습니까?')) {
                _showSettings();
            }
            return;
        }

        const safeName = name.replace(/[^a-zA-Z0-9가-힣._-]/g,'_').replace(/\.md$/i,'') + '.md';

        /* prompt 대신 전용 모달 — 파일명이 항상 보임 */
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9350;background:rgba(0,0,0,.72);display:flex;align-items:center;justify-content:center;padding:16px';
            ov.innerHTML = `
            <div style="background:var(--bg2);border:1px solid rgba(88,200,248,.3);
                border-radius:14px;padding:22px 24px;max-width:420px;width:100%;
                box-shadow:0 12px 50px rgba(0,0,0,.7)">
                <div style="font-size:13px;font-weight:700;color:#58c8f8;margin-bottom:4px">
                    📤 md-viewer에 Push</div>
                <div style="font-size:11px;color:var(--tx3);margin-bottom:14px">
                    <span style="color:var(--tx2)">${_esc(vcfg.repo)}</span>
                    의 <code style="color:#a090ff">docs/</code> 폴더에 저장됩니다.
                </div>
                <label style="font-size:10px;color:var(--tx3);display:block;margin-bottom:5px">
                    저장 파일명</label>
                <div style="display:flex;align-items:center;gap:6px;margin-bottom:16px">
                    <span style="font-size:12px;color:var(--tx3);flex-shrink:0">docs/</span>
                    <input id="qp-fname" type="text" value="${safeName}"
                        style="flex:1;background:var(--bg3);border:1px solid var(--bd);
                            border-radius:6px;color:var(--tx);font-size:12px;
                            padding:7px 10px;outline:none;box-sizing:border-box"
                        oninput="document.getElementById('qp-preview').textContent=this.value">
                </div>
                <div style="font-size:10px;color:var(--tx3);margin-bottom:14px;
                    padding:7px 10px;background:var(--bg3);border-radius:6px">
                    🔗 예상 링크:
                    <span id="qp-preview" style="color:#a090ff;word-break:break-all;font-family:var(--fm)">
                        ${safeName}
                    </span>
                </div>
                <div id="qp-status" style="font-size:11px;color:#6af7b0;margin-bottom:10px;display:none"></div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="qp-cancel" style="padding:7px 16px;border-radius:6px;
                        border:1px solid var(--bd);background:var(--bg3);
                        color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="qp-ok" style="padding:7px 18px;border-radius:6px;border:none;
                        background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">
                        ⬆ Push</button>
                </div>
            </div>`;
            document.body.appendChild(ov);
            setTimeout(() => {
                const inp = document.getElementById('qp-fname');
                if (inp) { inp.focus(); inp.select(); }
            }, 40);

            const close = () => { ov.remove(); resolve(); };
            document.getElementById('qp-cancel').onclick = close;
            ov.onclick = (e) => { if (e.target === ov) close(); };

            document.getElementById('qp-ok').onclick = async () => {
                const fname = document.getElementById('qp-fname').value.trim();
                if (!fname) { alert('파일명을 입력하세요'); return; }
                const filePath = 'docs/' + fname;
                const okBtn    = document.getElementById('qp-ok');
                const statusEl = document.getElementById('qp-status');

                okBtn.textContent = '⟳ Push 중…'; okBtn.disabled = true;
                statusEl.style.display = '';
                statusEl.textContent = `docs/${fname} 에 저장 중…`;

                try {
                    let sha = null;
                    try { const ex = await _getFile(filePath); sha = ex.sha; } catch(e) {}
                    await _putFile(filePath, content, `Publish: ${fname}`, sha);
                    const link = _makeLink(filePath);
                    statusEl.textContent = '✅ Push 완료!';
                    App._toast('✅ md-viewer Push 완료');
                    setTimeout(() => { ov.remove(); _showLinkResult(link, fname); resolve(); }, 800);
                    /* 관리 창이 열려 있으면 목록 새로고침 */
                    if (document.getElementById('pvs-list')) _loadList('docs');
                } catch(e) {
                    okBtn.textContent = '⬆ Push'; okBtn.disabled = false;
                    statusEl.style.color = '#f76a6a';
                    statusEl.textContent = '❌ ' + e.message;
                }
            };
        });
    }

    /* ── 링크 결과 모달 ── */
    function _showLinkResult(url, title) {
        const ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;inset:0;z-index:9300;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
        ov.innerHTML = `
        <div style="background:var(--bg2);border:1px solid rgba(106,247,176,.35);
            border-radius:14px;padding:24px 26px;max-width:460px;width:100%;
            box-shadow:0 12px 50px rgba(0,0,0,.7)">
            <div style="font-size:14px;font-weight:700;color:#6af7b0;margin-bottom:6px">
                ✅ 공유 링크 발급 — ${_esc(title)}</div>
            <div style="font-size:11px;color:var(--tx3);margin-bottom:12px">
                링크를 복사해 공유하세요. 문서를 업데이트해도 같은 링크로 최신 내용이 표시됩니다.
            </div>
            <input id="pvsr-url" type="text" readonly value="${url}" onclick="this.select()"
                style="width:100%;background:var(--bg3);border:1px solid var(--bd);
                    border-radius:6px;color:var(--tx);font-size:11px;
                    padding:8px 10px;outline:none;box-sizing:border-box;
                    font-family:var(--fm);margin-bottom:12px">
            <div style="display:flex;gap:8px">
                <button id="pvsr-copy" style="flex:1;padding:9px;border-radius:7px;border:none;
                    background:var(--ac);color:#fff;font-size:13px;font-weight:700;cursor:pointer">
                    📋 링크 복사</button>
                <a href="${url}" target="_blank" rel="noopener noreferrer"
                    style="flex:1;padding:9px;border-radius:7px;
                        border:1px solid rgba(160,144,255,.4);
                        background:rgba(160,144,255,.1);color:#a090ff;
                        font-size:12px;font-weight:600;cursor:pointer;
                        text-decoration:none;display:flex;align-items:center;
                        justify-content:center;gap:4px">
                    🌐 미리보기</a>
                <button id="pvsr-close" style="padding:9px 14px;border-radius:7px;
                    border:1px solid var(--bd);background:var(--bg3);
                    color:var(--tx2);font-size:12px;cursor:pointer">닫기</button>
            </div>
        </div>`;
        document.body.appendChild(ov);
        setTimeout(() => { document.getElementById('pvsr-url')?.select(); }, 40);
        const close = () => ov.remove();
        document.getElementById('pvsr-close').onclick = close;
        ov.onclick = (e) => { if (e.target === ov) close(); };
        document.getElementById('pvsr-copy').onclick = () => {
            navigator.clipboard.writeText(url).then(() => {
                document.getElementById('pvsr-copy').textContent = '✅ 복사됨!';
                setTimeout(close, 1400);
            });
        };
    }

    /* ── 설정 모달 ── */
    /* ── 설정 모달 (로컬 폴더 + md-viewer 저장소 통합) ── */
    function _showSettings() {
        const vcfg      = _loadCfg() || {};
        const curFolder = _pvFolderName || _pvLoadFolderName() || '';

        const ov = document.createElement('div');
        ov.id = 'pvs-settings-overlay';
        ov.style.cssText = 'position:fixed;inset:0;z-index:9400;background:rgba(0,0,0,.78);display:flex;align-items:center;justify-content:center;padding:16px';
        ov.innerHTML = `
        <div style="background:var(--bg2);border:1px solid var(--bd);border-radius:14px;
            padding:0;max-width:460px;width:100%;
            box-shadow:0 12px 50px rgba(0,0,0,.7);overflow:hidden">

          <!-- 헤더 -->
          <div style="display:flex;align-items:center;justify-content:space-between;
              padding:14px 18px 12px;border-bottom:1px solid var(--bd);background:var(--bg3)">
            <span style="font-size:13px;font-weight:700;color:var(--txh)">⚙ 공개노트 설정</span>
            <button id="vcfg-x" style="background:none;border:none;cursor:pointer;
                color:var(--tx3);font-size:18px;padding:0;line-height:1">✕</button>
          </div>

          <div style="padding:18px">

            <!-- ① 로컬 폴더 섹션 -->
            <div style="margin-bottom:18px;padding:12px 14px;
                background:var(--bg3);border:1px solid var(--bd);border-radius:10px">
              <div style="font-size:11px;font-weight:700;color:#58c8f8;margin-bottom:10px;
                  letter-spacing:.5px">💻 로컬 폴더</div>
              <div style="font-size:10.5px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
                로컬 PC의 마크다운 폴더를 연결합니다.<br>
                선택한 폴더의 .md 파일이 로컬 탭에 표시됩니다.
              </div>
              <div style="display:flex;align-items:center;gap:8px">
                <div style="flex:1;background:var(--bg4);border:1px solid var(--bd);
                    border-radius:6px;padding:7px 10px;font-size:12px;
                    color:${curFolder ? 'var(--tx)' : 'var(--tx3)'};
                    overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                    id="vcfg-folder-display">
                  ${curFolder ? '📂 ' + curFolder : '선택된 폴더 없음'}
                </div>
                <button id="vcfg-select-folder"
                    style="padding:7px 14px;border-radius:6px;white-space:nowrap;
                        border:1px solid rgba(88,200,248,.4);
                        background:rgba(88,200,248,.1);color:#58c8f8;
                        font-size:12px;cursor:pointer;flex-shrink:0">
                  ${curFolder ? '📂 변경' : '📂 폴더 선택'}
                </button>
              </div>
            </div>

            <!-- ② md-viewer 저장소 섹션 -->
            <div style="margin-bottom:14px;padding:12px 14px;
                background:var(--bg3);border:1px solid var(--bd);border-radius:10px">
              <div style="font-size:11px;font-weight:700;color:#a090ff;margin-bottom:8px;
                  letter-spacing:.5px">🐙 md-viewer GitHub 저장소</div>
              <div style="font-size:10.5px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
                노트를 공개할 GitHub 저장소를 설정합니다.<br>
                토큰은 GH 패널 설정에서 자동으로 가져옵니다.
              </div>
              <div style="margin-bottom:10px">
                <label style="font-size:10px;color:var(--tx3);display:block;margin-bottom:4px">
                  저장소 (owner/repo)</label>
                <input id="vcfg-repo" type="text" value="${vcfg.repo || ''}"
                    placeholder="예: myname/my-notes"
                    style="width:100%;background:var(--bg4);border:1px solid var(--bd);
                        border-radius:6px;color:var(--tx);font-size:12px;
                        padding:7px 10px;outline:none;box-sizing:border-box">
                <div style="font-size:10px;color:var(--tx3);margin-top:4px">
                  현재: <span style="color:#a090ff">${vcfg.repo || '미설정'}</span>
                </div>
              </div>
              <div>
                <label style="font-size:10px;color:var(--tx3);display:block;margin-bottom:4px">
                  기본 브랜치</label>
                <input id="vcfg-branch" type="text" value="${vcfg.branch || 'main'}"
                    placeholder="main"
                    style="width:100%;background:var(--bg4);border:1px solid var(--bd);
                        border-radius:6px;color:var(--tx);font-size:12px;
                        padding:7px 10px;outline:none;box-sizing:border-box">
              </div>
            </div>

            <!-- 버튼 -->
            <div style="display:flex;gap:8px;justify-content:flex-end">
              <button id="vcfg-cancel" style="padding:7px 16px;border-radius:6px;
                  border:1px solid var(--bd);background:var(--bg3);
                  color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
              <button id="vcfg-save" style="padding:7px 20px;border-radius:6px;
                  border:none;background:var(--ac);color:#fff;
                  font-size:12px;font-weight:600;cursor:pointer">저장</button>
            </div>

          </div>
        </div>`;

        document.body.appendChild(ov);
        const close = () => ov.remove();

        document.getElementById('vcfg-x').onclick      = close;
        document.getElementById('vcfg-cancel').onclick  = close;
        ov.onclick = (e) => { if (e.target === ov) close(); };

        /* ── 로컬 폴더 선택 버튼 ── */
        document.getElementById('vcfg-select-folder').onclick = async () => {
            const ok = await _pvSelectFolder();
            if (!ok) return;
            const newFolder = _pvFolderName;
            const dispEl    = document.getElementById('vcfg-folder-display');
            const btnEl     = document.getElementById('vcfg-select-folder');
            if (dispEl) {
                dispEl.textContent = newFolder ? '📂 ' + newFolder : '선택된 폴더 없음';
                dispEl.style.color = newFolder ? 'var(--tx)' : 'var(--tx3)';
            }
            if (btnEl) btnEl.textContent = newFolder ? '📂 변경' : '📂 폴더 선택';
            /* 로컬 탭 폴더바도 즉시 업데이트 */
            _renderLocalFiles();
        };

        /* ── 저장 버튼 ── */
        document.getElementById('vcfg-save').onclick = () => {
            const repo   = document.getElementById('vcfg-repo').value.trim();
            const branch = document.getElementById('vcfg-branch').value.trim() || 'main';
            if (repo && !repo.includes('/')) {
                App._toast('⚠ 저장소명은 owner/repo 형식으로 입력하세요');
                return;
            }
            if (repo) {
                _saveCfg({ repo, branch });
                /* 모달 헤더 저장소명 업데이트 */
                const nameEl = document.getElementById('pvs-repo-name');
                if (nameEl) {
                    nameEl.textContent = repo + ' ↗';
                    nameEl.href = `https://github.com/${repo}`;
                }
                App._toast('✅ md-viewer 저장소 설정 저장됨');
            }
            close();
            _loadList();
            /* 로컬 탭도 새로고침 */
            const localBtn = document.getElementById('pvs-tab-local');
            if (localBtn && localBtn.style.color && localBtn.style.color !== 'var(--tx3)') {
                _renderLocalFiles();
            }
        };

        setTimeout(() => { document.getElementById('vcfg-repo')?.focus(); }, 50);
    }

    /* ── 공개노트 로컬 폴더 선택 (PVShare 전용) ── */
    async function _selectLocalFolder() {
        const ok = await _pvSelectFolder();
        if (ok) _renderLocalFiles();
    }

    /* ── 로컬 파일 열기 (PVShare 전용 → _pvOpenFile 위임) ── */
    function _openLocalFile(btnOrRow) { _pvOpenFile(btnOrRow); }

    /* ── 로컬 파일 Push (PVShare 전용 → _pvPushPublic 위임) ── */
    async function _pushLocalFile(btn) { await _pvPushPublic(btn); }

    /* ── 초기화 ── */
    function refresh() {
        const btn = document.getElementById(BTN_ID);
        if (!btn) return;
        const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
        btn.style.display = tab ? '' : 'none';
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', refresh);
    } else {
        setTimeout(refresh, 300);
    }

    return {
        refresh,
        copy       : openModal,
        openModal,
        quickPush,
        quickPushCurrent: () => {
            const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
            if (!tab) { App._toast('⚠ 열린 문서가 없습니다'); return; }
            const content = document.getElementById('editor')?.value || '';
            return quickPush({ name: tab.title || 'document', content });
        },
        _refresh,
        _pull,
        _pushCurrent,
        _clone,
        _cloneModal,
        _switchTab,
        _newFile,
        _newFolder,
        _dispatchNewFile,
        _dispatchNewFolder,
        _pvNewFile,
        _pvNewFolder,
        _deleteItem,
        _moveFile,
        _copyLink,
        _search,
        _itemClick,
        _showSettings,
        _selectLocalFolder,
        _pvOpenLocalDir,
        _pvCreateFolderIn,
        _pvCreateFileInFolder,
        _openLocalFile,
        _pushLocalFile,
        _pvSelectFolder,
        _pvRefresh,
        _pvOpenFile,
        _pvPushPrivate,
        _pvPushPublic,
        _pvMoveFile,
        _pvDeleteFile,
        _loadList,
        _toggleAutoRefresh,
        _showArIntervalSetting,
    };
})();
