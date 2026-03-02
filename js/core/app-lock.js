/* AppLock — 앱 잠금 & GH/PV 설정 암호화 (localStorage) */
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