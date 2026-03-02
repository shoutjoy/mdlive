/* ScholarApiKey — SerpAPI 키 암호화 저장 */
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