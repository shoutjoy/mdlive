/* AiApiKey — Google AI API 키 암호화 저장 */
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