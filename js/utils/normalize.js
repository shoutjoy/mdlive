/* ═══════════════════════════════════════════════════════════
   NFC 정규화 유틸 (점진적 적용용)
   사용: normalizeNFC(str) → index.js 내 value.normalize('NFC') 대체 가능
═══════════════════════════════════════════════════════════ */
function normalizeNFC(value) {
    return value != null && typeof value === 'string' ? value.normalize('NFC') : value;
}
