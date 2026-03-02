/* SS — Scroll Sync (에디터↔미리보기 헤딩 앵커 동기화), el, PW 의존 */
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
       getComputedStyle lineHeight·paddingTop 사용 (동기화 정렬 보정)  */
    function _buildMap(ed) {
        const lines = ed.value.split('\n');
        const style = window.getComputedStyle(ed);
        const lineHeight = parseFloat(style.lineHeight) || 21;
        const paddingTop = parseFloat(style.paddingTop) || 12;
        const map = [];
        lines.forEach((ln, i) => {
            const m = ln.match(/^(#{1,3})\s+(.+)/);
            if (!m) return;
            map.push({ line: i, id: _makeId(m[2]), edY: paddingTop + Math.round(i * lineHeight) });
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
            const style = window.getComputedStyle(ed);
            const lineHeight = parseFloat(style.lineHeight) || 21;
            const paddingTop = parseFloat(style.paddingTop) || 12;
            refY = paddingTop + curLine * lineHeight;
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
        if (typeof PW !== 'undefined' && PW.pushScroll) PW.pushScroll(rEd, anchor);
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
        ['pv-sync-btn', 'ed-sync-btn'].forEach(id => {
            const btn = el(id);
            if (!btn) return;
            btn.textContent = _enabled ? '🔗 동기화 ON' : '🔗 동기화 OFF';
            btn.style.color       = _enabled ? '#6af7b0' : '#888';
            btn.style.background  = _enabled ? 'rgba(106,247,176,.12)' : 'rgba(255,255,255,.05)';
            btn.style.borderColor = _enabled ? 'rgba(106,247,176,.35)' : 'rgba(255,255,255,.15)';
        });
    }

    function onCursor() {
        clearTimeout(_tCursor);
        _tCursor = setTimeout(() => { _syncToPv(true); }, 60);
    }

    function init() {
        const ed = el('editor'), pc = el('preview-container');
        if (!ed || !pc) return;

        ed.addEventListener('scroll', () => {
            if (_lock) return;
            clearTimeout(_tScroll);
            _tScroll = setTimeout(() => {
                _lock = true; _syncToPv(false);
                setTimeout(() => { _lock = false; }, 120);
            }, 10);
        }, { passive: true });

        pc.addEventListener('scroll', () => {
            if (_lock || !_enabled) return;
            clearTimeout(_tScroll);
            _tScroll = setTimeout(() => {
                _lock = true; _syncToEd();
                setTimeout(() => { _lock = false; }, 120);
            }, 10);
        }, { passive: true });

        _updateBtn();
    }

    return { init, toggle, onCursor, isEnabled: () => _enabled };
})();
