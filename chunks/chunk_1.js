/* ins, repCL: App/US 의존 — index.js에 유지 */
function ins(ed, s, e, text) { ed.value = ed.value.substring(0, s) + text + ed.value.substring(e); const p = s + text.length; ed.setSelectionRange(p, p); ed.focus(); App.render(); US.snap() }
function repCL(ed, t) { const { ls, le } = getCL(ed); ed.value = ed.value.substring(0, ls) + t + ed.value.substring(le); const p = ls + t.length; ed.setSelectionRange(p, p); ed.focus(); App.render(); US.snap() }

/* AppLock → js/core/app-lock.js */

/* AiApiKey → js/core/ai-apikey.js */

/* ScholarApiKey → js/core/scholar-apikey.js */

/* mdRender, splitPages, parseSlideContent, parseMarkdownToSlides → js/markdown/parser.js */

/* PR (Preview Renderer) → js/markdown/preview.js */

/* SlideMode → js/markdown/slide-mode.js */

/* PV → js/markdown/pv.js */


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
/* AiApiKey → js/core/ai-apikey.js */
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

/* PW → js/core/pw.js */


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
/* TM → js/core/tm.js */

/* ═══════════════════════════════════════════════════════════
   CITATION MANAGER
═══════════════════════════════════════════════════════════ */
/* SB → js/core/sb.js */

/* CiteModal → js/ui/cite-modal.js */

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

/* TMPLS → js/data/templates.js (로드 시 전역 TMPLS 사용) */

/* Scholar → js/scholar/scholar.js */

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