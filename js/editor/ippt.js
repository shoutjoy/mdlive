/* IPPT — 내부 PV PPT 드로잉 팔레트 (ppt-nav 내 버튼으로 제어) */
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
