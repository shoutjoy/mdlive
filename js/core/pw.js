/* PW — Preview Window (el, Render, LN, SS 의존) */
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