/* IMG — 이미지 드롭/업로드, 미리보기, ImgCrop, ImgInsert → js/image/img.js
   의존: el, TM, ImgStore, App (전역). _showImgpv는 다른 스크립트에서 호출됨 */

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

function clearImageModalTraces() {
    const urlEl = document.getElementById('img-url');
    const altEl = document.getElementById('img-alt');
    const dropText = document.getElementById('img-drop-text');
    const codeInput = document.getElementById('img-code-input');
    const htmlUrl = document.getElementById('img-html-url');
    const htmlW = document.getElementById('img-html-width');
    const htmlH = document.getElementById('img-html-height');
    const cropBtn = document.getElementById('img-insert-crop-btn');
    if (urlEl) urlEl.value = '';
    if (altEl) altEl.value = '';
    if (dropText) { dropText.textContent = '🖼 클릭 또는 드래그'; dropText.style.color = ''; }
    if (codeInput) codeInput.value = '';
    if (htmlUrl) htmlUrl.value = '';
    if (htmlW) htmlW.value = '';
    if (htmlH) htmlH.value = '';
    if (cropBtn) cropBtn.disabled = true;
    _showImgpv('');
    window._mdliveCropPending = null;
    window._imgCropTarget = null;
}
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
        // crop 창 로드 후 이미지 전달 (crop-ready 메시지 실패 시 폴백)
        const sendToCrop = () => {
            if (w.closed) return;
            try { w.postMessage({ type: 'crop', image: src }, '*'); } catch (e) {}
        };
        setTimeout(sendToCrop, 150);
        setTimeout(sendToCrop, 500);
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
