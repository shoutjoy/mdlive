/* ═══════════════════════════════════════════════════════════
   PvImageResize — PV 창 이미지 마우스 크기 조절
   의존: el (dom.js), US, TM, App (전역)
   - 이미지 클릭 시 핸들 표시
   - Shift 누르면 비율 유지
   - resize 완료 시 에디터 width 동기화
═══════════════════════════════════════════════════════════ */
const PvImageResize = (() => {
    let _currentWrapper = null;

    function _collectImageInfos(md) {
        const infos = [];
        const lines = (md || '').split('\n');
        const imgRegex = /!\[([^\]]*)\]\(([^)]+)\)|<img[^>]+>/gi;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            let m;
            let idxInLine = 0;
            imgRegex.lastIndex = 0;
            while ((m = imgRegex.exec(line)) !== null) {
                if (m[0].startsWith('!')) {
                    infos.push({ line: i, idxInLine, type: 'md', alt: m[1], src: m[2], fullMatch: m[0] });
                } else {
                    infos.push({ line: i, idxInLine, type: 'html', fullMatch: m[0] });
                }
                idxInLine++;
            }
        }
        return infos;
    }

    function _wrapAndAttach(container, md, lineOffset) {
        const infos = _collectImageInfos(md);
        infos.forEach(info => { info.line += (lineOffset || 0); });
        const imgs = container.querySelectorAll('img');
        imgs.forEach((img, idx) => {
            if (img.closest('.pv-resizable-wrapper')) return;
            const info = infos[idx];
            const wrapper = document.createElement('div');
            wrapper.className = 'pv-resizable-wrapper';
            img.parentNode.insertBefore(wrapper, img);
            wrapper.appendChild(img);

            const handleBottom = document.createElement('div');
            handleBottom.className = 'pv-resize-handle pv-resize-handle-bottom';
            handleBottom.title = '드래그하여 세로 크기 조절';
            wrapper.appendChild(handleBottom);

            const handleRight = document.createElement('div');
            handleRight.className = 'pv-resize-handle pv-resize-handle-right';
            handleRight.title = '드래그하여 가로 크기 조절';
            wrapper.appendChild(handleRight);

            const handleCorner = document.createElement('div');
            handleCorner.className = 'pv-resize-handle pv-resize-handle-corner';
            handleCorner.title = '드래그하여 비율 유지 크기 조절 (Shift: 자유 비율)';
            wrapper.appendChild(handleCorner);

            if (info) {
                img.dataset.sourceLine = String(info.line);
                img.dataset.sourceIdx = String(info.idxInLine || 0);
                img.dataset.sourceType = info.type;
                if (info.type === 'md') {
                    img.dataset.sourceAlt = info.alt || '';
                    img.dataset.sourceSrc = info.src || '';
                    img.dataset.sourceFull = info.fullMatch || '';
                } else {
                    img.dataset.sourceFull = info.fullMatch || '';
                }
            }

            _enableSelection(wrapper);
            _enableResize(wrapper, img, handleBottom, 'bottom');
            _enableResize(wrapper, img, handleRight, 'right');
            _enableResize(wrapper, img, handleCorner, 'corner');
        });
    }

    function _enableSelection(wrapper) {
        wrapper.addEventListener('click', (e) => {
            e.stopPropagation();
            _clearActive();
            wrapper.classList.add('active');
            _currentWrapper = wrapper;
        });
    }

    function _clearActive() {
        document.querySelectorAll('.pv-resizable-wrapper').forEach(w => w.classList.remove('active'));
        _currentWrapper = null;
    }

    function _enableResize(wrapper, img, handle, mode) {
        handle.addEventListener('mousedown', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const startX = e.clientX;
            const startY = e.clientY;
            const startWidth = img.offsetWidth;
            const startHeight = img.offsetHeight;
            const ratio = startHeight > 0 ? startWidth / startHeight : 1;

            function onMove(ev) {
                const dx = ev.clientX - startX;
                const dy = ev.clientY - startY;
                let newWidth = startWidth;
                let newHeight = startHeight;

                if (mode === 'bottom') {
                    newHeight = Math.max(20, startHeight + dy);
                } else if (mode === 'right') {
                    newWidth = Math.max(20, startWidth + dx);
                } else {
                    if (ev.shiftKey) {
                        const d = Math.abs(dx) >= Math.abs(dy) ? dx : dy;
                        newWidth = Math.max(20, startWidth + d);
                        newHeight = Math.round(newWidth / ratio);
                    } else {
                        newWidth = Math.max(20, startWidth + dx);
                        newHeight = Math.max(20, startHeight + dy);
                    }
                }

                img.style.width = newWidth + 'px';
                img.style.height = newHeight + 'px';
            }

            function onUp() {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
                _syncEditor(img, img.offsetWidth, img.offsetHeight);
            }

            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
        });
    }

    function _syncEditor(img, newWidth, newHeight) {
        const ed = el('editor');
        if (!ed) return;
        const lineNum = parseInt(img.dataset.sourceLine, 10);
        const type = img.dataset.sourceType;
        const idxInLine = parseInt(img.dataset.sourceIdx, 10) || 0;
        if (isNaN(lineNum)) return;

        const lines = ed.value.split('\n');
        if (lineNum < 0 || lineNum >= lines.length) return;

        let newLine = lines[lineNum];
        if (type === 'md') {
            const alt = (img.dataset.sourceAlt || '').replace(/"/g, '&quot;');
            const src = (img.dataset.sourceSrc || img.src || '').replace(/"/g, '&quot;');
            const newImgTag = `<img src="${src}" alt="${alt}" width="${newWidth}" style="width:${newWidth}px;height:auto">`;
            let n = 0;
            newLine = newLine.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, (match) => {
                if (n++ === idxInLine) return newImgTag;
                return match;
            });
        } else if (type === 'html') {
            const full = img.dataset.sourceFull || '';
            let replaced = full;
            if (/width\s*=\s*["']?\d+["']?/i.test(replaced)) {
                replaced = replaced.replace(/width\s*=\s*["']?\d+["']?/i, `width="${newWidth}"`);
            } else {
                replaced = replaced.replace(/<img/i, `<img width="${newWidth}"`);
            }
            if (/height\s*=\s*["']?\d+["']?/i.test(replaced) && newHeight) {
                replaced = replaced.replace(/height\s*=\s*["']?\d+["']?/i, `height="${newHeight}"`);
            }
            let n = 0;
            newLine = newLine.replace(/<img[^>]+>/gi, (match) => {
                if (n++ === idxInLine) return replaced;
                return match;
            });
        } else {
            return;
        }

        lines[lineNum] = newLine;
        ed.value = lines.join('\n');
        if (typeof US !== 'undefined' && US.snap) US.snap();
        if (typeof TM !== 'undefined' && TM.markDirty) TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    }

    function init(md) {
        const pc = el('preview-container');
        if (!pc) return;
        _clearActive();
        document.querySelectorAll('.pv-resizable-wrapper').forEach(w => {
            const img = w.querySelector('img');
            if (img) w.parentNode.insertBefore(img, w);
            w.remove();
        });
        const pages = (md || '').replace(/\r\n/g, '\n').split(/\n?<div class="page-break"><\/div>\n?/);
        const pageMd = pages.length ? pages : [md || ''];
        let lineOffset = 0;
        const sel = pc.classList.contains('slide-mode') ? '.ppt-slide .slide-inner' : '.preview-page';
        const blocks = pc.querySelectorAll(sel);
        blocks.forEach((block, i) => {
            _wrapAndAttach(block, pageMd[i] || '', lineOffset);
            const lineCount = (pageMd[i] || '').split('\n').length;
            lineOffset += lineCount + (i < pageMd.length - 1 ? 1 : 0);
        });
    }

    document.addEventListener('click', (e) => {
        if (!e.target.closest('.pv-resizable-wrapper')) _clearActive();
    });

    return { init };
})();
