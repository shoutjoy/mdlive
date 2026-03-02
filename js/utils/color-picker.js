/* ColorPicker — 글자/형광펜 색상 선택 모달 */
const ColorPicker = (() => {
    let mode = 'text';
    const TEXT_COLORS = ['#e8e8f0', '#ff4444', '#ff8800', '#ffcc00', '#44cc44', '#00aaff', '#aa44ff', '#ff44aa', '#000000', '#333333', '#666666', '#999999', '#cccccc', '#ffffff', '#5b4ce4', '#f7a06a'];
    const BG_COLORS = ['#fff176', '#ffcc80', '#ef9a9a', '#80cbc4', '#a5d6a7', '#90caf9', '#ce93d8', '#f48fb1', '#ffecb3', '#dcedc8', 'transparent'];

    function open(m) {
        mode = m;
        el('color-modal-title').textContent = m === 'text' ? '글자 색상 설정' : '형광펜 하이라이트 색상';
        const colors = m === 'text' ? TEXT_COLORS : BG_COLORS;
        el('color-swatches').innerHTML = colors.map(c => `<div class="csw" style="background:${c === 'transparent' ? 'repeating-linear-gradient(45deg,#888,#888 2px,transparent 2px,transparent 6px)' : c};border-color:${c === '#ffffff' ? '#ccc' : 'transparent'}" onclick="ColorPicker.setHex('${c}')" title="${c}"></div>`).join('');
        el('color-hex').value = '';
        const supported = 'EyeDropper' in window;
        el('eyedropper-btn').style.display = supported ? '' : 'none';
        el('eyedrop-support-msg').style.display = supported ? 'none' : 'block';
        el('eyedrop-btn').onclick = e => { e.preventDefault(); el('color-native').click() };
        el('color-modal').classList.add('vis');
        updatePreview('');
    }

    function setHex(c) {
        el('color-hex').value = c;
        if (c && c !== 'transparent') { try { el('color-native').value = c } catch (e) { } }
        updatePreview(c);
    }

    function fromNative(hex) {
        el('color-hex').value = hex;
        updatePreview(hex);
    }

    async function eyedrop() {
        if (!('EyeDropper' in window)) {
            el('eyedrop-support-msg').style.display = 'block'; return;
        }
        try {
            el('color-modal').style.opacity = '0';
            el('color-modal').style.pointerEvents = 'none';
            const result = await new EyeDropper().open();
            el('color-modal').style.opacity = '';
            el('color-modal').style.pointerEvents = '';
            setHex(result.sRGBHex);
        } catch (e) {
            el('color-modal').style.opacity = '';
            el('color-modal').style.pointerEvents = '';
        }
    }

    function updatePreview(c) {
        const prev = el('color-preview');
        if (!c || c === 'transparent') { prev.style.color = ''; prev.style.background = ''; return }
        if (mode === 'text') { prev.style.color = c; prev.style.background = '' }
        else { prev.style.background = c; prev.style.color = '' }
    }

    function apply() {
        const c = el('color-hex').value.trim(); if (!c) return;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd; const sel = ed.value.substring(s, e) || '텍스트';
        let wrapped;
        if (mode === 'text') { wrapped = `<span style="color:${c}">${sel}</span>` }
        else { wrapped = c === 'transparent' ? sel : `<span style="background:${c}">${sel}</span>` }
        ins(ed, s, e, wrapped);
        if (mode === 'text') { el('fc-bar').style.background = c }
        else { el('hl-bar').style.background = c }
        App.hideModal('color-modal');
    }

    return { open, setHex, fromNative, eyedrop, updatePreview, apply };
})();
