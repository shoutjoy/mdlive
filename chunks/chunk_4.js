    const PAIRS = { '(': ')', '[': ']', '"': '"', "'": "'", '{': '}', '<': '>' };

    function isEnabled() {
        try { return localStorage.getItem(STORAGE_KEY) !== 'off'; } catch (e) { return true; }
    }

    function updateUI() {
        const enabled = isEnabled();
        const btn = document.getElementById('hk-auto-pair-btn');
        if (btn) btn.textContent = enabled ? 'ON' : 'OFF';
    }

    function toggle() {
        let enabled = isEnabled();
        enabled = !enabled;
        try { localStorage.setItem(STORAGE_KEY, enabled ? 'on' : 'off'); } catch (e) {}
        updateUI();
    }

    /** 에디터에서 ( [ " ' 입력 시 처리. 처리했으면 true, 아니면 false */
    function handleKey(e) {
        if (!e.key || e.key.length !== 1) return false;
        const open = e.key;
        const close = PAIRS[open];
        if (close === undefined) return false;
        if (e.ctrlKey || e.metaKey || e.altKey) return false;
        if (!isEnabled()) return false;

        const edi = document.getElementById('editor');
        if (!edi || document.activeElement !== edi) return false;

        const ss = edi.selectionStart;
        const se = edi.selectionEnd;
        const val = edi.value;

        if (ss !== se) {
            /* 선택 영역 wrap: "텍스트" → "텍스트" */
            e.preventDefault();
            const sel = val.substring(ss, se);
            edi.value = val.substring(0, ss) + open + sel + close + val.substring(se);
            edi.setSelectionRange(ss + 1 + sel.length, ss + 1 + sel.length);
            edi.focus();
            if (typeof US !== 'undefined') US.snap();
            if (typeof TM !== 'undefined') TM.markDirty();
            if (typeof App !== 'undefined' && App.render) App.render();
            return true;
        }

        /* 커서만 있을 때: 자동쌍 ( ) [ ] " " ' ' */
        e.preventDefault();
        edi.value = val.substring(0, ss) + open + close + val.substring(se);
        edi.setSelectionRange(ss + 1, ss + 1);
        edi.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
        return true;
    }

    function init() {
        updateUI();
    }

    return { handleKey, isEnabled, toggle, init, updateUI };
})();

/* ═══════════════════════════════════════════════════════════
   AUTHOR INFO — 이름/소속/메일/연락처 저장 및 Shift+Alt+A 삽입
═══════════════════════════════════════════════════════════ */
const AuthorInfo = (() => {
    const STORAGE_KEY = 'mdpro_author_info';
    const INSERT_KEY = 'mdpro_author_insert';
    const DEFAULT_INSERT = { name: true, affiliation: false, email: false, contact: false };

    function load() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : { name: '', affiliation: '', email: '', contact: '' };
        } catch (e) { return { name: '', affiliation: '', email: '', contact: '' }; }
    }

    function loadInsert() {
        try {
            const raw = localStorage.getItem(INSERT_KEY);
            return raw ? JSON.parse(raw) : { ...DEFAULT_INSERT };
        } catch (e) { return { ...DEFAULT_INSERT }; }
    }

    function saveInputs() {
        const name = document.getElementById('hk-author-name');
        const affiliation = document.getElementById('hk-author-affiliation');
        const email = document.getElementById('hk-author-email');
        const contact = document.getElementById('hk-author-contact');
        if (!name) return;
        const data = {
            name: (name.value || '').trim(),
            affiliation: (affiliation && affiliation.value ? affiliation.value : '').trim(),
            email: (email && email.value ? email.value : '').trim(),
            contact: (contact && contact.value ? contact.value : '').trim()
        };
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) {}
        saveInsertFromCheckboxes();
    }

    function saveInsertFromCheckboxes() {
        const chkName = document.getElementById('hk-insert-name');
        const chkAff = document.getElementById('hk-insert-affiliation');
        const chkEmail = document.getElementById('hk-insert-email');
        const chkContact = document.getElementById('hk-insert-contact');
        if (!chkName) return;
        const data = {
            name: !!chkName.checked,
            affiliation: !!(chkAff && chkAff.checked),
            email: !!(chkEmail && chkEmail.checked),
            contact: !!(chkContact && chkContact.checked)
        };
        try { localStorage.setItem(INSERT_KEY, JSON.stringify(data)); } catch (e) {}
    }

    function loadToPanel() {
        const data = load();
        const nameEl = document.getElementById('hk-author-name');
        const affEl = document.getElementById('hk-author-affiliation');
        const emailEl = document.getElementById('hk-author-email');
        const contactEl = document.getElementById('hk-author-contact');
        if (nameEl) nameEl.value = data.name || '';
        if (affEl) affEl.value = data.affiliation || '';
        if (emailEl) emailEl.value = data.email || '';
        if (contactEl) contactEl.value = data.contact || '';

        const ins = loadInsert();
        const chkName = document.getElementById('hk-insert-name');
        const chkAff = document.getElementById('hk-insert-affiliation');
        const chkEmail = document.getElementById('hk-insert-email');
        const chkContact = document.getElementById('hk-insert-contact');
        if (chkName) chkName.checked = ins.name;
        if (chkAff) chkAff.checked = ins.affiliation;
        if (chkEmail) chkEmail.checked = ins.email;
        if (chkContact) chkContact.checked = ins.contact;

        [chkName, chkAff, chkEmail, chkContact].forEach(el => {
            if (el) el.removeEventListener('change', saveInsertFromCheckboxes);
            if (el) el.addEventListener('change', saveInsertFromCheckboxes);
        });
    }

    function getTextToInsert() {
        const data = load();
        const ins = loadInsert();
        const lines = [];
        if (ins.name && data.name) lines.push(data.name);
        if (ins.affiliation && data.affiliation) lines.push(data.affiliation);
        if (ins.email && data.email) lines.push(data.email);
        if (ins.contact && data.contact) lines.push(data.contact);
        return lines.join('\n');
    }

    /** 패널 입력란에서 작성된 항목만 모두 모아서 삽입 (체크박스 무시) */
    function getAllWrittenText() {
        const nameEl = document.getElementById('hk-author-name');
        const affEl = document.getElementById('hk-author-affiliation');
        const emailEl = document.getElementById('hk-author-email');
        const contactEl = document.getElementById('hk-author-contact');
        const lines = [];
        if (nameEl && (nameEl.value || '').trim()) lines.push((nameEl.value || '').trim());
        if (affEl && (affEl.value || '').trim()) lines.push((affEl.value || '').trim());
        if (emailEl && (emailEl.value || '').trim()) lines.push((emailEl.value || '').trim());
        if (contactEl && (contactEl.value || '').trim()) lines.push((contactEl.value || '').trim());
        return lines.join('\n');
    }

    function insertIntoEditor() {
        const ed = document.getElementById('editor');
        if (!ed) return;
        const text = getTextToInsert();
        if (!text) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        const val = ed.value;
        ed.value = val.substring(0, s) + text + val.substring(e);
        ed.setSelectionRange(s + text.length, s + text.length);
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    }

    function insertAllIntoEditor() {
        const ed = document.getElementById('editor');
        if (!ed) return;
        const text = getAllWrittenText();
        if (!text) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        const val = ed.value;
        ed.value = val.substring(0, s) + text + val.substring(e);
        ed.setSelectionRange(s + text.length, s + text.length);
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    }

    return { load, loadInsert, saveInputs, loadToPanel, getTextToInsert, getAllWrittenText, insertIntoEditor, insertAllIntoEditor };
})();

/* ═══════════════════════════════════════════════════════════
   FONT SIZE MANAGER  (선택 텍스트에 크기 적용)
═══════════════════════════════════════════════════════════ */
const FS = (() => {
    const SIZES = [8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 36, 40, 48, 50];
    let cur = 4;// 기본 12pt

    function updateDisplay() {
        el('fsize-display').textContent = SIZES[cur] + 'pt';
    }

    function apply() {
        const pt = SIZES[cur];
        const ed = el('editor');
        const s = ed.selectionStart, e = ed.selectionEnd;
        const sel = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="font-size:${pt}pt">${sel}</span>`);
    }

    function inc() { if (cur < SIZES.length - 1) { cur++; updateDisplay(); apply() } }
    function dec() { if (cur > 0) { cur--; updateDisplay(); apply() } }

    // 한번 클릭 → 드롭다운 픽커
    let _picker = null;
    function clickPick(ev) {
        ev.stopPropagation();
        if (_picker) { _picker.remove(); _picker = null; return }
        const rect = el('fsize-display').getBoundingClientRect();
        const div = document.createElement('div');
        div.style.cssText = `position:fixed;left:${rect.left}px;top:${rect.bottom + 2}px;background:var(--bg2);border:1px solid var(--bd);border-radius:6px;box-shadow:0 6px 24px rgba(0,0,0,.4);z-index:9999;overflow:hidden;min-width:70px`;
        div.innerHTML = SIZES.map((s, i) => `<div data-i="${i}" style="padding:5px 14px;font-family:var(--fm);font-size:12px;cursor:pointer;color:${i === cur ? 'var(--ac)' : 'var(--tx)'};background:${i === cur ? 'var(--acg)' : 'transparent'};transition:background .1s" onmouseenter="this.style.background='var(--bg5)'" onmouseleave="this.style.background='${i === cur ? 'var(--acg)' : 'transparent'}'" onclick="FS.pickSize(${i},event)">${s}pt</div>`).join('');
        document.body.appendChild(div); _picker = div;
        setTimeout(() => document.addEventListener('click', _closePicker, { once: true }), 10);
    }
    function _closePicker() { if (_picker) { _picker.remove(); _picker = null } }
    function pickSize(i, ev) { if (ev) ev.stopPropagation(); cur = i; updateDisplay(); _closePicker(); apply() }

    // 두번 클릭 → 인라인 직접 입력
    function startEdit(ev) {
        ev.stopPropagation(); _closePicker();
        const disp = el('fsize-display'), inp = el('fsize-input');
        inp.value = SIZES[cur];
        disp.style.display = 'none'; inp.style.display = 'inline-block';
        inp.focus(); inp.select();
    }
    function endEdit() {
        const inp = el('fsize-input'), disp = el('fsize-display');
        const v = parseInt(inp.value);
        if (v >= 6 && v <= 200) {
            // find nearest or add
            let best = 0, bDiff = 999;
            SIZES.forEach((s, i) => { const d = Math.abs(s - v); if (d < bDiff) { bDiff = d; best = i } });
            cur = best; updateDisplay(); apply();
        }
        inp.style.display = 'none'; disp.style.display = '';
    }
    function editKey(ev) { if (ev.key === 'Enter') el('fsize-input').blur(); if (ev.key === 'Escape') { el('fsize-input').style.display = 'none'; el('fsize-display').style.display = ''; } }

    function update() { updateDisplay() }
    return { inc, dec, update, clickPick, pickSize, startEdit, endEdit, editKey };
})();

/* ═══════════════════════════════════════════════════════════
   FORMAT QUICK PANEL (Alt+L)
═══════════════════════════════════════════════════════════ */
const FP = (() => {
    let vis = false;
    function show() {
        const panel = el('fmt-panel');
        if (vis) { hide(); return }
        // position near toolbar
        const tb = document.querySelector('#toolbar');
        const rect = tb.getBoundingClientRect();
        panel.style.left = '50%'; panel.style.top = (rect.bottom + 4) + 'px';
        panel.style.transform = 'translateX(-50%)';
        panel.classList.add('vis'); vis = true;
        setTimeout(() => document.addEventListener('click', _outside, { once: true }), 10);
    }
    function hide() { el('fmt-panel').classList.remove('vis'); vis = false }
    function _outside(e) { if (!el('fmt-panel').contains(e.target)) hide(); else setTimeout(() => document.addEventListener('click', _outside, { once: true }), 10) }

    function fsz(dir) {
        const sel = el('fp-fsize');
        const idx = sel.selectedIndex;
        const ni = Math.max(0, Math.min(sel.options.length - 1, idx + dir));
        sel.selectedIndex = ni; applyFsize();
    }
    function applyFsize() {
        const size = el('fp-fsize').value;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="font-size:${size}">${sel2}</span>`);
    }
    function setFc(c) { el('fp-fc').value = c === '#e8e8f0' ? '#e8e8f0' : c; applyColor() }
    function applyColor() {
        const c = el('fp-fc').value;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="color:${c}">${sel2}</span>`);
    }
    function setHL(c) { if (c === 'none') { applyHLnone(); return } el('fp-hl').value = c; applyHL() }
    function applyHL() {
        const c = el('fp-hl').value;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="background:${c}">${sel2}</span>`);
    }
    function applyHLnone() {
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e);
        if (sel2) ins(ed, s, e, sel2.replace(/<span style="background:[^"]*">(.*?)<\/span>/gs, '$1'));
    }
    return { show, hide, fsz, applyFsize, setFc, applyColor, setHL, applyHL };
})();

/* ═══════════════════════════════════════════════════════════
   APA STATISTICS INSERTER
═══════════════════════════════════════════════════════════ */
const STATS = (() => {
    const CUSTOM_KEY = 'mdpro_custom_stats';
    let curType = 'ttest';
    let customList = [];

    const TYPES = {
        ttest: {
            label: 't-test',
            fields: [
                { id: 'df', label: 'df', ph: '자유도', req: true },
                { id: 't', label: 't', ph: 't값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
                { id: 'd', label: "Cohen's d", ph: '효과크기 (선택)', req: false },
            ],
            fmt: (v) => {
                let s = `(t(${v.df}) = ${v.t}, p = ${fmtP(v.p)}`;
                if (v.d) s += `, d = ${v.d}`;
                return s + ')';
            }
        },
        anova: {
            label: 'ANOVA',
            fields: [
                { id: 'df1', label: 'df₁', ph: '처리 자유도', req: true },
                { id: 'df2', label: 'df₂', ph: '오차 자유도', req: true },
                { id: 'F', label: 'F', ph: 'F값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
                { id: 'np2', label: 'η²p', ph: '부분 에타제곱 (선택)', req: false },
            ],
            fmt: (v) => {
                let s = `(F(${v.df1}, ${v.df2}) = ${v.F}, p = ${fmtP(v.p)}`;
                if (v.np2) s += `, η²p = ${v.np2}`;
                return s + ')';
            }
        },
        regression: {
            label: 'Regression',
            fields: [
                { id: 'beta', label: 'β (표준화)', ph: '베타 (선택)', req: false },
                { id: 'B', label: 'B (비표준화)', ph: 'B (선택)', req: false },
                { id: 'SE', label: 'SE', ph: '표준오차 (선택)', req: false },
                { id: 't', label: 't', ph: 't값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
            ],
            fmt: (v) => {
                const parts = [];
                if (v.beta) parts.push(`β = ${v.beta}`);
                if (v.B) parts.push(`B = ${v.B}`);
                if (v.SE) parts.push(`SE = ${v.SE}`);
                parts.push(`t = ${v.t}`);
                parts.push(`p = ${fmtP(v.p)}`);
                return '(' + parts.join(', ') + ')';
            }
        },
        correlation: {
            label: 'Correlation',
            fields: [
                { id: 'r', label: 'r', ph: '상관계수', req: true },
                { id: 'df', label: 'df', ph: '자유도 (선택)', req: false },
                { id: 'p', label: 'p', ph: 'p값', req: true },
            ],
            fmt: (v) => {
                let s = v.df ? `(r(${v.df}) = ${v.r}` : `(r = ${v.r}`;
                s += `, p = ${fmtP(v.p)})`;
                return s;
            }
        },
        chisq: {
            label: 'Chi-square',
            fields: [
                { id: 'df', label: 'df', ph: '자유도', req: true },
                { id: 'chisq', label: 'χ²', ph: '카이제곱값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
                { id: 'V', label: "Cramer's V", ph: '효과크기 (선택)', req: false },
            ],
            fmt: (v) => {
                let s = `(χ²(${v.df}) = ${v.chisq}, p = ${fmtP(v.p)}`;
                if (v.V) s += `, Cramer's V = ${v.V}`;
                return s + ')';
            }
        },
        sem: {
            label: 'SEM',
            fields: [
                { id: 'beta', label: 'β (표준화)', ph: '베타 (선택)', req: false },
                { id: 'b', label: 'b (비표준화)', ph: 'b (선택)', req: false },
                { id: 'SE', label: 'SE', ph: '표준오차 (선택)', req: false },
                { id: 'z', label: 'z', ph: 'z값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
            ],
            fmt: (v) => {
                const parts = [];
                if (v.beta) parts.push(`β = ${v.beta}`);
                if (v.b) parts.push(`b = ${v.b}`);
                if (v.SE) parts.push(`SE = ${v.SE}`);
                parts.push(`z = ${v.z}`);
                parts.push(`p = ${fmtP(v.p)}`);
                return '(' + parts.join(', ') + ')';
            }
        },
        logistic: {
            label: 'Logistic Regression',
            fields: [
                { id: 'OR', label: 'OR', ph: '오즈비', req: true },
                { id: 'CI_low', label: '95% CI 하한', ph: '하한값', req: true },
                { id: 'CI_high', label: '95% CI 상한', ph: '상한값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
            ],
            fmt: (v) => `(OR = ${v.OR}, 95% CI [${v.CI_low}, ${v.CI_high}], p = ${fmtP(v.p)})`
        },
        multilevel: {
            label: 'Multilevel (HLM)',
            fields: [
                { id: 'gamma', label: 'γ', ph: '감마 계수', req: true },
                { id: 'SE', label: 'SE', ph: '표준오차', req: true },
                { id: 't', label: 't', ph: 't값', req: true },
                { id: 'p', label: 'p', ph: 'p값', req: true },
            ],
            fmt: (v) => `(γ = ${v.gamma}, SE = ${v.SE}, t = ${v.t}, p = ${fmtP(v.p)})`
        },
    };

    function fmtP(p) {
        if (!p) return '?';
        const n = parseFloat(p);
        if (isNaN(n)) return p;
        if (n < .001) return '< .001';
        if (n < .01) return n.toFixed(3).replace('0.', '. ').replace(/ /, '');
        return n.toFixed(3).replace('0.', '.').replace(/0+$/, '').replace(/\.$/, '');
    }

    function loadCustom() { try { customList = JSON.parse(localStorage.getItem(CUSTOM_KEY) || '[]') } catch (e) { customList = [] } }
    function saveCustomList() { try { localStorage.setItem(CUSTOM_KEY, JSON.stringify(customList)) } catch (e) { } }

    function renderFields(type) {
        const area = el('stats-fields');
        const customArea = el('stats-custom-area');
        if (type === 'custom') {
            area.style.display = 'none';
            customArea.style.display = 'block';
            renderCustomSavedSel();
            updateCustomVars();
        } else {
            area.style.display = 'grid';
            customArea.style.display = 'none';
            const t = TYPES[type]; if (!t) return;
            area.innerHTML = t.fields.map(f => `
        <div class="fg" style="margin:0">
          <label class="fl">${f.label}${f.req ? '' : ' <span style="color:var(--tx3)">(선택)</span>'}</label>
          <input class="fi" id="sf_${f.id}" type="text" placeholder="${f.ph}" oninput="STATS.preview()" style="padding:5px 8px">
        </div>`).join('');
        }
        preview();
    }

    function preview() {
        const pv = el('stats-preview');
        try {
            if (curType === 'custom') {
                const fmt = el('custom-fmt').value;
                const vars = (el('custom-vars').value || '').split(',').map(s => s.trim()).filter(Boolean);
                const vals = {};
                vars.forEach(v => { const inp = el('cfsf_' + v); vals[v] = inp ? inp.value.trim() : ''; });
                let out = fmt;
                vars.forEach(v => { if (vals[v]) out = out.replaceAll('{' + v + '}', vals[v]); });
                pv.textContent = out || '(출력 미리보기)';
            } else {
                const t = TYPES[curType]; if (!t) { pv.textContent = ''; return }
                const vals = {};
                t.fields.forEach(f => { const inp = el('sf_' + f.id); vals[f.id] = inp ? inp.value.trim() : ''; });
                pv.textContent = t.fmt(vals);
            }
        } catch (e) { pv.textContent = '입력값 오류' }
    }

    function setType(type) {
        curType = type;
        document.querySelectorAll('#stats-type-row .btn-tog').forEach(b => b.classList.remove('active'));
        const btn = el('st-' + type); if (btn) btn.classList.add('active');
        renderFields(type);
    }

    function insert() {
        const pv = el('stats-preview').textContent;
        if (!pv || (pv === '(출력 미리보기)' && curType === 'custom')) return;
        const ed = el('editor'); const pos = ed.selectionEnd;
        ed.value = ed.value.substring(0, pos) + pv + ed.value.substring(pos);
        ed.setSelectionRange(pos + pv.length, pos + pv.length);
        ed.focus(); App.render(); US.snap();
        App.hideModal('stats-modal');
    }

    function updateCustomVars() {
        const vars = (el('custom-vars').value || '').split(',').map(s => s.trim()).filter(Boolean);
        const area = el('custom-fields');
        area.innerHTML = vars.map(v => `
      <div class="fg" style="margin:0">
        <label class="fl">${v}</label>
        <input class="fi" id="cfsf_${v}" type="text" placeholder="${v} 값" oninput="STATS.preview()" style="padding:5px 8px">
      </div>`).join('');
        preview();
    }

    function saveCustom() {
        const name = (el('custom-name').value || '').trim();
        const fmt = (el('custom-fmt').value || '').trim();
        const vars = (el('custom-vars').value || '').trim();
        if (!name || !fmt) { alert('이름과 포맷을 입력하세요.'); return }
        const existing = customList.findIndex(c => c.name === name);
        const entry = { name, fmt, vars };
        if (existing >= 0) customList[existing] = entry;
        else customList.push(entry);
        saveCustomList();
        renderCustomSavedSel();
        el('custom-name').value = '';
        alert(`"${name}" 저장됨`);
    }

    function deleteCustom() {
        const sel = el('custom-saved-sel').value;
        if (!sel) return;
        customList = customList.filter(c => c.name !== sel);
        saveCustomList();
        renderCustomSavedSel();
        el('custom-name').value = ''; el('custom-fmt').value = ''; el('custom-vars').value = '';
        el('custom-fields').innerHTML = '';
        preview();
    }

    function loadCustom(name) {
        if (!name) return;
        const c = customList.find(x => x.name === name);
        if (!c) return;
        el('custom-name').value = c.name;
        el('custom-fmt').value = c.fmt;
        el('custom-vars').value = c.vars || '';
        updateCustomVars();
    }

    function renderCustomSavedSel() {
        const sel = el('custom-saved-sel');
        sel.innerHTML = '<option value="">— 저장된 커스텀 —</option>' + customList.map(c => `<option value="${c.name}">${c.name}</option>`).join('');
    }

    function show() {
        loadCustom();
        el('stats-modal').classList.add('vis');
        setType(curType);
    }

    return { show, setType, preview, insert, updateCustomVars, saveCustom, deleteCustom, loadCustom };
})();

/* ═══════════════════════════════════════════════════════════
   HOTKEY ENGINE
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   HK — 단축키 목록 매니저 (편집 가능)
═══════════════════════════════════════════════════════════ */
const HK = (() => {
    const STORAGE_KEY = 'mdpro-hotkeys-v2';

    /* ── action → 실제 함수 매핑 ───────────────────────────────
       handleKey()가 HK.getDispatch()를 통해 이 테이블을 참조하여
       동적으로 디스패치한다. 키 수정 시 rebuild()가 재빌드한다.  */
    const ACTION_MAP = {
        'view.split':       () => App.setViewCycle('split'),
        'view.editor':      () => App.setViewCycle('editor'),
        'view.preview':     () => App.setViewCycle('preview'),
        'ed.h1':            () => ED.h(1),
        'ed.h2':            () => ED.h(2),
        'ed.h3':            () => ED.h(3),
        'ed.pageBreak':     () => ED.pageBreak(),
        'ed.lineBreak':     () => ED.lineBreak(),
        'ed.bold':          () => ED.bold(),
        'ed.italic':        () => ED.italic(),
        'ed.bquote':        () => ED.bquote(),
        'ed.inlineCode':    () => ED.inlineCode(),
        'ed.codeBlock':     () => ED.codeBlockDirect(),
        'ed.table':         () => ED.table(),
        'ed.tableRow':      () => ED.tableRow(),
        'ed.tableCol':      () => ED.tableCol(),
        'ed.mergeH':        () => ED.mergeH(),
        'ed.mergeV':        () => ED.mergeV(),
        'ed.footnote':      () => ED.footnote(),
        'ed.alignLeft':     () => ED.align('left'),
        'ed.alignCenter':   () => ED.align('center'),
        'ed.alignRight':    () => ED.align('right'),
        'ed.moveUp':        () => ED.moveLine(-1),
        'ed.moveDown':      () => ED.moveLine(1),
        'ed.dupLine':       () => ED.dupLine(),
        'ed.undo':          () => US.undo(),
        'ed.redo':          () => US.redo(),
        'fs.inc':           () => FS.inc(),
        'fs.dec':           () => FS.dec(),
        'app.stats':        () => STATS.show(),
        'app.translator':   () => Translator.show(),
        'app.fmtPanel':     () => FP.show(),
        'app.previewWin':   () => PW.open(),
        'app.previewPPT':   () => PW.openSlide(),
        'app.researchMode': () => App.toggleRM(),
        'app.cite':         () => App.showCite(),
        'app.scholar':      () => Scholar.show(),
        'app.aiPPT':        () => AiPPT.open(),
        'app.save':         () => App.smartSave(),
        'app.find':         () => App.toggleFind(),
        'app.toggleMultiEditBar': () => App.toggleMultiEditBar(),
        'app.multiEditApply': () => { if (el('multi-edit-bar') && el('multi-edit-bar').classList.contains('vis')) App.multiEditApply(); },
        'app.hotkeys':      () => App.showHK(),
        'app.themeDark':    () => App.setTheme('dark'),
        'app.themeLight':   () => App.setTheme('light'),
        'app.themeToggle':  () => App.toggleTheme(),
        'app.lock':         () => { if (typeof AppLock !== 'undefined') AppLock.lockNow(); },
        'app.nbsp':         () => { const ed = el('editor'), s = ed.selectionStart; ins(ed, s, ed.selectionEnd, '&nbsp;'); US.snap(); },
        'tab.new':          () => TM.newTab(),
        'tab.open':         () => TM.openFile(),
        'tab.saveAll':      () => TM.saveAll(),
        'tab.close':        () => { const t = TM.getActive(); if (t) TM.closeTab(t.id); },
        'tab.print':        () => App.printDoc(),
        'edit.deleteLine':  () => App.deleteLine(),
        'ed.strikethrough': () => EdCommands.strikethrough(),
        'ed.underline':     () => EdCommands.underline(),
        'ed.sup':           () => EdCommands.sup(),
        'ed.sub':           () => EdCommands.sub(),
        'ed.highlight':     () => EdCommands.highlight(),
        'ed.hr':            () => EdCommands.hr(),
        'ed.ul':            () => EdCommands.ul(),
        'ed.ol':            () => EdCommands.ol(),
        'ed.textToList':    () => { ED.textToList(); },
        'ed.textToNumberedList': () => { ED.textToNumberedList(); },
        'ed.task':          () => EdCommands.task(),
        'ed.link':          () => EdCommands.link(),
        'ed.image':         () => EdCommands.image(),
        'ed.indentIn':      () => EdCommands.indentIn(),
        'ed.indentOut':     () => EdCommands.indentOut(),
        'ed.textToTable':   () => ED.textToTable(),
        'ed.mdTableToHtml': () => ED.mdTableToHtml(),
        'tab.prev':         () => { const tabs=TM.getAll(); const i=tabs.findIndex(t=>t.id===TM.getActive()?.id); if(i>0) TM.switchTab(tabs[i-1].id); },
        'tab.next':         () => { const tabs=TM.getAll(); const i=tabs.findIndex(t=>t.id===TM.getActive()?.id); if(i<tabs.length-1) TM.switchTab(tabs[i+1].id); },
        'app.insertDate':   () => App.insertDate(),
        'app.makeImageLink': () => App.makeImageLink(),
        'app.openSelectionAsLink': () => App.openSelectionAsLink(),
        'app.insertAuthorInfo': () => { if (typeof AuthorInfo !== 'undefined') AuthorInfo.insertIntoEditor(); },
        'app.charMap':      () => CharMap.show(),
        'app.syncToggle':   () => SS.toggle(),
        'app.ghCommit':     () => { const t=TM.getActive(); if(t&&t.ghPath) App._openGHSaveModal(t); },
        'app.pullGH':       () => FM.pullFromGitHub(),
        'app.pushGH':       () => FM.syncToGitHub(),
        'edit.deleteLine':  () => App.deleteLine(),
    };

    /* ── 기본 단축키 데이터 ─────────────────────────────────────
       keys : 표시용 문자열 (사용자가 편집)
       action: ACTION_MAP 키 — 이 값이 실제 동작을 결정한다.     */
    const DEFAULT_DATA = [
        {
            section: '문서 구조', items: [
                { desc: 'H1', keys: 'Ctrl + Alt + 1', action: 'ed.h1' },
                { desc: 'H2', keys: 'Ctrl + Alt + 2', action: 'ed.h2' },
                { desc: 'H3', keys: 'Ctrl + Alt + 3', action: 'ed.h3' },
                { desc: '페이지 나누기', keys: 'Ctrl + Enter', action: 'ed.pageBreak' },
                { desc: '줄바꿈 (<br>)', keys: 'Ctrl + Shift + Enter', action: 'ed.lineBreak' },
            ]
        },
        {
            section: '표 편집', items: [
                { desc: '텍스트 → 표 변환', keys: 'Alt + 7', action: 'ed.textToTable' },
                { desc: '마크다운 표 → HTML 표', keys: 'Alt + H', action: 'ed.mdTableToHtml' },
                { desc: '표 삽입', keys: 'Alt + 8', action: 'ed.table' },
                { desc: '행 추가', keys: 'Alt + 9', action: 'ed.tableRow' },
                { desc: '열 추가', keys: 'Alt + 0', action: 'ed.tableCol' },
                { desc: '가로 병합 (colspan)', keys: 'Alt + Shift + H', action: 'ed.mergeH' },
                { desc: '세로 병합 (rowspan)', keys: 'Alt + Shift + V', action: 'ed.mergeV' },
                { desc: 'HTML 표 들여쓰기 정돈', keys: 'Tidy 버튼', action: '' },
            ]
        },
        {
            section: '텍스트 서식', items: [
                { desc: 'Smart Bold', keys: 'Ctrl + B', action: 'ed.bold' },
                { desc: '기울임꼴', keys: 'Ctrl + I', action: 'ed.italic' },
                { desc: '인용구', keys: 'Ctrl + .', action: 'ed.bquote' },
                { desc: '인라인 코드 `code`', keys: 'Alt + V', action: 'ed.inlineCode' },
                { desc: '코드 직접 삽입 (마지막 언어)', keys: 'Alt + C', action: 'ed.codeBlock' },
                { desc: '글자 크기 키우기', keys: 'Shift + Alt + .', action: 'fs.inc' },
                { desc: '글자 크기 줄이기', keys: 'Shift + Alt + ,', action: 'fs.dec' },
            ]
        },
        {
            section: '레이아웃 / 정렬', items: [
                { desc: '왼쪽 정렬', keys: 'Shift + Alt + L', action: 'ed.alignLeft' },
                { desc: '가운데 정렬', keys: 'Shift + Alt + C', action: 'ed.alignCenter' },
                { desc: '오른쪽 정렬', keys: 'Shift + Alt + R', action: 'ed.alignRight' },
                { desc: 'Split 보기', keys: 'Alt + 1', action: 'view.split' },
                { desc: '에디터만', keys: 'Alt + 2', action: 'view.editor' },
                { desc: '미리보기만', keys: 'Alt + 3', action: 'view.preview' },
                { desc: '전체 다크/라이트 토글', keys: 'Alt + 4', action: 'app.themeToggle' },
            ]
        },
        {
            section: '편집', items: [
                { desc: '줄 위로 이동', keys: 'Alt + ArrowUp', action: 'ed.moveUp' },
                { desc: '줄 아래로 이동', keys: 'Alt + ArrowDown', action: 'ed.moveDown' },
                { desc: '줄 / 선택 복제', keys: 'Shift + Alt + ArrowDown', action: 'ed.dupLine' },
                { desc: '실행 취소', keys: 'Ctrl + Z', action: 'ed.undo' },
                { desc: '다시 실행', keys: 'Ctrl + Shift + Z', action: 'ed.redo' },
                { desc: '다시 실행 (대체)', keys: 'Ctrl + Y', action: 'ed.redo' },
                { desc: '현재 줄 삭제', keys: 'Alt + Y', action: 'edit.deleteLine' },
            ]
        },
        {
            section: '삽입 / 도구', items: [
                { desc: '오늘 날짜 삽입', keys: 'Shift + Alt + D', action: 'app.insertDate' },
                { desc: '작성자 정보 삽입', keys: 'Shift + Alt + A', action: 'app.insertAuthorInfo' },
                { desc: '이미지 링크 만들기', keys: 'Alt + I', action: 'app.makeImageLink' },
                { desc: '선택 텍스트 → 하이퍼링크 새창', keys: 'Shift + Alt + I', action: 'app.openSelectionAsLink' },
                { desc: '인용 삽입', keys: 'Ctrl + Shift + C', action: 'app.cite' },
                { desc: '각주 삽입', keys: 'Shift + Alt + N', action: 'ed.footnote' },
                { desc: 'APA 통계 삽입', keys: 'Shift + Alt + 9', action: 'app.stats' },
                { desc: '번역기', keys: 'Shift + Alt + G', action: 'app.translator' },
                { desc: '서식 패널 (크기·색·형광펜)', keys: 'Alt + L', action: 'app.fmtPanel' },
                { desc: '새창 미리보기', keys: 'Ctrl + Shift + P', action: 'app.previewWin' },
                { desc: '슬라이드 모드로 새창 열기', keys: 'Ctrl + Shift + T', action: 'app.previewPPT' },
                { desc: '저장 다이얼로그', keys: 'Ctrl + S', action: 'app.save' },
                { desc: '찾기 / 바꾸기', keys: 'Ctrl + H', action: 'app.find' },
                { desc: '다중선택 편집 (선택 시 메뉴 열기)', keys: 'Ctrl + Alt + K', action: 'app.toggleMultiEditBar' },
                { desc: '다중선택 편집 (선택→바꾸기 전체 적용)', keys: 'Ctrl + Enter', action: 'app.multiEditApply' },
                { desc: 'Research Mode', keys: 'Ctrl + Shift + R', action: 'app.researchMode' },
                { desc: 'Scholar 검색', keys: 'Ctrl + Shift + G', action: 'app.scholar' },
                { desc: 'AI PPT (ScholarSlide)', keys: 'Ctrl + Shift + L', action: 'app.aiPPT' },
                { desc: '단축키 목록 & 설정', keys: 'Alt + ?', action: 'app.hotkeys' },
                { desc: '문자표 (특수문자)', keys: 'Ctrl + Q', action: 'app.charMap' },
                { desc: '에디터-PV 스크롤 동기화', keys: 'Shift + Alt + M', action: 'app.syncToggle' },
                { desc: '앱 잠금', keys: 'Ctrl + G', action: 'app.lock' },
                { desc: '새 탭', keys: 'Ctrl + N', action: 'tab.new' },
                { desc: '파일 열기', keys: 'Ctrl + O', action: 'tab.open' },
                { desc: '탭 닫기', keys: 'Ctrl + W', action: 'tab.close' },
                { desc: '전체 저장', keys: 'Ctrl + Shift + S', action: 'tab.saveAll' },
                { desc: '인쇄', keys: 'Ctrl + P', action: 'tab.print' },
                { desc: '줄바꿈 공백 (&nbsp;)', keys: 'Ctrl + Shift + Space', action: 'app.nbsp' },
            ]
        },
        {
            section: '추가 서식', items: [
                { desc: '취소선 (~~)', keys: '', action: 'ed.strikethrough' },
                { desc: '밑줄', keys: '', action: 'ed.underline' },
                { desc: '위첨자', keys: '', action: 'ed.sup' },
                { desc: '아래첨자', keys: '', action: 'ed.sub' },
                { desc: '형광펜 (==)', keys: '', action: 'ed.highlight' },
                { desc: '수평선', keys: '', action: 'ed.hr' },
                { desc: '순서없는 목록', keys: '', action: 'ed.ul' },
                { desc: '텍스트→목록 항목 (•)', keys: 'Alt + 5', action: 'ed.textToList' },
                { desc: '텍스트→숫자 목록 (1. 2. 3.)', keys: 'Alt + 6', action: 'ed.textToNumberedList' },
                { desc: '체크리스트', keys: '', action: 'ed.task' },
                { desc: '링크 삽입', keys: '', action: 'ed.link' },
                { desc: '이미지 삽입', keys: '', action: 'ed.image' },
                { desc: '들여쓰기', keys: '', action: 'ed.indentIn' },
                { desc: '내어쓰기', keys: '', action: 'ed.indentOut' },
            ]
        },
        {
            section: '탭 이동', items: [
                { desc: '이전 탭', keys: '', action: 'tab.prev' },
                { desc: '다음 탭', keys: '', action: 'tab.next' },
            ]
        },
        {
            section: 'GitHub 연동', items: [
                { desc: 'GitHub 커밋 (현재 파일)', keys: '', action: 'app.ghCommit' },
                { desc: 'GitHub Pull', keys: '', action: 'app.pullGH' },
                { desc: 'GitHub Push', keys: '', action: 'app.pushGH' },
            ]
        },
    ];

    let data = [];
    let editMode = false;

    function load() {
        try {
            const saved = localStorage.getItem(STORAGE_KEY);
            if (saved) {
                const parsed = JSON.parse(saved);
                // action 필드가 없는 구버전(v1) 데이터 → 기본값으로 초기화
                const hasAction = parsed.some(g => g.items && g.items.some(i => i.action !== undefined));
                data = hasAction ? parsed : JSON.parse(JSON.stringify(DEFAULT_DATA));
            } else {
                data = JSON.parse(JSON.stringify(DEFAULT_DATA));
            }
        } catch (e) {
            data = JSON.parse(JSON.stringify(DEFAULT_DATA));
        }
    }

    function save() {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) { }
    }

    /* ── keys 표시 문자열 → hkKey() 정규화 형식 변환 ───────────
       'Ctrl + Shift + Z'  →  'C+S+Z'
       'Alt + ArrowUp'     →  'A+ArrowUp'
       'Tidy 버튼' 같은 비키 항목 → null                         */
    function parseHotkey(keysStr) {
        if (!keysStr) return null;
        // modifier 없이 '버튼', 'Tidy' 등 단순 텍스트는 키 항목이 아님
        const hasMod = /ctrl|shift|alt|cmd|option/i.test(keysStr);
        if (!hasMod && !keysStr.includes('+')) return null;
        const tokens = keysStr.split('+').map(s => s.trim()).filter(Boolean);
        if (tokens.length === 0) return null;
        const mods = [];
        let mainKey = null;
        for (const t of tokens) {
            const lo = t.toLowerCase();
            if (lo === 'ctrl' || lo === 'cmd') mods.push('C');
            else if (lo === 'shift') mods.push('S');
            else if (lo === 'alt' || lo === 'option') mods.push('A');
            else mainKey = t;
        }
        if (!mainKey) return null;
        // 특수 키 이름은 그대로, 단일 문자는 대문자로
        if (mainKey.length === 1) mainKey = mainKey.toUpperCase();
        // 'Space' → 공백 문자로 (hkKey는 e.key=' '를 ' '.toUpperCase()=' '로 반환)
        if (mainKey.toLowerCase() === 'space') mainKey = ' ';
        return [...mods, mainKey].join('+');
    }

    /* ── Shift 조합 시 브라우저 e.key 변환 대응 ────────────────
       Shift+9 → e.key='(' 이므로 canonical 'S+A+9' 외에
       'S+A+(' 도 함께 등록해야 매칭된다.                         */
    const SHIFT_CHAR = {
        '1':'!','2':'@','3':'#','4':'$','5':'%',
        '6':'^','7':'&','8':'*','9':'(','0':')',
        '-':'_','=':'+',
        ';':':',',':'<','.':'>','/':'?',
    };

    function getMatchKeys(keysStr) {
        const base = parseHotkey(keysStr);
        if (!base) return [];
        const results = [base];
        // Shift가 포함된 단일 문자 키: 실제 e.key 변환값도 추가
        const tokens = keysStr.split('+').map(s => s.trim());
        const hasShift = tokens.some(t => t.toLowerCase() === 'shift');
        const mainKey = tokens.find(t => !['ctrl','cmd','shift','alt','option'].includes(t.toLowerCase()));
        if (hasShift && mainKey && mainKey.length === 1) {
            const shifted = SHIFT_CHAR[mainKey.toLowerCase()];
            if (shifted) {
                // 'C+S+9' → 'C+S+(' 형태로 교체
                const alt = base.slice(0, base.lastIndexOf('+') + 1) + shifted.toUpperCase();
                if (alt !== base) results.push(alt);
            }
        }
        return results;
    }

    /* ── dispatch 테이블 빌드 ───────────────────────────────────
       data를 순회하며 { hkKey형식: fn } 매핑을 생성한다.
       save() 또는 resetDefault() 후에 반드시 호출해야 한다.      */
    let _dispatch = {};

    function rebuild() {
        _dispatch = {};
        data.forEach(group => {
            (group.items || []).forEach(item => {
                if (!item.action || !item.keys) return;
                const fn = ACTION_MAP[item.action];
                if (!fn) return;
                getMatchKeys(item.keys).forEach(k => { _dispatch[k] = fn; });
            });
        });
        /* 역방향 맵 갱신 (handleKey의 getActionId에서 사용) */
        _fnToId = new Map();
        Object.entries(ACTION_MAP).forEach(([id, fn]) => { _fnToId.set(fn, id); });
    }

    function getDispatch() { return _dispatch; }
    function getActionMap() { return ACTION_MAP; }

    /* fn → actionId 역방향 조회 캐시 (rebuild() 내에서 갱신) */
    let _fnToId = new Map();

    function getActionId(fn) { return _fnToId.get(fn) || null; }

    function render() {
        const wrap = el('hk-list-wrap');
        wrap.innerHTML = '';
        const actionKeys = Object.keys(ACTION_MAP);
        data.forEach((group, gi) => {
            // 섹션 헤더
            const sec = document.createElement('div');
            sec.className = 'hk-s';
            sec.style.cssText = 'display:flex;align-items:center;gap:6px';
            if (editMode) {
                const inp = document.createElement('input');
                inp.className = 'hk-editable desc';
                inp.style.cssText = 'font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--ac);flex:1';
                inp.value = group.section;
                inp.oninput = () => { data[gi].section = inp.value; };
                const delSec = document.createElement('button');
                delSec.className = 'hk-del-btn';
                delSec.title = '섹션 삭제';
                delSec.textContent = '✕';
                delSec.onclick = () => { data.splice(gi, 1); render(); };
                sec.appendChild(inp);
                sec.appendChild(delSec);
            } else {
                sec.textContent = group.section;
            }
            wrap.appendChild(sec);

            // 그리드
            const grid = document.createElement('div');
            grid.className = editMode ? 'hk-grid edit-mode' : 'hk-grid';
            grid.style.marginBottom = '4px';

            group.items.forEach((item, ii) => {
                const row = document.createElement('div');
                if (editMode) {
                    row.className = 'hk-item-edit';

                    const descInp = document.createElement('input');
                    descInp.className = 'hk-editable desc';
                    descInp.value = item.desc;
                    descInp.oninput = () => { data[gi].items[ii].desc = descInp.value; };

                    const keysInp = document.createElement('input');
                    keysInp.className = 'hk-editable keys';
                    keysInp.value = item.keys;
                    keysInp.placeholder = 'Ctrl + Shift + X';
                    keysInp.title = '예: Ctrl + Z  |  Shift + Alt + ArrowDown  |  Alt + 9';
                    keysInp.oninput = () => { data[gi].items[ii].keys = keysInp.value; };

                    // action 드롭다운 — 핵심: 어떤 기능과 연결할지 선택
                    const actSel = document.createElement('select');
                    actSel.className = 'hk-editable';
                    actSel.style.cssText = 'font-size:10px;padding:2px 4px;background:var(--bg4);color:var(--tx2);border:1px solid var(--bd);border-radius:3px;min-width:90px;max-width:150px;flex-shrink:0';
                    actSel.title = '이 키에 연결할 기능';
                    const emptyOpt = document.createElement('option');
                    emptyOpt.value = '';
                    emptyOpt.textContent = '— 표시용 —';
                    actSel.appendChild(emptyOpt);
                    actionKeys.forEach(ak => {
                        const opt = document.createElement('option');
                        opt.value = ak;
                        opt.textContent = ak;
                        opt.selected = item.action === ak;
                        actSel.appendChild(opt);
                    });
                    actSel.onchange = () => { data[gi].items[ii].action = actSel.value; };

                    const del = document.createElement('button');
                    del.className = 'hk-del-btn';
                    del.title = '행 삭제';
                    del.innerHTML = '🗑';
                    del.onclick = () => { data[gi].items.splice(ii, 1); render(); };

                    row.appendChild(descInp);
                    row.appendChild(keysInp);
                    row.appendChild(actSel);
                    row.appendChild(del);
                } else {
                    row.className = 'hk-item';
                    const keys = item.keys.split('+').map(k => k.trim()).filter(Boolean);
                    row.innerHTML = `<span class="hk-desc">${item.desc}</span><div class="hk-keys">${keys.map(k => `<kbd>${k}</kbd>`).join('')}</div>`;
                }
                grid.appendChild(row);
            });

            // 편집 모드: 이 섹션에 행 추가 버튼
            if (editMode) {
                const addRow = document.createElement('div');
                addRow.style.cssText = 'padding:2px 6px;';
                const addBtn = document.createElement('button');
                addBtn.className = 'btn btn-g btn-sm';
                addBtn.style.cssText = 'font-size:10px;padding:2px 7px;width:100%;opacity:.7';
                addBtn.textContent = '+ 이 섹션에 행 추가';
                addBtn.onclick = () => { data[gi].items.push({ desc: '새 항목', keys: '', action: '' }); render(); };
                addRow.appendChild(addBtn);
                grid.appendChild(addRow);