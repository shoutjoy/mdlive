/* STATS — APA 통계 삽입 (t-test, ANOVA 등) → js/ui/stats.js
   의존: el, App, US (전역) */

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
