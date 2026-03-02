/* AiPPT — ScholarSlide 연동 (MD 내용 → 슬라이드 변환) */
const AiPPT = (() => {
    const SITE     = 'https://shoutjoy.github.io/sholarslide/';
    const ORIGIN   = 'https://shoutjoy.github.io';
    const WIN_NAME = 'scholarslide_ppt';
    const WIN_OPTS = 'width=1280,height=900,left=80,top=60,resizable=yes,scrollbars=yes';
    let _win = null;
    let _pendingText = null;

    function _send(text) {
        if (!_win || _win.closed) return false;
        try {
            _win.postMessage({ type: 'mdpro_text', text }, '*');
            return true;
        } catch (e) { return false; }
    }

    function _scheduleRetry(text) {
        [200, 600, 1200, 2200, 3500].forEach(ms => {
            setTimeout(() => {
                if (_pendingText === text) _send(text);
            }, ms);
        });
    }

    async function open() {
        const edEl = document.getElementById('editor');
        const text = edEl ? edEl.value.trim() : '';
        if (!text) { App._toast('⚠ 에디터에 내용이 없습니다'); return; }

        _pendingText = text;

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

        const isReuse = _win && !_win.closed;
        if (isReuse) {
            _win.focus();
            _send(text);
            _scheduleRetry(text);
        } else {
            _win = window.open(SITE, WIN_NAME, WIN_OPTS);
            if (_win) {
                try {
                    _win.addEventListener('load', () => {
                        setTimeout(() => _send(text), 100);
                    });
                } catch (e) {}
                _scheduleRetry(text);
            }
        }

        App._toast(
            copied
                ? '📊 ScholarSlide 전송 중…\n텍스트가 자동으로 입력됩니다.\n(안 되면 Ctrl+V 후 ✅ 텍스트 로드 클릭)'
                : '📊 ScholarSlide를 열었습니다.\n텍스트를 수동으로 붙여넣어 주세요.',
            4000
        );
    }

    window.addEventListener('message', (e) => {
        if (e.data && e.data.type === 'mdpro_ready' && _pendingText) {
            _send(_pendingText);
        }
    });

    return { open };
})();
