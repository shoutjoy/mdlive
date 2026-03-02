/* ScrollSync — 문서 내 스크롤 동기화 스텁 (SS에 위임) */
const ScrollSync = (() => {
    function onEditor() { /* SS.init()에서 이미 에디터 scroll 이벤트 처리 */ }
    function onPreview() { /* SS.init()에서 이미 미리보기 scroll 이벤트 처리 */ }
    function init() { /* SS.init()에 위임 */ }
    return { onEditor, onPreview, init };
})();
