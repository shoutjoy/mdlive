/* ═══════════════════════════════════════════════════════════
   LOCAL FS — File System Access API 헬퍼
   의존: 없음 (브라우저 FileSystemFileHandle)
   사용: App.smartSave, 탭 로컬 저장 등
═══════════════════════════════════════════════════════════ */
const LocalFS = {
    /**
     * FileSystemFileHandle에 문자열 내용 쓰기
     * @param {FileSystemFileHandle} handle
     * @param {string} content
     * @returns {Promise<void>}
     */
    async writeToHandle(handle, content) {
        if (!handle || typeof handle.createWritable !== 'function') throw new Error('유효한 파일 핸들이 아닙니다');
        const wr = await handle.createWritable();
        await wr.write(content);
        await wr.close();
    },

    /**
     * FileSystemFileHandle에서 텍스트 읽기
     * @param {FileSystemFileHandle} handle
     * @returns {Promise<string>}
     */
    async readFromHandle(handle) {
        if (!handle || typeof handle.getFile !== 'function') throw new Error('유효한 파일 핸들이 아닙니다');
        const file = await handle.getFile();
        return file.text();
    }
};
