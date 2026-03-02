#imgpv)# index.js 리팩토링 계획

## 목표
- 단일 18000줄+ index.js를 기능 단위 모듈로 분리
- 기존 기능 100% 유지, 전역 App/TM/US 유지
- 점진적 진행으로 오류·Cursor 부담 최소화

## 최근 진행된 UI/사이드바 개선 (완료)

다음 작업은 **index.html / style.css / index.js** 에 반영 완료되었다.

### 미리보기(PV) Trans 버튼
- **내부 PV** (pv-hdr): 새창 PV와 동일하게 **↔ Trans** 버튼 추가. 클릭 시 A4 가로/세로 전환.
- **index.html**: pv-hdr에 `id="pv-trans-btn"`, `onclick="PV.toggleTrans()"` 버튼 추가.
- **index.js**: PV 모듈에 `_transOn`, `toggleTrans()` 추가. PPT 모드에서도 가로/세로 기준치 반영.
- **style.css**: `body.trans-mode .preview-page { width: 297mm; min-height: 210mm; padding: 15mm 22mm; }` 추가.

### 사이드바 파일 목록 — 버튼 항상 표시
- **용량·날짜·푸시·이동·삭제**가 파일명을 가리지 않도록 레이아웃 조정.
- **style.css**:
  - `.file-item` / `.file-item-name`: `min-width: 0`, `flex: 1 1 0%`로 파일명이 말줄임되며 우선 표시.
  - `.file-item-meta`: `max-width: 72px` + `overflow: hidden` + `text-overflow: ellipsis`로 메타가 파일명을 덮지 않음.
  - `.file-share-btn`: `opacity: 0.9` (호버 없이도 푸시 버튼 표시).
  - `.file-move-btn` / `.folder-del-btn`: 기본 `color`를 반투명으로 설정해 항상 표시.
- **#sidebar**: `container-type: inline-size; container-name: sidebar;` 추가 (반응형 숨김용).

### 사이드바 좁을 때 유동적 숨김
- **style.css** — `@container sidebar` 단계별 적용:
  - **260px 이하**: `.file-item-meta` 숨김 (용량·날짜).
  - **220px 이하**: `.file-item-meta` + `.file-share-btn` (푸시 🐙📤) 숨김.
  - **180px 이하**: 메타 + 푸시 + `.file-move-btn` + `.file-del-btn` 모두 숨김 → 아이콘 + 파일명만 표시.
- 사이즈를 줄일 때 파일명과 겹치기 시작하는 요소부터 순서대로 숨겨지도록 유동적으로 동작.

### 입력창·미리보기와 구분
- **#main**: `border-left: 1px solid var(--bd)` 추가로 사이드바(로컬/깃허브 폴더)와 입력·미리보기 영역이 시각적으로 구분됨.

### 폴더 행
- **.ft-folder-name**: `flex: 1 1 0%; min-width: 0` 적용해 좁을 때 폴더명 말줄임 표시.

---

## 현재 스크립트 로드 순서 (index.html)
1. marked.min.js, mathjax, **js/markdown/setup.js**
2. (본문 하단) JSZip 등 외부 라이브러리
3. `js/utils/dom.js`
4. **js/core/app-lock.js**, **js/core/ai-apikey.js**, **js/core/scholar-apikey.js** — 잠금·API키 (2단계)
5. `js/utils/normalize.js` ~ `js/editor/font-size.js`, `js/storage/autosave.js` ~ `js/data/templates.js`
6. `js/core/detect-errors.js`, **js/core/render.js**, **js/core/state.js**, **js/core/events.js**
7. **js/markdown/parser.js**, **js/markdown/preview.js**, **js/scholar/scholar.js** — Scholar (2단계)
8. **js/markdown/slide-mode.js**, **js/markdown/pv.js**, **js/core/pw.js**, **js/core/tm.js**, **js/core/sb.js**, **js/storage/fm.js**
9. **js/github/api.js**, **js/github/history.js**, **js/github/sync.js**
10. `index.js` — App 및 나머지 전부

## 완료된 1차 분리
- **js/utils/dom.js**: `el`, `formatDateTime`, `getCL`, `dlBlob` (index.js에서 제거됨)
- **js/editor/undo.js**: `US` (snap, undo, redo, _getState, _setState) (index.js에서 제거됨)
- **js/utils/normalize.js**: `normalizeNFC()` 스텁 (추후 적용)
- **js/utils/debounce.js**: `debounce(fn, ms)` 스텁 (추후 적용)

## 완료된 2·3단계
- **2단계**: normalize.js, debounce.js 스크립트 로드 연결 완료
- **js/editor/commands.js**: `EdCommands` (strikethrough, underline, sup, sub, highlight, hr, ul, ol, task, link, image, indentIn, indentOut) — ACTION_MAP에서 호출로 전환
- **js/editor/cursor.js**: `CursorUI.updCursor()`, `CursorUI.updFmtBtns()` — App.updCursor/updFmtBtns는 위임만
- **js/markdown/setup.js**: marked 설정 (setOptions, Renderer heading/link) — index.js 상단 블록 제거
- **js/markdown/toc.js**: TOC (build, go, insertTOC) — index.js에서 약 170줄 제거
- **4단계 core**: **js/core/render.js** — Render.run(md, title), App.render()는 위임만
- **js/core/state.js** — State {} 스텁 (추후 전역 상태 이동용)
- **js/core/events.js** — CoreEvents.init(), App.init()에서 호출 (에디터/문서 이벤트 바인딩)
- **js/editor/line-numbers.js** — LN (update, toggle, init) — index.js에서 약 18줄 제거
- **js/storage/autosave.js** — AS (load, save) — index.js에서 약 27줄 제거
- **js/storage/localfs.js** — LocalFS.writeToHandle, readFromHandle (App.smartSave에서 사용)
- **js/storage/persistence.js** — Persist.save / Persist.load (TM 탭 세션 영속, 폴백 인라인 유지)
- **js/data/templates.js** — TMPLS (약 410줄 분리, index.js 메모리·로드 부담 감소)
- **js/markdown/parser.js** — mdRender, splitPages, parseSlideContent, parseMarkdownToSlides (약 75줄 분리, PR 등에서 전역 사용)
- **js/markdown/preview.js** — PR (Preview Renderer, 약 100줄 분리, Render.run에서 사용)
- **js/github/api.js** — GHApi (base, fetch), GH에서 사용
- **js/github/history.js** — GHHistory (loadHistory, refreshHistory, filterHistory), GH에서 위임
- **js/github/sync.js** — GH 전체 (약 1975줄 분리, restore, refresh, saveFile 등)
- **js/core/app-lock.js** — AppLock (앱 잠금, GH/PV 설정 암호화)
- **js/core/ai-apikey.js** — AiApiKey (Google AI API 키 암호화)
- **js/core/scholar-apikey.js** — ScholarApiKey (SerpAPI 키 암호화)
- **js/scholar/scholar.js** — Scholar (학술 검색, APA 가이드, mdRender 의존)
- **js/image/pv-image-resize.js** — PvImageResize (PV 창 이미지 마우스 크기 조절, 클릭 시 핸들, Shift 비율 유지, 에디터 동기화)

## 원칙
1. **새 기능은 index.js에 누적하지 않음** — 기능별로 `js/` 카테고리 폴더에 분리 (core, editor, image, markdown, cite, ai, github, storage, ui, utils)
2. 한 번에 많이 옮기지 말 것
3. 각 단계마다 동작 확인 (실행/테스트)
4. App 전역 의존은 점진적으로만 제거
5. 모듈(import/export) 전환은 나중에 — 당분간 전역 스크립트 여러 개로 분리

---

## 다음 단계 제안 (우선순위)

### 2단계: 추가 유틸 분리
- index.js에서 `normalizeNFC` 사용처를 찾아 `js/utils/normalize.js` 로드 후 점진 적용 (선택)
- input 이벤트 등에 `debounce` 적용 시 `js/utils/debounce.js` 로드 후 사용

### 3단계: editor/ commands·cursor
- **editor/commands.js**: strikethrough, underline, sup, sub, highlight, ul, ol, hr 등 (export function 형태로 정리 후 별 파일로 이동)
- **editor/cursor.js**: updCursor, SS.onCursor, selection 관련 — 의존성 파악 후 분리

### 4단계: core (state / render / events)
- **core/state.js**: activeFile, _allFiles, _searchQ, _currentGitHubPath, SHA map, history cache 등 전역 상태
- **core/render.js**: App.render 내부를 renderEditor, renderPreview, renderFileList, renderTabs 등으로 분리
- **core/events.js**: editor input/keydown/scroll/selectionchange 바인딩, App.init()에서 initEvents() 호출

### 5단계: GitHub·storage·markdown
- **github/api.js**, **github/sync.js**, **github/history.js**
- **storage/localfs.js**
- **markdown/parser.js**, **markdown/preview.js**

각 단계는 한 번에 하나의 파일만 새로 만들고, index.js에서 해당 블록 제거 → 스크립트 태그 추가 → 동작 확인 후 진행 권장.

---

## 분리 진행 체크리스트 (상세)

**목적**: 진행 시 항목별로 체크하며 분리 작업을 추적한다.  
**현재 index.js**: 약 11,000줄 (1단계 분리 후, 목표: 1,000줄 이하)  
**체크 방법**: 해당 항목 완료 시 표의 `[ ]` 를 `[x]` 로 수동 변경한다.

### ⚠ 메모리 절약 우선순위 (OOM 방지)

**원칙**: Cursor에서 index.js 전체 로드 시 OOM이 나면, **줄 수가 적은 블록부터** 분리해 index.js를 먼저 가볍게 만든다. 한 번에 하나만 진행하고, 대형 블록은 index.js가 충분히 줄어든 뒤 진행한다.

**가벼운 순서 (추천 진행 순서)**  
| 순서 | 항목 | 예상 줄 수 | 저장 위치 | 비고 |
|------|------|------------|-----------|------|
| 1 | **EZ** | ~38 | js/ui/ez.js | 에디터 글자 크기 ✓ |
| 2 | **CiteModal** | ~15 | js/ui/cite-modal.js | 참고문헌 모달 최대화 ✓ |
| 3 | **DelConfirm** | ~62 | js/ui/del-confirm.js | 삭제 확인 모달 ✓ |
| 4 | **EditorLineHighlight** | ~68 | js/editor/line-highlight.js | 현재 줄 하이라이트 ✓ |
| 5 | **EditorAutoPair** | ~72 | js/editor/auto-pair.js | 괄호 자동 쌍 ✓ |
| 6 | **ColorPicker** | ~78 | js/utils/color-picker.js | 색상 선택기 ✓ |
| 7 | **SS** (Scroll Sync) | ~195 | js/editor/scroll-sync.js | 에디터↔미리보기 스크롤 (파일만, index.html 미연결) |
| 8 | **IPPT** | ~90 | js/editor/ippt.js | PV PPT 드로잉 ✓ |
| … | (이후 3·4·5·6단계 표 참고) | | | 중대형은 index.js 축소 후 |

**작업 시**: 한 번에 **한 블록만** 제거·파일 생성·스크립트 추가 후 저장하고, 필요 시 Cursor 창을 다시 열어 계속 진행한다.

---
1. [ ] index.js에서 해당 블록의 **시작·끝 줄** 확인
2. [ ] 새 파일 생성 (`js/폴더/파일명.js`), 블록 복사 후 `el`/전역 의존성 유지
3. [ ] index.js에서 해당 블록 **삭제**, 주석 `/* XXX → js/폴더/파일명.js */` 추가
4. [ ] index.html에 `<script src="js/폴더/파일명.js"></script>` **로드 순서** 반영
5. [ ] 브라우저에서 **동작 확인** 후 해당 항목 체크

---

### 1단계: 미리보기·탭·파일 (핵심 플로우)

| # | 항목 | 저장 위치 | 내용 요약 | 예상 줄 수 | 의존성 | 완료 |
|---|------|-----------|-----------|------------|--------|------|
| 1.1 | **SlideMode** | `js/markdown/slide-mode.js` | 슬라이드 모드 토글, ScholarSlide 연동 | ~25 | PR, App | [x] |
| 1.2 | **PV** (미리보기 확대/축소) | `js/markdown/pv.js` | scale, PPT 모드, fontUp/Down, refresh | ~360 | el, PR | [x] |
| 1.3 | **PW** (Preview Window) | `js/core/pw.js` | 새 창 미리보기, sync, checkClosed, pushScroll | ~1115 | el, Render, LN, SS | [x] |
| 1.4 | **TM** (Tab Manager) | `js/core/tm.js` | 탭 CRUD, persist, renderTabs, _pushToEditor | ~450 | el, US, Persist, GH | [x] |
| 1.5 | **SB** (Source Bar) | `js/core/sb.js` | 로컬/GitHub 소스 전환, switchSource | ~40 | GH, FM | [x] |
| 1.6 | **FM** (File Manager) | `js/storage/fm.js` | 로컬 폴더 선택, IDB 캐시, syncToGitHub, pullFromGitHub | ~1620 | el, GH, TM, LocalFS, DelConfirm | [x] |

---

### 2단계: 잠금·API키·학술 (설정·인증)

| # | 항목 | 저장 위치 | 내용 요약 | 예상 줄 수 | 의존성 | 완료 |
|---|------|-----------|-----------|------------|--------|------|
| 2.1 | **AppLock** | `js/core/app-lock.js` | 앱 잠금, PBKDF2+AES-GCM, GH/PV 설정 암호화 | ~400 | localStorage | [x] |
| 2.2 | **AiApiKey** | `js/core/ai-apikey.js` | Google AI API 키 암호화 저장 | ~60 | - | [x] |
| 2.3 | **ScholarApiKey** | `js/core/scholar-apikey.js` | Scholar API 키 저장 | ~60 | - | [x] |
| 2.4 | **Scholar** | `js/scholar/scholar.js` | 학술 검색, RISS/KCI/DBpia 등, 검색·인용 | ~390 | GHApi 또는 fetch | [x] |

---

### 3단계: 에디터 보조·UI (커서·스크롤·모달)

| # | 항목 | 저장 위치 | 내용 요약 | 예상 줄 수 | 의존성 | 완료 |
|---|------|-----------|-----------|------------|--------|------|
| 3.1 | **SS** (Scroll Sync) | `js/editor/scroll-sync.js` | 에디터↔미리보기 스크롤 동기화 | ~190 | el, PW | [x] |
| 3.2 | **IPPT** | `js/editor/ippt.js` | 인라인 PPT 관련 | ~90 | - | [x] |
| 3.3 | **CP** (Clipboard?) | `js/editor/cp.js` | 클립보드/붙여넣기 처리 | ~110 | - | [ ] |
| 3.4 | **A4Ruler** | `js/markdown/a4-ruler.js` | A4 눈금자 UI | ~600 | el, PR | [x] |
| 3.5 | **EditorLineHighlight** | `js/editor/line-highlight.js` | 에디터 줄 하이라이트 | ~60 | el | [x] |
| 3.6 | **EditorAutoPair** | `js/editor/auto-pair.js` | 괄호/따옴표 자동 쌍 | ~70 | el | [x] |
| 3.7 | **ScrollSync** (문서 내) | `js/editor/scroll-sync-doc.js` | 문서 내 스크롤 동기화 | ~30 | - | [x] |

---

### 4단계: 참고문헌·인용·색상·이미지

| # | 항목 | 저장 위치 | 내용 요약 | 예상 줄 수 | 의존성 | 완료 |
|---|------|-----------|-----------|------------|--------|------|
| 4.1 | **CM** (Cite Manager) | `js/cite/cm.js` | 참고문헌 라이브러리, APA 파싱, 스타일 변환 | ~620 | el | [x] |
| 4.2 | **CiteAISearch** | `js/cite/cite-ai-search.js` | 인용 AI 검색 | ~75 | - | [x] |
| 4.3 | **CiteAiSearchHistory** | `js/cite/cite-ai-history.js` | 인용 AI 검색 기록 | ~85 | - | [x] |
| 4.4 | **CAP** (Cite AI Panel?) | `js/cite/cap.js` | 표/그림 캡션 삽입 | ~60 | - | [x] |
| 4.5 | **RefSearch** | `js/cite/ref-search.js` | 참고문헌 검색 (CrossRef 등) | ~280 | - | [x] |
| 4.6 | **ColorPicker** | `js/utils/color-picker.js` | 색상 선택기 | ~80 | el | [x] |
| 4.7 | **IMG** / **ImgStore** | `js/image/img.js`, `img-store.js` | 이미지 업로드·저장 | ~130 + 45 | el | [x] |
| 4.8 | **AiImage** | `js/image/ai-image.js` | AI 이미지 생성 | ~1500+ | el, ImgStore | [x] |

---

### 5단계: 핫키·통계·공유·기타 모달

| # | 항목 | 저장 위치 | 내용 요약 | 예상 줄 수 | 의존성 | 완료 |
|---|------|-----------|-----------|------------|--------|------|
| 5.1 | **DelConfirm** | `js/ui/del-confirm.js` | 삭제 확인 모달 (로컬/GitHub 공용) | ~60 | App | [x] |
| 5.2 | **EZ** | `js/ui/ez.js` | EZ 유틸 (에디터 글자 크기) | ~40 | - | [x] |
| 5.3 | **AuthorInfo** | `js/ui/author-info.js` | 작성자 정보 UI | ~140 | - | [x] |
| 5.4 | **FS** / **FP** | `js/editor/font-size.js`, `js/ui/fp.js` | 폰트 크기·포맷 패널 | ~60 + 55 | el | [x] |
| 5.5 | **STATS** | `js/ui/stats.js` | 통계 패널 | ~255 | el | [x] |
| 5.6 | **HK** (Hotkey) | `js/core/hotkey.js` | 단축키 매핑·실행 | ~710 | App, FM, GH 등 | [x] |
| 5.7 | **PVShare** | `js/share/pv-share.js` | 미리보기 공유 | ~? | el, GH | [ ] |

---

### 6단계: AI·번역·심볼·앱 진입점

| # | 항목 | 저장 위치 | 내용 요약 | 예상 줄 수 | 의존성 | 완료 |
|---|------|-----------|-----------|------------|--------|------|
| 6.1 | **DeepResearch** | `js/ai/deep-research.js` | 딥 리서치 AI | ~1380 | App, el | [ ] |
| 6.2 | **Translator** | `js/ai/translator.js` | 번역 UI·API | ~510 | el | [x] |
| 6.3 | **CharMap** | `js/ui/char-map.js` | 문자 맵(특수문자 삽입) | ~230 | el | [x] |
| 6.4 | **AiPPT** | `js/ai/ai-ppt.js` | AI PPT 생성 | ~100 | - | [x] |
| 6.5 | **App** + **init** + **handleKey** | `index.js`에 유지 또는 `js/core/app.js` | App 객체, init(), 전역 init·이벤트 바인딩 | 최종만 유지 | TM, Render, PW, GH, FM, HK 등 | - |

---

### 스크립트 로드 순서 (분리 시 반영)

분리한 파일은 **의존하는 전역이 정의된 뒤**, **index.js보다 앞**에 두면 된다.

- `el`, `formatDateTime` 등 → **dom.js** 이후
- **PR**, **Render** → parser.js, preview.js, render.js 이후
- **GH** → api.js → history.js → sync.js
- **FM** → GH, LocalFS, DelConfirm 이후
- **App** 참조하는 모듈 → App이 정의되기 전에 로드되면 안 됨 (대부분 index.js 내 정의이므로, 분리 시 index.js보다 **앞**에 두고 전역만 사용)

---

### 완료 시 체크 요약

- [x] 1단계 1.1~1.6 완료
- [x] 2단계 2.1~2.4 완료
- [ ] 3단계 3.1~3.7 완료 (3.1 SS, 3.2 IPPT, 3.4 A4Ruler, 3.5 EditorLineHighlight, 3.6 EditorAutoPair, 3.7 ScrollSync 완료 · 미완료: 3.3 CP)
- [x] 4단계 4.1~4.8 완료 (4.1 CM, 4.2 CiteAISearch, 4.3 CiteAiSearchHistory, 4.4 CAP, 4.5 RefSearch, 4.6 ColorPicker, 4.7 IMG, 4.8 AiImage 완료)
- [ ] 5단계 5.1~5.7 완료 (5.1 DelConfirm, 5.2 EZ 완료)
- [ ] 6단계 6.1~6.5 검토 완료 (6.4 AiPPT 완료)
- [ ] index.js 1,000줄 이하 달성
- [ ] 각 파일 2,000줄 이하 원칙 유지

---

## 폴더 구조 (목표)

```
js/
├── main.js          (최종 진입점 — 나중에 type="module" 전환 시)
├── core/
│   ├── state.js     ✅ 스텁
│   ├── render.js    ✅ 완료
│   ├── events.js    ✅ 완료
│   ├── app-lock.js  ✅ 완료 (AppLock, 2단계)
│   ├── ai-apikey.js ✅ 완료 (2단계)
│   └── scholar-apikey.js ✅ 완료 (2단계)
├── editor/
│   ├── undo.js      ✅ 완료
│   ├── commands.js  ✅ 완료
│   ├── cursor.js    ✅ 완료
│   ├── line-numbers.js ✅ 완료
│   ├── line-highlight.js ✅ 완료
│   ├── auto-pair.js ✅ 완료
│   ├── font-size.js ✅ 완료
│   ├── ippt.js      ✅ 완료
│   └── scroll-sync.js ✅ 파일만 (index.html 미연결)
├── markdown/
│   ├── setup.js    ✅ 완료 (marked 설정)
│   ├── toc.js      ✅ 완료 (목차 빌드/이동/삽입)
│   ├── parser.js   ✅ 완료 (mdRender, splitPages, parseSlideContent)
│   └── preview.js  ✅ 완료 (PR)
├── scholar/
│   └── scholar.js  ✅ 완료 (학술 검색, 2단계)
├── storage/
│   ├── autosave.js  ✅ 완료 (AS)
│   ├── localfs.js   ✅ 완료 (writeToHandle, readFromHandle)
│   └── persistence.js ✅ 완료 (Persist.save/load — TM 탭 세션)
├── data/
│   └── templates.js ✅ 완료 (TMPLS — 메모리·로드 분리)
├── cite/
│   └── cm.js        ✅ 완료 (CM — 참고문헌 라이브러리)
├── ui/
│   ├── ez.js        ✅ 완료
│   ├── cite-modal.js ✅ 완료
│   └── del-confirm.js ✅ 완료
├── github/
│   ├── api.js    ✅ 완료 (GHApi)
│   ├── history.js ✅ 완료 (GHHistory)
│   └── sync.js   ✅ 완료 (GH)
└── utils/
    ├── dom.js       ✅ 완료
    ├── color-picker.js ✅ 완료
    ├── normalize.js ✅ 스텁
    └── debounce.js  ✅ 스텁
```

## 리팩토링 완료 목표
- index.js 1000줄 이하
- 각 파일 2000줄 이하
- GitHub / Editor / Markdown 역할 분리
- 유지보수 가능한 구조

---

# MDPro 최적화(렌더 병목 제거) + 메모리 누수 점검 지침 (Cursor 실행용)

**목표**
1. 입력(input)마다 전체 `App.render()`를 호출하는 구조를 제거한다.
2. Preview 렌더를 스케줄링(requestAnimationFrame / debounce)하고, 변경 유형별 부분 렌더로 분리한다.
3. 이벤트 중복 바인딩/타이머/DOM 참조 누적 등 메모리 누수 지점을 점검하고 방지한다.
4. 기능은 100% 유지한다.

---

## A. 렌더 병목 제거: 핵심 설계

### A1) "렌더 스케줄러(Render Scheduler)" 도입
- `App.render()`를 직접 호출하지 말고, `App.invalidate(reason)`로 변경한다.
- `invalidate`는 `reason`(예: `'editor'`, `'preview'`, `'tabs'`, `'find'`)를 누적하고  
  `requestAnimationFrame`(또는 microtask) 단위로 한 번만 `renderFlush()`를 실행한다.

**구현 요구사항**
- `App.render()`는 기존처럼 전체 렌더도 가능하지만,  
  새로 만드는 `renderFlush()`는 reason 기반 부분 렌더를 우선한다.
- 입력 중에는 preview 렌더만 예약하고, 무거운 UI(파일목록 등)는 예약하지 않는다.

### A2) 입력 이벤트 최적화 (현재 병목)
**현재 구조**
- editor input에서 `US.snap(); TM.markDirty(); this.render();` 를 매 입력마다 실행 (병목)
- find-highlight도 input마다 setTimeout으로 `App.updateFindHighlight()` 호출 (추가 병목)

**변경**
- input에서는 "상태 갱신 + 렌더 예약"만 한다.
- Undo 스냅(US.snap)은 "타이핑 종료 후"로 지연하거나(예: 300ms debounce), 또는 1초 단위로 throttle한다.
- markDirty는 즉시 가능하되, UI 갱신은 `invalidate('tabs'/'dirty')`로 분리한다.

### A3) 부분 렌더 분리
`App.render()`가 지금 모든 것을 만진다면, 다음 4개 함수로 분리한다.
- `Render.renderPreview(mdText)`
- `Render.renderToolbarState(selection/cursor)`
- `Render.renderTabs(tabsStateDirty)`
- `Render.renderFindHighlight(findQuery, startPos)`

**규칙**
- editor input → `renderPreview`만 스케줄
- cursor move/selectionchange → `renderToolbarState`만 스케줄
- tab title input → `renderTabs`만 스케줄
- find input → `renderFindHighlight`만 debounce

### A4) 프리뷰 렌더 성능
- Markdown 파싱이 무거우면 parse를 "idle"로 미루거나(가능하면 requestIdleCallback), 최소한 rAF + debounce를 조합한다.
- 예: 입력 중 120ms debounce로 parse 호출, parse 결과는 diff 없이 innerHTML 교체 (기존 유지)
- 단, highlight 오버레이(찾기/동시선택)는 parse 결과 이후 별도 레이어로 적용

### A5) find highlight 최적화
**현재**
- input마다 timeout 120ms로 `App.updateFindHighlight();` (하지만 render도 함께 발생)

**변경**
- find highlight는 preview와 분리된 오버레이 DOM(`#editor-find-highlight` 등)에만 적용하고, preview 렌더와 독립적으로 debounce 한다.
- query가 비어있으면 즉시 clear만 수행.

### A6) setInterval 최적화 (불필요 폴링 제거)
**현재**
- `setInterval(() => PW.checkClosed(), 2000)`

**변경**
- preview window가 열릴 때만 interval 시작, 닫히면 clearInterval
- 또는 window.onbeforeunload / postMessage handshake 등 이벤트 기반으로 전환

---

## B. 렌더 스케줄러: 구현 체크리스트

### B1) App.invalidate(reason) 추가
- reason은 Set으로 누적
- `_renderScheduled` 플래그로 중복 스케줄 방지
- requestAnimationFrame에서 `App._renderFlush()` 호출

### B2) App._renderFlush() 설계
- reasons에 따라 다음 순서로 호출 (예시)
  1. `if 'preview'` → `Render.renderPreview()`
  2. `if 'find'` → `Render.renderFindHighlight()`
  3. `if 'toolbar'` → `Render.renderToolbarState()`
  4. `if 'tabs'` → `Render.renderTabs()`
- flush 후 reasons clear

### B3) 기존 App.render() 호출부 치환
- 직접 호출(`App.render()`)을 대부분 `App.invalidate('preview')` 등으로 교체
- 완전 전체 렌더가 필요한 경우만 `App.render()` 유지  
  예: 템플릿 목록 갱신, 레이아웃 변경, 설정창 열기/닫기 등

### B4) input 이벤트 변경 지침
- **editor input**
  - `TM.markDirty()`는 유지
  - `US.snap()`는 `debounceSnap()`로 변경 (300~600ms 권장)
  - `App.invalidate('preview')` + (find-bar 열려있으면) `App.invalidate('find')`

- **editor scroll**
  - LN.update() 등은 최소화
  - find-highlight overlay scroll sync는 passive 유지

- **selectionchange**
  - `App.invalidate('toolbar')`로 변경 (현재처럼 매번 updFmtBtns 직접 호출 최소화)

---

## C. 메모리 누수 점검 지침 (MDPro용)

### C1) 이벤트 리스너 중복 바인딩 확인
**문제 패턴**
- App.init() 또는 탭 전환 시 동일 addEventListener가 다시 실행되면 누수/중복 실행 발생

**지침**
- bind 함수마다 "이미 바인딩됨" 플래그를 둔다:  
  `if (edi._bound) return; edi._bound = true;`

**점검 대상(대표)**
- `document.addEventListener('keydown', ...)`
- `document.addEventListener('selectionchange', ...)`
- `editor.addEventListener('input'/'scroll'/'keyup'/'click', ...)`

### C2) setInterval / setTimeout 누수
**문제 패턴**
- interval을 생성하고 clearInterval을 하지 않음
- timeout 핸들을 계속 덮어쓰지만 clearTimeout 누락

**지침**
- interval/timeout 핸들을 모듈 스코프에 저장하고, 모듈 종료/윈도우 닫힘/기능 OFF 시 clear 한다.
- preview window polling은 "열릴 때 생성, 닫히면 제거"로 변경

### C3) DOM 참조 누수
**문제 패턴**
- 제거된 DOM 노드를 전역 변수에 계속 들고 있어 GC가 안 됨
- overlay/modal을 만들고 닫을 때 remove()만 하고 참조를 null로 안 함

**지침**
- 모달/오버레이 객체는 close 시: `node.remove(); node = null;`
- querySelectorAll 결과를 캐싱하지 말고, 필요 시만 조회

### C4) 큰 문자열/히스토리 스택 누수 (Undo/History)
**문제 패턴**
- US.snap이 너무 자주 호출되어 대형 문자열이 stack에 과도하게 누적
- ptr 이동이 잦고 persist가 잦으면 localStorage/IDB 압박

**지침**
- Undo 스냅은 debounce/throttle
- "변경량이 없으면 snap 하지 않기" (직전 value와 동일하면 skip)
- stack 최대 길이 cap(예: 200~400)
- 큰 문서에서는 "diff 기반"이 이상적이나, 당장은 cap+debounce로 완화

### C5) Preview 렌더 누수
**문제 패턴**
- preview.innerHTML을 자주 교체하면서, 내부에 이벤트 핸들러를 인라인(onclick="...")로 심으면 전역 함수 참조가 남거나, 새 DOM 생성이 과도

**지침**
- preview 내부 이벤트는 가능한 이벤트 위임(단일 listener)로 유지
- 렌더 시마다 addEventListener를 반복하지 않도록 주의

### C6) 메모리 점검 실무 체크(브라우저 개발자도구)
- **Performance**: 입력 5초 동안 FPS/스크립트 실행 시간 확인 (render 폭주 여부)
- **Memory**: Heap snapshot 2회 비교 — 탭 전환/프리뷰 열기/닫기 10회 후에도 node 수가 계속 증가하면 누수
- **Event Listeners 탭**: 동일 요소에 listener가 증가하는지 확인

---

## D. Cursor에 실행 지시(구체 작업)

1. `App.invalidate` / `App._renderFlush` / Render 모듈 생성
2. editor input / selectionchange / find input 등에서 `App.render` 직접 호출 제거
3. `US.snap`을 `debounceSnap`으로 교체하고, stack cap 적용
4. `setInterval(PW.checkClosed)` 조건부 실행 및 clearInterval 적용
5. 모든 bind 함수에 `_bound` 플래그 추가
6. 모달/오버레이 close 시 참조 null 처리

**완료 조건**
- 타이핑 시 App.render가 초당 1~2회 수준으로 제한
- find highlight는 preview 렌더와 독립적으로 동작
- 탭/프리뷰 열고닫기 반복 후에도 Heap node 수가 안정
- 기능 회귀 없음

**주의**
- 기존 전역 App/TM/US 인터페이스는 유지한다.
- 변경은 점진적으로 적용하고, 각 단계마다 동작 확인한다.
