/**
 * 1000줄 단위 강제 분할 (전체 해석/AST/리팩터링 없음, 단순 텍스트 분할만)
 * 사용: node scripts/split-by-1000.js
 * 입력: index.js  →  출력: chunks/chunk_1.js, chunk_2.js, ...
 */
const fs = require('fs');
const path = require('path');

const inputPath = path.join(__dirname, '..', 'index.js');
const outDir = path.join(__dirname, '..', 'chunks');
const chunkSize = 1000;

if (!fs.existsSync(inputPath)) {
  console.error('입력 파일 없음:', inputPath);
  process.exit(1);
}

const content = fs.readFileSync(inputPath, 'utf8');
const lines = content.split('\n');
const total = lines.length;

if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

let fileIndex = 1;
for (let i = 0; i < lines.length; i += chunkSize) {
  const chunk = lines.slice(i, i + chunkSize).join('\n');
  const outPath = path.join(outDir, `chunk_${fileIndex}.js`);
  fs.writeFileSync(outPath, chunk, 'utf8');
  fileIndex++;
}

console.log('분할 완료:', Math.ceil(total / chunkSize), '개 파일, 총', total, '줄');
