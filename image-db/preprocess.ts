/**
 * Markdown preprocessor: convert brace-style dimensions to query params
 * so standard markdown parsers output a single <img> and resolve can read dimensions from src.
 *
 * Before: ![alt](indexeddb://uuid){width=300 height=200}
 * After:  ![alt](indexeddb://uuid?width=300&height=200)
 */

const INDEXEDDB_PREFIX = 'indexeddb://';
const BRACE_RE = /\]\((indexeddb:\/\/[^)]+)\)\{width=([^\s}]*)\s+height=([^}]*)\}/g;

/**
 * Transform markdown so that indexeddb image links with {width= w height= h}
 * become query params. Safe to call multiple times (idempotent for already-converted links).
 */
export function preprocessMarkdownForIndexedDBImages(md: string): string {
  return md.replace(BRACE_RE, (_, urlPart: string, width: string, height: string) => {
    const base = urlPart.trim();
    const params = new URLSearchParams();
    if (width.trim() !== '') params.set('width', width.trim());
    if (height.trim() !== '') params.set('height', height.trim());
    const query = params.toString();
    return `](${base}${query ? `?${query}` : ''})`;
  });
}
