/**
 * Insert image: store Blob in IndexedDB and return Markdown string.
 * Format: ![alt](indexeddb://<uuid>){width=300 height=200}
 * Width/height optional; if omitted, image renders at natural size.
 */

import { set } from './store';
import { InsertImageOptions } from './types';

const INDEXEDDB_IMAGE_SCHEME = 'indexeddb://';

function generateUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Store blob in IndexedDB and return markdown string.
 * Exact format: ![alt](indexeddb://<uuid>){width=300 height=200}
 * Brace block only present when at least one dimension is provided.
 * For HTML rendering, preprocess markdown to inject data-width/data-height on the img,
 * or use query params in the URL (indexeddb://uuid?width=300&height=200) so resolve can read dimensions from src.
 */
export async function insertImage(
  blob: Blob,
  alt: string,
  options?: InsertImageOptions
): Promise<string> {
  const uuid = generateUUID();
  await set(uuid, blob);
  const url = `${INDEXEDDB_IMAGE_SCHEME}${uuid}`;
  const brace =
    options?.width != null || options?.height != null
      ? `{width=${options.width ?? ''} height=${options.height ?? ''}}`
      : '';
  return `![${alt.replace(/\]/g, '\\]')}](${url})${brace}`;
}
