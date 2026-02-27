/**
 * Insert image: store Blob in IndexedDB with UUID, return Markdown string.
 * Format: ![alt](indexeddb://<uuid>?width=300&height=200)
 * Width/height are optional; omitted dimensions render at natural size.
 */

import * as store from './store';
import type { InsertImageOptions } from './types';

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

function buildIndexedDBUrl(uuid: string, options?: InsertImageOptions): string {
  const url = `indexeddb://${uuid}`;
  const params = new URLSearchParams();
  if (options?.width != null && Number.isFinite(options.width)) {
    params.set('width', String(Math.round(options.width)));
  }
  if (options?.height != null && Number.isFinite(options.height)) {
    params.set('height', String(Math.round(options.height)));
  }
  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
}

/**
 * Store image Blob in IndexedDB and return Markdown for insertion.
 * @param blob - Image Blob (e.g. from File or canvas.toBlob)
 * @param alt - Alt text for the image
 * @param options - Optional width and/or height (pixels)
 * @returns Markdown string: ![alt](indexeddb://uuid?width=...&height=...)
 */
export async function insertImage(
  blob: Blob,
  alt: string,
  options?: InsertImageOptions
): Promise<string> {
  if (!blob || !(blob instanceof Blob)) {
    throw new Error('insertImage: blob is required');
  }
  const uuid = generateUUID();
  await store.set(uuid, blob);
  const url = buildIndexedDBUrl(uuid, options);
  const escapedAlt = alt.replace(/\]/g, '\\]');
  return `![${escapedAlt}](${url})`;
}
