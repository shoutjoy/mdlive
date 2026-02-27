# image-db — IndexedDB image handling for Markdown editors

Store images as Blobs in IndexedDB, insert as markdown with optional dimensions, resolve `indexeddb://` in rendered HTML with proper blob URL lifecycle.

## Markdown format

- Without dimensions: `![alt](indexeddb://<uuid>)`
- With dimensions: `![alt](indexeddb://<uuid>){width=300 height=200}`

Width/height are optional. If omitted, images render at natural size.

## Usage

### 1. Insert image (e.g. from file input or paste)

```ts
import { insertImage } from './image-db';

const blob = await fileInput.files[0].arrayBuffer().then(ab => new Blob([ab]));
const markdown = await insertImage(blob, 'My image', { width: 300, height: 200 });
// => ![My image](indexeddb://uuid){width=300 height=200}
```

### 2. Before rendering markdown to HTML

Preprocess so standard parsers (e.g. marked) get a single `<img>` and dimensions in the URL:

```ts
import { preprocessMarkdownForIndexedDBImages } from './image-db';

const html = marked.parse(preprocessMarkdownForIndexedDBImages(md));
container.innerHTML = html;
```

### 3. After rendering: resolve indexeddb:// and apply dimensions

```ts
import { resolveIndexedDBImages, revokeUrlsForContainer } from './image-db';

await resolveIndexedDBImages(container);
```

On re-render (e.g. content changed), revoke old blob URLs then resolve again:

```ts
revokeUrlsForContainer(container);
container.innerHTML = marked.parse(preprocessMarkdownForIndexedDBImages(md));
await resolveIndexedDBImages(container);
```

### 4. IndexedDB helper (optional)

```ts
import { open, get, set } from './image-db';

await set('some-uuid', blob);
const blob = await get('some-uuid');
```

## Build

```bash
npx tsc -p tsconfig.json
```

Output in `dist/`. Use with a bundler or as ES modules.

## Behaviour

- **Aspect ratio:** If only `width` is set, `height` is `auto`; if only `height`, `width` is `auto`. If both are set, both are applied with `object-fit: contain` so the image is not distorted.
- **Cleanup:** Blob URLs created for a container are tracked; calling `revokeUrlsForContainer(container)` or `resolveIndexedDBImages(container)` again revokes previous URLs for that container to avoid leaks.
- **Errors:** Missing blob or IDB errors are handled defensively; missing images show alt text and no broken icon.
