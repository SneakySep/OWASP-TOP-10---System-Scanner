// Helpers to collect files from drag & drop (including folders) and from
// file/folder picker inputs, preserving relative paths.

export interface PickedFile {
  file: File;
  /** Path relative to the drop root / picked folder, e.g. "src/app.py". */
  path: string;
}

/** Hard cap to avoid freezing the browser on huge trees. */
export const MAX_FILES = 5000;

/** Junk directories that are never useful to scan as source. */
const SKIPPED_DIRS = new Set([
  "node_modules",
  ".git",
  "__pycache__",
  ".venv",
  "venv",
  ".next",
  "dist",
  "build",
  ".idea",
  ".vscode",
]);

export class CollectionError extends Error {}

/**
 * Collect files from a drop event. Supports a mix of loose files and
 * directories in modern browsers; falls back to plain files elsewhere.
 */
export async function collectFromDataTransfer(
  dt: DataTransfer
): Promise<PickedFile[]> {
  const entries: FileSystemEntry[] = [];
  for (const item of Array.from(dt.items ?? [])) {
    const entry = item.webkitGetAsEntry?.();
    if (entry) entries.push(entry);
  }

  // Fallback for browsers without the entries API: only loose files.
  if (entries.length === 0) {
    return collectFromInput(dt.files);
  }

  const picked: PickedFile[] = [];
  for (const entry of entries) {
    await walkEntry(entry, "", picked);
  }
  if (picked.length === 0) {
    throw new CollectionError(
      "Nothing to upload — the dropped item(s) contain no files."
    );
  }
  return picked;
}

async function walkEntry(
  entry: FileSystemEntry,
  prefix: string,
  out: PickedFile[]
): Promise<void> {
  if (out.length >= MAX_FILES) return;
  if (entry.isFile) {
    const file = await entryToFile(entry as FileSystemFileEntry);
    out.push({ file, path: prefix + entry.name });
  } else if (entry.isDirectory) {
    if (SKIPPED_DIRS.has(entry.name)) return;
    const dir = entry as FileSystemDirectoryEntry;
    const reader = dir.createReader();
    // readEntries() returns at most 100 entries per call — loop until empty.
    for (;;) {
      const batch = await readEntries(reader);
      if (batch.length === 0) break;
      for (const child of batch) {
        await walkEntry(child, `${prefix}${entry.name}/`, out);
      }
    }
  }
}

function entryToFile(fe: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => {
    fe.file(resolve, () =>
      reject(new CollectionError(`Could not read dropped file "${fe.name}".`))
    );
  });
}

function readEntries(
  reader: FileSystemDirectoryReader
): Promise<FileSystemEntry[]> {
  return new Promise((resolve, reject) => {
    reader.readEntries(resolve, () =>
      reject(new CollectionError("Could not read a dropped folder."))
    );
  });
}

/** Collect files from an <input type="file"> (multi-select or folder picker). */
export function collectFromInput(fileList: FileList | null): PickedFile[] {
  const picked: PickedFile[] = [];
  for (const file of Array.from(fileList ?? [])) {
    const rel = (file as File & { webkitRelativePath?: string })
      .webkitRelativePath;
    picked.push({ file, path: rel ? rel : file.name });
    if (picked.length >= MAX_FILES) break;
  }
  return picked;
}