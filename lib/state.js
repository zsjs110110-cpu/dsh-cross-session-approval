/**
 * Persistent cross-session registry for dsh-cross-session-approval.
 *
 * State lives under `<workspace>/<stateDir>/registry.json` (default
 * `.cross-session`). Two layers of protection:
 *  - a process-local promise chain serializes tool-call mutations in one host;
 *  - an O_EXCL lockfile (`registry.lock`) serializes across processes, with
 *    stale-lock detection after LOCK_STALE_MS; stale locks require operator recovery so a dead writer
 *    is surfaced as an error. The lock carries an ownership token, so a
 *    process whose lock was taken over can never delete the new holder's lock.
 * Reads never write: only a missing file yields an empty registry, and any
 * other read failure is reported instead of silently resetting the store.
 * Writes themselves are atomic (temp file + same-volume rename), so readers
 * never observe a torn file even without the lock.
 *
 * @module dsh-cross-session-approval/state
 */
import { randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

/** Process-local serialization chain for registry writes. */
let chain = Promise.resolve();

/** A lockfile older than this may be residue or a paused holder: fail closed. */
const LOCK_STALE_MS = 10_000;
/** Give up waiting for a live holder after this long. */
const LOCK_MAX_WAIT_MS = 8_000;
const LOCK_RETRY_MS = 50;
/** 临界区心跳间隔——更新 lockfile mtime，避免长临界区被误判 stale。 */
const LOCK_HEARTBEAT_MS = 2_000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Empty registry shape. */
function empty() {
  return { workers: {} };
}

/**
 * The registry exists but cannot be trusted (corrupt JSON, bad shape, I/O or
 * permission failure). Callers must surface this instead of writing an empty
 * registry over data that is merely unreadable right now.
 */
export class RegistryReadError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'RegistryReadError';
  }
}

/**
 * Absolute registry path for one workspace.
 * @param {string} workspace - workspace root directory.
 * @param {string} stateDir - configured state directory name.
 * @returns {string} absolute registry.json path.
 */
export function registryPath(workspace, stateDir) {
  return join(workspace, stateDir, 'registry.json');
}

/**
 * Run `fn` while holding the cross-process lock for `dir`.
 * @param {string} dir - state directory containing registry.json.
 * @param {() => Promise<T>} fn - critical section.
 * @returns {Promise<T>} fn's result.
 */
async function withLock(dir, fn) {
  await mkdir(dir, { recursive: true });
  const lockPath = join(dir, 'registry.lock');
  // Ownership token: releasing must only ever remove our own lock file.
  const owner = `${process.pid}.${randomUUID()}`;
  const deadline = Date.now() + LOCK_MAX_WAIT_MS;
  let handle;
  for (;;) {
    try {
      handle = await open(lockPath, 'wx'); // exclusive create
      await handle.writeFile(owner, 'utf8');
      break;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      let info;
      
      try {
        info = await stat(lockPath);
      } catch (probeError) {
        // Only a vanished lock means "retry immediately". Permission or I/O
        // failures must surface instead of spinning until the deadline.
        if (probeError?.code === 'ENOENT') continue;
        throw probeError;
      }
      const stale = Date.now() - info.mtimeMs > LOCK_STALE_MS;
      if (stale) {
        throw new Error('registry lock stale; unsafe automatic takeover disabled: ' + lockPath);
      }
      if (Date.now() > deadline) {
        throw new Error(`registry lock busy after ${LOCK_MAX_WAIT_MS}ms: ${lockPath}`);
      }
      await sleep(LOCK_RETRY_MS);
    }
  }
  const heartbeat = setInterval(() => { handle.utimes(new Date(), new Date()).catch(() => {}); }, LOCK_HEARTBEAT_MS);
  try {
    return await fn();
  } finally {
    clearInterval(heartbeat);
    await handle.close().catch(() => {});
    try {
      // Remove the lock only while we still own it.
      if (await readFile(lockPath, 'utf8') === owner) {
        await rm(lockPath, { force: true });
      }
    } catch {
      // Lock already gone or unreadable: nothing safe to remove.
    }
  }
}

/**
 * Read the registry without ever inventing an empty one.
 *
 * Only a missing file starts a fresh registry. A corrupt file, a bad shape or
 * an I/O error is thrown so callers cannot silently write `{workers:{}}` back
 * over records that are merely unreadable right now.
 *
 * @param {string} path - absolute registry.json path.
 * @returns {Promise<{workers: Record<string, object>}>}
 * @throws {Error} when the file exists but cannot be parsed or trusted.
 */
async function readRegistry(path) {
  let text;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return empty();
    throw new RegistryReadError(`registry file is unreadable: ${path}`, { cause: error });
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new RegistryReadError(`registry file is not valid JSON: ${path}`, { cause: error });
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new RegistryReadError(`registry file has an invalid root value: ${path}`);
  }
  if (parsed.workers === undefined) return { ...parsed, workers: {} };
  if (parsed.workers === null || typeof parsed.workers !== 'object' || Array.isArray(parsed.workers)) {
    throw new RegistryReadError(`registry file has an invalid "workers" map: ${path}`);
  }
  return parsed;
}

/**
 * Read-only registry view for tools that only inspect state.
 *
 * Never acquires the write lock and never writes, so a read can no longer
 * truncate the registry (previously even `status`/`list` rewrote it).
 *
 * @param {string} workspace - workspace root directory.
 * @param {string} stateDir - configured state directory name.
 * @returns {Promise<{workers: Record<string, object>}>}
 */
export async function readRegistryOnly(workspace, stateDir) {
  return readRegistry(registryPath(workspace, stateDir));
}

/**
 * Write the registry atomically (write temp file then rename over target).
 * Rename within the same directory is atomic on POSIX and on Windows
 * (same volume); a leftover temp file is removed on failure.
 * @param {string} path - absolute registry.json path.
 * @param {object} registry - full registry value.
 * @returns {Promise<void>}
 */
async function writeRegistry(path, registry) {
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`;
  try {
    await writeFile(temp, JSON.stringify(registry, null, 2), 'utf8');
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true }).catch(() => {});
    throw error;
  }
}

/**
 * Run one read-modify-write against the registry: the process-local chain
 * orders callers in-process, the lockfile orders them across processes.
 * @param {string} workspace - workspace root directory.
 * @param {string} stateDir - configured state directory name.
 * @param {(registry: object) => void | Promise<void>} mutate - mutation callback.
 * @returns {Promise<object>} the registry after mutation.
 */
export function withRegistry(workspace, stateDir, mutate) {
  const run = chain.then(() =>
    withLock(join(workspace, stateDir), async () => {
      const path = registryPath(workspace, stateDir);
      const registry = await readRegistry(path);
      await mutate(registry);
      await writeRegistry(path, registry);
      return registry;
    }),
  );
  // Keep the chain alive even when a mutation throws; callers see the error.
  chain = run.then(() => undefined, () => undefined);
  return run;
}
