import type {
	ExecException,
	ExecFileException,
	ExecFileOptions,
	ExecFileSyncOptions,
	ExecOptions,
	ExecSyncOptions,
	ForkOptions,
	SpawnOptions,
	SpawnSyncOptions,
} from 'node:child_process';
import { isBuiltin } from 'node:module';

import { DisallowedModuleError } from './errors/disallowed-module.error';
import { ExecutionError } from './errors/execution-error';

export type RequireResolverOpts = {
	/**
	 * List of built-in nodejs modules that are allowed to be required in the
	 * execution sandbox. `"*"` means all are allowed.
	 */
	allowedBuiltInModules: Set<string> | '*';

	/**
	 * List of external modules that are allowed to be required in the
	 * execution sandbox. `"*"` means all are allowed.
	 */
	allowedExternalModules: Set<string> | '*';

	/**
	 * When true, return a write-blocking view of each resolved module. The
	 * module cache is shared across every task in the runner process, so an
	 * unprotected module object lets one task's changes leak into other tasks.
	 */
	secureModules?: boolean;
};

export type RequireResolver = (request: string) => unknown;

type Constructor = new (...args: unknown[]) => object;

const isWrappable = (value: unknown): value is object =>
	value !== null && (typeof value === 'object' || typeof value === 'function');

// Views (write-blocking proxies) keyed by their real target, plus the reverse
// lookup used to unwrap `this`/arguments back to the real object before a
// wrapped function runs. One view per target keeps identity stable across reads.
const viewByTarget = new WeakMap<object, unknown>();
const targetByView = new WeakMap<object, object>();

const unwrap = (value: unknown): unknown =>
	isWrappable(value) ? (targetByView.get(value) ?? value) : value;

// A non-configurable, non-writable data property: a Proxy must hand back its
// exact value (invariant), so it can't be wrapped.
const isFixedData = (descriptor: PropertyDescriptor | undefined): boolean =>
	!!descriptor && 'value' in descriptor && !descriptor.configurable && !descriptor.writable;

// Secure a value read off the module. Normally wrap it in the membrane; when an
// invariant forces us to return the exact object, freeze it best-effort instead
// so it still can't be mutated for other tasks.
function secureReadValue(value: unknown, mustReturnRaw: boolean): unknown {
	if (!mustReturnRaw) return secureModuleExport(value);
	if (isWrappable(value) && !Object.isFrozen(value)) {
		try {
			Object.freeze(value);
		} catch {
			// Non-freezable (e.g. a populated TypedArray) — nothing more we can do.
		}
	}
	return value;
}

// Blocks every write (assignment incl. accessor setters, (re)definition,
// deletion, prototype change) and wraps values read from the module — via both
// property reads and descriptor reflection — so nested objects can't be mutated
// either. Function calls forward to the real module with `this`/arguments
// unwrapped, so internal-slot/brand checks still pass.
const membraneHandler: ProxyHandler<object> = {
	set: () => false,
	defineProperty: () => false,
	deleteProperty: () => false,
	setPrototypeOf: () => false,
	get(target, prop) {
		const value = Reflect.get(target, prop, target) as unknown;
		const descriptor = Reflect.getOwnPropertyDescriptor(target, prop);
		return secureReadValue(value, isFixedData(descriptor));
	},
	getOwnPropertyDescriptor(target, prop) {
		const descriptor = Reflect.getOwnPropertyDescriptor(target, prop);
		if (descriptor && 'value' in descriptor) {
			descriptor.value = secureReadValue(descriptor.value, isFixedData(descriptor));
		}
		return descriptor;
	},
	apply: (target, thisArg, args) =>
		Reflect.apply(target as (...a: unknown[]) => unknown, unwrap(thisArg), args.map(unwrap)),
	// Return values are left unwrapped so callers keep ownership of what a
	// module hands back (e.g. a Buffer they can still mutate).
	construct: (target, args, newTarget) =>
		Reflect.construct(target as Constructor, args.map(unwrap), unwrap(newTarget) as Constructor),
};

/**
 * Wrap a resolved module in a write-blocking membrane. Proxying rather than
 * `Object.freeze` avoids two problems: freezing throws on non-freezable
 * exports (e.g. a non-empty `Buffer`/`TypedArray`), and it leaves accessor
 * setters (e.g. `crypto.fips`) able to mutate shared process state. The
 * membrane also wraps nested objects on read, so one task cannot mutate a
 * module's nested state (e.g. `http.globalAgent`) for the others.
 */
export function secureModuleExport(resolved: unknown): unknown {
	if (!isWrappable(resolved)) return resolved;

	const cached = viewByTarget.get(resolved);
	if (cached !== undefined) return cached;

	const view = new Proxy(resolved, membraneHandler);
	viewByTarget.set(resolved, view);
	targetByView.set(view, resolved);
	return view;
}

export function createRequireResolver({
	allowedBuiltInModules,
	allowedExternalModules,
	secureModules = false,
}: RequireResolverOpts) {
	return (request: string) => {
		const checkIsAllowed = (allowList: Set<string> | '*', moduleName: string) => {
			return allowList === '*' || allowList.has(moduleName);
		};

		const isAllowed = isBuiltin(request)
			? checkIsAllowed(allowedBuiltInModules, request)
			: checkIsAllowed(allowedExternalModules, request);

		if (!isAllowed) {
			const error = new DisallowedModuleError(request);
			throw new ExecutionError(error);
		}

		// eslint-disable-next-line @typescript-eslint/no-require-imports
		const resolved = require(request) as unknown;

		// Defense-in-depth: wrap `child_process` so subprocesses spawned by code
		// under audit can't inherit the runner's secrets. Applied before the
		// membrane so the write-blocking view still wraps the object we return.
		const exported =
			request === 'child_process'
				? createSecureChildProcessWrapper(resolved as ChildProcessModule)
				: resolved;

		return secureModules ? secureModuleExport(exported) : exported;
	};
}

type ChildProcessModule = typeof import('node:child_process');

/**
 * Environment variables that must not be inherited by subprocesses spawned from
 * inside the sandbox. Runner tokens would allow pivoting back into n8n;
 * `ANTHROPIC_API_KEY` is a paid credential.
 *
 * NOTE: this require-time wrapper is the *stricter* of two layers and strips the
 * Anthropic key too, because code that reaches for `child_process` directly is
 * untrusted. The global patch in `js-task-runner.ts` deliberately keeps the key
 * so the `claude` CLI / Anthropic SDK it spawns can still authenticate — that
 * asymmetry is intentional (stripping the key everywhere broke Claude before).
 */
const SENSITIVE_ENV_VARS = [
	'ANTHROPIC_API_KEY',
	'N8N_RUNNERS_GRANT_TOKEN',
	'N8N_RUNNERS_AUTH_TOKEN',
] as const;

const stripSensitiveEnvVars = (env?: NodeJS.ProcessEnv): NodeJS.ProcessEnv => {
	// Undefined env means the child would inherit process.env; clone and scrub it.
	const cleaned = { ...(env ?? process.env) };
	for (const key of SENSITIVE_ENV_VARS) delete cleaned[key];
	return cleaned;
};

/**
 * Wraps `child_process` so every process-spawning API — async *and* sync — runs
 * with a scrubbed environment. The sync variants (`execSync`/`execFileSync`/
 * `spawnSync`) are covered too; otherwise code could exfiltrate secrets through
 * them while the async APIs were locked down.
 */
export function createSecureChildProcessWrapper(childProcess: ChildProcessModule): ChildProcessModule {
	// Each override narrows to a single signature; cast once back to the module's
	// overloaded type at the return.
	return {
		...childProcess,
		spawn: (command: string, args?: readonly string[], options?: SpawnOptions) =>
			childProcess.spawn(command, args ?? [], {
				...options,
				env: stripSensitiveEnvVars(options?.env),
			}),
		exec: (
			command: string,
			options?: ExecOptions,
			onExit?: (error: ExecException | null, stdout: string | Buffer, stderr: string | Buffer) => void,
		) =>
			childProcess.exec(
				command,
				{ ...options, env: stripSensitiveEnvVars(options?.env) },
				onExit,
			),
		execFile: (
			file: string,
			args?: readonly string[],
			options?: ExecFileOptions,
			onExit?: (
				error: ExecFileException | null,
				stdout: string | Buffer,
				stderr: string | Buffer,
			) => void,
		) =>
			childProcess.execFile(
				file,
				args ?? [],
				{ ...options, env: stripSensitiveEnvVars(options?.env) },
				onExit,
			),
		fork: (modulePath: string, args?: readonly string[], options?: ForkOptions) =>
			childProcess.fork(modulePath, args ?? [], {
				...options,
				env: stripSensitiveEnvVars(options?.env),
			}),
		execSync: (command: string, options?: ExecSyncOptions) =>
			childProcess.execSync(command, { ...options, env: stripSensitiveEnvVars(options?.env) }),
		execFileSync: (file: string, args?: readonly string[], options?: ExecFileSyncOptions) =>
			childProcess.execFileSync(file, args ?? [], {
				...options,
				env: stripSensitiveEnvVars(options?.env),
			}),
		spawnSync: (command: string, args?: readonly string[], options?: SpawnSyncOptions) =>
			childProcess.spawnSync(command, args ?? [], {
				...options,
				env: stripSensitiveEnvVars(options?.env),
			}),
	} as ChildProcessModule;
}
