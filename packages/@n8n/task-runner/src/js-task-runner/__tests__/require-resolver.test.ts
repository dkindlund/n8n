import type * as nodeCrypto from 'node:crypto';

import { ExecutionError } from '@/js-task-runner/errors/execution-error';

import {
	createRequireResolver,
	createSecureChildProcessWrapper,
	secureModuleExport,
	type RequireResolverOpts,
} from '../require-resolver';

describe('require resolver', () => {
	let defaultOpts: RequireResolverOpts;

	beforeEach(() => {
		defaultOpts = {
			allowedBuiltInModules: new Set(['path', 'fs']),
			allowedExternalModules: new Set(['lodash']),
		};
	});

	describe('built-in modules', () => {
		it('should allow requiring whitelisted built-in modules', () => {
			const resolver = createRequireResolver(defaultOpts);
			expect(() => resolver('path')).not.toThrow();
			expect(() => resolver('fs')).not.toThrow();
		});

		it('should throw when requiring non-whitelisted built-in modules', () => {
			const resolver = createRequireResolver(defaultOpts);
			expect(() => resolver('crypto')).toThrow(ExecutionError);
		});

		it('should allow all built-in modules when allowedBuiltInModules is "*"', () => {
			const resolver = createRequireResolver({
				...defaultOpts,
				allowedBuiltInModules: '*',
			});

			expect(() => resolver('path')).not.toThrow();
			expect(() => resolver('crypto')).not.toThrow();
			expect(() => resolver('fs')).not.toThrow();
		});
	});

	describe('external modules', () => {
		it('should allow requiring whitelisted external modules', () => {
			const resolver = createRequireResolver(defaultOpts);
			expect(() => resolver('lodash')).not.toThrow();
		});

		it('should throw when requiring non-allowlisted external modules', () => {
			const resolver = createRequireResolver(defaultOpts);
			expect(() => resolver('express')).toThrow(ExecutionError);
			expect(() => resolver('express')).toThrow('express');
		});

		it('should allow all external modules when allowedExternalModules is "*"', () => {
			const resolver = createRequireResolver({
				...defaultOpts,
				allowedExternalModules: '*',
			});

			expect(() => resolver('lodash')).not.toThrow();
			expect(() => resolver('express')).not.toThrow();
		});
	});

	describe('module securing', () => {
		it('should not let one resolution mutate the shared module for another', () => {
			const resolver = createRequireResolver({ ...defaultOpts, secureModules: true });

			const first = resolver('path') as { normalize: unknown };
			const original = first.normalize;
			// Own-property reassignment on the shared cached module must not stick.
			expect(() => {
				'use strict';
				first.normalize = () => 'poisoned';
			}).toThrow();

			const second = resolver('path') as { normalize: unknown };
			expect(second.normalize).toBe(original);
			expect((second.normalize as (p: string) => string)('a//b')).toBe('a/b');
		});

		it('should return the same view for repeated resolutions (stable identity)', () => {
			const resolver = createRequireResolver({ ...defaultOpts, secureModules: true });

			expect(resolver('path')).toBe(resolver('path'));
		});

		it('should not secure modules by default', () => {
			const resolver = createRequireResolver(defaultOpts);
			const fs = resolver('fs') as Record<string, unknown>;

			const marker = () => 'noop';
			fs.__probe = marker;
			expect(fs.__probe).toBe(marker);
			delete fs.__probe;
		});
	});

	describe('secureModuleExport', () => {
		it('should not throw when securing a non-freezable Buffer/TypedArray export', () => {
			// Object.freeze throws on these ("Cannot freeze array buffer views with elements").
			const buf = Buffer.from([1, 2, 3]);
			const view = secureModuleExport(buf) as Buffer;

			expect(view[0]).toBe(1); // reads pass through
			expect(() => {
				'use strict';
				view[0] = 9;
			}).toThrow(); // writes are blocked
			expect(buf[0]).toBe(1); // underlying buffer untouched
		});

		it('should block assignment through accessor setters', () => {
			let sideEffect = 0;
			const mod = {};
			Object.defineProperty(mod, 'danger', {
				get: () => sideEffect,
				set: (v: number) => {
					sideEffect = v;
				},
				configurable: true,
			});

			const secured = secureModuleExport(mod) as { danger: number };
			// Strict-mode module code: the blocked write throws instead of the setter running.
			expect(() => {
				secured.danger = 99;
			}).toThrow();

			expect(sideEffect).toBe(0); // the real setter never ran
		});

		it('should block adding, redefining, deleting properties and swapping the prototype', () => {
			const mod: Record<string, unknown> = { existing: 1 };
			const secured = secureModuleExport(mod) as Record<string, unknown>;

			expect(() => Object.defineProperty(secured, 'added', { value: 1 })).toThrow();
			expect(Reflect.deleteProperty(secured, 'existing')).toBe(false);
			expect(Reflect.setPrototypeOf(secured, {})).toBe(false);
			expect(mod.existing).toBe(1);
		});

		it('should keep a real module callable and usable through the view', () => {
			const resolver = createRequireResolver({
				allowedBuiltInModules: new Set(['crypto']),
				allowedExternalModules: new Set(),
				secureModules: true,
			});
			const crypto = resolver('crypto') as typeof nodeCrypto;

			expect(crypto.randomBytes(8)).toHaveLength(8);
			expect(crypto.createHash('sha256').update('x').digest('hex')).toHaveLength(64);

			// poisoning attempts must not stick
			expect(() => {
				(crypto as { randomBytes: unknown }).randomBytes = () => Buffer.from('PWNED');
			}).toThrow();
			expect(crypto.randomBytes(8)).toHaveLength(8);
		});
	});

	describe('secureModuleExport (nested membrane)', () => {
		it('should wrap nested objects and block writes to them', () => {
			const shared = { count: 0 };
			const secured = secureModuleExport({ nested: shared }) as { nested: { count: number } };

			expect(() => {
				secured.nested.count = 5;
			}).toThrow();
			expect(shared.count).toBe(0); // shared nested state untouched
		});

		it('should return a stable wrapped view for the same nested object', () => {
			const secured = secureModuleExport({ nested: {} }) as { nested: object };

			expect(secured.nested).toBe(secured.nested);
		});

		it('should freeze (not wrap) non-configurable non-writable data properties', () => {
			const mod = {};
			Object.defineProperty(mod, 'FIXED', {
				value: { a: 1 },
				writable: false,
				configurable: false,
			});
			const secured = secureModuleExport(mod) as { FIXED: { a: number } };

			// Proxy invariant forbids wrapping, so it's returned raw — but frozen,
			// so it still can't be mutated for other tasks.
			expect(secured.FIXED.a).toBe(1);
			expect(Object.isFrozen(secured.FIXED)).toBe(true);
			expect(() => {
				(secured.FIXED as Record<string, unknown>).evil = 1;
			}).toThrow();
		});

		it('should wrap values reached through descriptor reflection', () => {
			const shared = { count: 0 };
			const secured = secureModuleExport({ nested: shared });

			const descriptor = Object.getOwnPropertyDescriptor(secured, 'nested');
			const reflected = descriptor?.value as { count: number };
			expect(() => {
				reflected.count = 5;
			}).toThrow();
			expect(shared.count).toBe(0); // reflection can't bypass the membrane
		});

		it('should construct classes exposed by a module', () => {
			const secured = secureModuleExport({
				widget: class {
					constructor(public v: number) {}
				},
			}) as { widget: new (v: number) => { v: number } };

			expect(new secured.widget(7).v).toBe(7);
		});

		it('should preserve new.target when subclassing a module constructor', () => {
			const secured = secureModuleExport({
				base: class {
					kind: string;
					constructor() {
						this.kind = new.target.name;
					}
				},
			}) as { base: new () => { kind: string } };
			class Derived extends secured.base {}

			expect(new Derived().kind).toBe('Derived');
		});

		it('should keep nested real-module state readable but not mutable', () => {
			const resolver = createRequireResolver({
				allowedBuiltInModules: new Set(['crypto']),
				allowedExternalModules: new Set(),
				secureModules: true,
			});
			const crypto = resolver('crypto') as typeof nodeCrypto;

			// nested reads and receiver-sensitive method calls still work
			expect(typeof crypto.constants.RSA_PKCS1_PADDING).toBe('number');
			expect(crypto.webcrypto.getRandomValues(new Uint8Array(4))).toHaveLength(4);

			// nested writes are blocked
			expect(() => {
				(crypto.webcrypto as { getRandomValues: unknown }).getRandomValues = () => null;
			}).toThrow();
			expect(crypto.webcrypto.getRandomValues(new Uint8Array(2))).toHaveLength(2);
		});
	});

	describe('error handling', () => {
		it('should wrap DisallowedModuleError in ExecutionError', () => {
			const resolver = createRequireResolver(defaultOpts);
			expect(() => resolver('non-existent-module')).toThrow(ExecutionError);
		});

		it('should include the module name in the error message', () => {
			const resolver = createRequireResolver(defaultOpts);
			expect(() => resolver('non-existent-module')).toThrow(
				"Module 'non-existent-module' is disallowed",
			);
		});
	});

	describe('child_process environment scrubbing', () => {
		const SENSITIVE = {
			ANTHROPIC_API_KEY: 'sk-secret',
			N8N_RUNNERS_GRANT_TOKEN: 'grant-token',
			N8N_RUNNERS_AUTH_TOKEN: 'auth-token',
		} as const;

		// Vitest can't spy on a builtin's ESM namespace, so drive the wrapper with
		// a plain mock module and assert on the env it forwards to each method.
		const makeMock = () => ({
			spawn: vi.fn(),
			exec: vi.fn(),
			execFile: vi.fn(),
			fork: vi.fn(),
			execSync: vi.fn(),
			execFileSync: vi.fn(),
			spawnSync: vi.fn(),
			passthrough: 'untouched',
		});

		type MockModule = ReturnType<typeof makeMock>;
		const wrap = (mock: MockModule) =>
			createSecureChildProcessWrapper(
				mock as unknown as Parameters<typeof createSecureChildProcessWrapper>[0],
			);
		const envAt = (call: unknown[], index: number): NodeJS.ProcessEnv | undefined =>
			(call[index] as { env?: NodeJS.ProcessEnv } | undefined)?.env;

		beforeEach(() => {
			Object.assign(process.env, SENSITIVE);
		});

		afterEach(() => {
			for (const key of Object.keys(SENSITIVE)) delete process.env[key];
		});

		it('strips secrets but preserves other vars for spawn/exec/execFile/fork', () => {
			const mock = makeMock();
			const cp = wrap(mock);
			const options = { env: { ...process.env, KEEP: 'yes' } };

			cp.spawn('cmd', [], options);
			cp.exec('cmd', options);
			cp.execFile('cmd', [], options);
			cp.fork('mod', [], options);

			const envs = [
				envAt(mock.spawn.mock.calls[0], 2),
				envAt(mock.exec.mock.calls[0], 1),
				envAt(mock.execFile.mock.calls[0], 2),
				envAt(mock.fork.mock.calls[0], 2),
			];
			for (const env of envs) {
				expect(env?.KEEP).toBe('yes');
				expect(env?.ANTHROPIC_API_KEY).toBeUndefined();
				expect(env?.N8N_RUNNERS_GRANT_TOKEN).toBeUndefined();
				expect(env?.N8N_RUNNERS_AUTH_TOKEN).toBeUndefined();
			}
		});

		it('strips secrets from the synchronous variants (execSync/execFileSync/spawnSync)', () => {
			const mock = makeMock();
			const cp = wrap(mock);
			const options = { env: { ...process.env } };

			cp.execSync('cmd', options);
			cp.execFileSync('cmd', [], options);
			cp.spawnSync('cmd', [], options);

			const envs = [
				envAt(mock.execSync.mock.calls[0], 1),
				envAt(mock.execFileSync.mock.calls[0], 2),
				envAt(mock.spawnSync.mock.calls[0], 2),
			];
			for (const env of envs) {
				expect(env?.ANTHROPIC_API_KEY).toBeUndefined();
				expect(env?.N8N_RUNNERS_GRANT_TOKEN).toBeUndefined();
				expect(env?.N8N_RUNNERS_AUTH_TOKEN).toBeUndefined();
			}
		});

		it('scrubs inherited process.env when no env option is given', () => {
			const mock = makeMock();

			wrap(mock).spawn('cmd');

			const env = envAt(mock.spawn.mock.calls[0], 2);
			expect(env?.ANTHROPIC_API_KEY).toBeUndefined();
			expect(env?.PATH).toBe(process.env.PATH); // unrelated vars pass through
		});

		it('passes non-spawning exports through untouched', () => {
			const wrapped = wrap(makeMock()) as unknown as { passthrough: string };
			expect(wrapped.passthrough).toBe('untouched');
		});
	});

	describe('child_process through the resolver (end-to-end)', () => {
		// Runs `node -e` so we verify the secret is genuinely absent from a real
		// child's environment — through the resolver, including the membrane.
		const PRINT_KEY = [
			'-e',
			'process.stdout.write(String(process.env.ANTHROPIC_API_KEY ?? "MISSING"))',
		];

		const resolveChildProcess = (secureModules = false) =>
			createRequireResolver({
				allowedBuiltInModules: new Set(['child_process']),
				allowedExternalModules: new Set(),
				secureModules,
			})('child_process') as typeof import('node:child_process');

		beforeEach(() => {
			process.env.ANTHROPIC_API_KEY = 'sk-secret';
		});

		afterEach(() => {
			delete process.env.ANTHROPIC_API_KEY;
		});

		it('really strips ANTHROPIC_API_KEY from a spawned subprocess', () => {
			const cp = resolveChildProcess();

			const out = cp
				.execFileSync(process.execPath, PRINT_KEY, { env: { ...process.env } })
				.toString();

			expect(out).toBe('MISSING');
		});

		it('still strips the key and blocks writes when wrapped by the membrane', () => {
			const cp = resolveChildProcess(true);

			const out = cp
				.execFileSync(process.execPath, PRINT_KEY, { env: { ...process.env } })
				.toString();
			expect(out).toBe('MISSING');

			// the wrapper is returned through the write-blocking membrane
			expect(() => {
				(cp as { spawn: unknown }).spawn = () => null;
			}).toThrow();
		});
	});
});
