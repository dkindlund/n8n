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
};

export type RequireResolver = (request: string) => unknown;

export function createRequireResolver({
	allowedBuiltInModules,
	allowedExternalModules,
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

		const module = require(request) as unknown;

		// Wrap child_process to strip sensitive environment variables from subprocesses
		if (request === 'child_process') {
			return createSecureChildProcessWrapper(module);
		}

		return module;
	};
}

/**
 * Creates a wrapper around child_process that strips sensitive environment
 * variables before spawning subprocesses. This prevents API keys and tokens
 * from being inherited by untrusted code analysis subprocesses.
 */
function createSecureChildProcessWrapper(childProcess: any) {
	const SENSITIVE_ENV_VARS = [
		'ANTHROPIC_API_KEY',
		'N8N_RUNNERS_GRANT_TOKEN',
		'N8N_RUNNERS_AUTH_TOKEN',
	];

	const stripSensitiveEnvVars = (env?: Record<string, string | undefined>) => {
		if (!env) {
			// If no env specified, use process.env but strip sensitive vars
			const cleaned = { ...process.env };
			SENSITIVE_ENV_VARS.forEach((key) => delete cleaned[key]);
			return cleaned;
		}

		// If env is specified, strip sensitive vars from it
		const cleaned = { ...env };
		SENSITIVE_ENV_VARS.forEach((key) => delete cleaned[key]);
		return cleaned;
	};

	return {
		...childProcess,
		spawn: (command: string, args?: readonly string[], options?: any) => {
			const secureOptions = {
				...options,
				env: stripSensitiveEnvVars(options?.env),
			};
			return childProcess.spawn(command, args, secureOptions);
		},
		exec: (command: string, options?: any, callback?: any) => {
			const secureOptions = {
				...options,
				env: stripSensitiveEnvVars(options?.env),
			};
			return childProcess.exec(command, secureOptions, callback);
		},
		execFile: (file: string, args?: any, options?: any, callback?: any) => {
			const secureOptions = {
				...options,
				env: stripSensitiveEnvVars(options?.env),
			};
			return childProcess.execFile(file, args, secureOptions, callback);
		},
		fork: (modulePath: string, args?: readonly string[], options?: any) => {
			const secureOptions = {
				...options,
				env: stripSensitiveEnvVars(options?.env),
			};
			return childProcess.fork(modulePath, args, secureOptions);
		},
	};
}
