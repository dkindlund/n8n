# CLAUDE.md - Task Runners Image Extension Guide

This document captures lessons learned from merging upstream n8n changes and
extending the task runners image with Claude Code CLI integration.

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Upstream Breaking Changes](#upstream-breaking-changes)
- [Image Extension Pattern](#image-extension-pattern)
- [Critical Lessons Learned](#critical-lessons-learned)
- [Configuration Guide](#configuration-guide)
- [Troubleshooting](#troubleshooting)

## Overview

This fork extends the n8n task runners image with:
- **Claude Code CLI** for AI-powered code assistance
- **Security patches** in the task-runner source code to protect API tokens
- **Additional dependencies** for Claude Agent SDK integration
- **Enhanced capabilities** while maintaining upstream compatibility

## Architecture

### Layer Structure

```
┌─────────────────────────────────────────────────────────────┐
│ LAYER 1: Source Code (Fork Modifications)                  │
│ packages/@n8n/task-runner/src/js-task-runner/               │
│ ├── js-task-runner.ts (monkey patches)                     │
│ └── require-resolver.ts (security wrappers)                │
└─────────────────────────────────────────────────────────────┘
                            ↓
                    pnpm run build:n8n
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LAYER 2: Compiled Artifacts                                │
│ dist/task-runner-javascript/ (includes patched code)       │
└─────────────────────────────────────────────────────────────┘
                            ↓
                   Docker COPY command
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LAYER 3: Base Image (Dockerfile)                           │
│ gcr.io/PROJECT/n8n-runners-base:latest                     │
│ ├── Upstream's clean Dockerfile                            │
│ ├── Contains: patched js-task-runner                       │
│ └── Contains: pnpm-created node_modules                    │
└─────────────────────────────────────────────────────────────┘
                            ↓
              FROM base image
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LAYER 4: Extended Image (Dockerfile.extended)              │
│ gcr.io/PROJECT/n8n-runners:latest                          │
│ ├── Adds: Claude Code CLI                                  │
│ ├── Adds: System tools (git, bash, curl, npm)              │
│ ├── Adds: Extra modules in /opt/extra-modules              │
│ └── Sets: NODE_PATH for dual module resolution             │
└─────────────────────────────────────────────────────────────┘
```

### Key Insight: Separation of Concerns

- **Source code patches** = TypeScript modifications in your fork
- **Docker customizations** = Image build instructions in Dockerfile.extended
- **Both are independent** but work together

## Upstream Breaking Changes

### PR #22079: Removed Build-Time Dependency Injection

**What Changed**:
- ❌ Removed `package.json` and `extras.txt` files from Docker build
- ❌ Removed build-time `pnpm install` and `uv pip install` steps
- ✅ Added cleanup script to remove `catalog:` and `workspace:` references
- ✅ New pattern: extend the image instead of modifying the build

**Migration Path**:
Instead of copying `package.json` during build, users should now extend the
base image and add dependencies at runtime using `pnpm add` or `npm install`.

## Image Extension Pattern

### Dockerfile.extended Strategy

```dockerfile
# Start from base image
FROM n8nio/runners-base:latest

USER root

# Install system dependencies
RUN apk add --no-cache git bash curl

# Install Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code

# Install extra packages to SEPARATE location
# CRITICAL: Do NOT delete the original node_modules!
RUN mkdir -p /opt/extra-modules && \
    cd /opt/extra-modules && \
    npm init -y && \
    npm install --legacy-peer-deps \
        @anthropic-ai/claude-agent-sdk@latest \
        @anthropic-ai/sdk@latest \
        moment@2.30.1

USER runner
```

### Why This Approach

**DON'T**: Delete and rebuild node_modules
```dockerfile
# ❌ WRONG - Destroys task-runner's core dependencies
RUN rm -rf node_modules && npm install
```

**DO**: Install to separate location with NODE_PATH
```dockerfile
# ✅ CORRECT - Preserves core deps, adds extras separately
RUN mkdir -p /opt/extra-modules && \
    cd /opt/extra-modules && \
    npm install --legacy-peer-deps your-packages
```

## Critical Lessons Learned

### 1. pnpm vs npm in Docker Extensions

**Problem**: pnpm store location conflicts
```
ERR_PNPM_UNEXPECTED_STORE
The dependencies at "node_modules" are currently linked from the store at
"/workspace/.pnpm-store/v10".
pnpm now wants to use the store at "/root/.local/share/pnpm/store/v10"
```

**Solution**: Use npm (not pnpm) in extended images
- Base image uses pnpm during build (with store at build time)
- Extended image uses npm (doesn't need pnpm store)

### 2. Workspace Protocol Errors

**Problem**: npm doesn't understand `workspace:` references
```
npm error Unsupported URL Type "workspace:": workspace:^
```

**Root Causes**:
1. `workspace:` refs in package.json
2. `workspace:` refs in pnpm metadata files (node_modules/.modules.yaml)
3. `workspace:` refs in individual package.json files inside node_modules

**Solution**: The base Dockerfile already cleans package.json. DON'T try to
clean it again or reinstall - you'll break the task-runner's dependencies.

### 3. Preserving Task-Runner Dependencies

**Critical Discovery**: The task-runner's node_modules from the base image
contains essential dependencies installed by pnpm:
- `@n8n/di` (dependency injection)
- `@n8n/errors` (error handling)
- Many internal @n8n packages with `workspace:` refs

**If you delete node_modules**:
```
Error: Cannot find module '@n8n/di'
```

**Correct approach**: Keep the original node_modules, install extras elsewhere.

### 4. Peer Dependency Conflicts

**Problem**: Version mismatches between packages
```
npm error peer zod@"^3.24.1" from @anthropic-ai/claude-agent-sdk
npm error Found: zod@4.1.12
```

**Solution**: Use `--legacy-peer-deps` flag
```dockerfile
RUN npm install --legacy-peer-deps package-name
```

### 5. NODE_PATH Module Resolution

**Two Locations for Modules**:
```
/opt/runners/task-runner-javascript/node_modules/  ← Core task-runner deps
/opt/extra-modules/node_modules/                    ← Our extra packages
```

**Configuration Required**:
```json
{
  "allowed-env": ["NODE_PATH"],  // ← Must whitelist the variable
  "env-overrides": {
    "NODE_PATH": "/opt/runners/task-runner-javascript/node_modules:/opt/extra-modules/node_modules"
  }
}
```

**Common Mistake**: Setting env-overrides without allowed-env
- The launcher will ignore the override if the variable isn't whitelisted
- Result: Module not found errors

## Configuration Guide

### n8n-task-runners.json Structure

```json
{
  "task-runners": [
    {
      "runner-type": "javascript",
      "allowed-env": [
        // Whitelist of environment variables that CAN be passed to runner
        "PATH",
        "NODE_PATH",    // Required for dual module paths
        "SHELL",
        "ANTHROPIC_API_KEY",
        // ... etc
      ],
      "env-overrides": {
        // Values the launcher SETS for whitelisted variables
        "NODE_PATH": "/path1:/path2",
        "NODE_FUNCTION_ALLOW_BUILTIN": "crypto,child_process,stream,fs",
        "NODE_FUNCTION_ALLOW_EXTERNAL": "moment,@anthropic-ai/claude-agent-sdk"
      }
    }
  ]
}
```

### Built-in vs External Modules

**Built-in Modules** (NODE_FUNCTION_ALLOW_BUILTIN):
- Node.js core modules: `crypto`, `fs`, `stream`, `child_process`, etc.
- No installation required
- Just whitelist them

**External Modules** (NODE_FUNCTION_ALLOW_EXTERNAL):
- npm packages: `moment`, `axios`, `@anthropic-ai/claude-agent-sdk`, etc.
- Must be installed (either in base image or extended image)
- Must be whitelisted

### Adding New Built-in Modules

To allow a built-in module like `fs`:

1. Add to `NODE_FUNCTION_ALLOW_BUILTIN` in n8n-task-runners.json:
```json
"NODE_FUNCTION_ALLOW_BUILTIN": "crypto,child_process,stream,fs"
```

2. Rebuild the image (config is baked in)
3. Restart the runner container

### Adding New External Packages

To add a new npm package:

1. Install to `/opt/extra-modules` in Dockerfile.extended:
```dockerfile
RUN cd /opt/extra-modules && \
    npm install --legacy-peer-deps your-new-package
```

2. Add to `NODE_FUNCTION_ALLOW_EXTERNAL` in n8n-task-runners.json:
```json
"NODE_FUNCTION_ALLOW_EXTERNAL": "moment,...,your-new-package"
```

3. Rebuild both base and extended images
4. Restart the runner container

## Configuration Reload Behavior

### Important: Config is Cached at Startup

The task-runner-launcher reads `/etc/n8n-task-runners.json` (or path from
`N8N_RUNNERS_CONFIG_PATH`) **once at startup** and caches it in memory.

**When runners auto-shutdown** (via `N8N_RUNNERS_AUTO_SHUTDOWN_TIMEOUT`):
- ❌ The launcher does NOT re-read the config file
- ✅ The launcher re-spawns runners using the CACHED config
- ⚠️ Config changes won't take effect until you restart the launcher

**To Apply Config Changes**:
```bash
# Must restart the entire launcher container
docker restart n8n-runners
# Or in Kubernetes
kubectl rollout restart deployment/n8n-runners
```

### Using N8N_RUNNERS_CONFIG_PATH for Overrides

**Valid Environment Variable**: `N8N_RUNNERS_CONFIG_PATH`

You can override the config file location:
```bash
docker run \
  -e N8N_RUNNERS_CONFIG_PATH=/config/custom-runners.json \
  -v ./custom-runners.json:/config/custom-runners.json:ro \
  n8nio/runners
```

**Benefits**:
- ✅ Default config baked into image (works out of the box)
- ✅ Runtime customization without rebuilding
- ✅ Environment-specific overrides (dev vs. prod)

**Limitation**: Still requires container restart to pick up config changes.

## Troubleshooting

### Build Errors

#### "Unsupported URL Type: workspace:"
**Cause**: npm found `workspace:` references in package.json or pnpm metadata

**Solution**: Don't reinstall node_modules in extended image. Use separate
location for extra packages.

#### "ERESOLVE unable to resolve dependency tree"
**Cause**: Peer dependency version conflicts (e.g., zod 3.x vs 4.x)

**Solution**: Use `--legacy-peer-deps` flag:
```dockerfile
RUN npm install --legacy-peer-deps package-name
```

#### "ERR_PNPM_UNEXPECTED_STORE"
**Cause**: Trying to use `pnpm add` in extended image with mismatched stores

**Solution**: Use `npm install` instead of `pnpm add` in extended images.

### Runtime Errors

#### "Cannot find module '@n8n/di'"
**Cause**: Task-runner's core dependencies were deleted/missing

**Solution**: NEVER delete `/opt/runners/task-runner-javascript/node_modules`
- This directory contains essential task-runner dependencies
- Install extras to `/opt/extra-modules` instead
- Use NODE_PATH to access both locations

#### "Cannot find module 'moment'" (or other extra packages)
**Cause**: NODE_PATH not properly configured

**Solution**: Check BOTH places in n8n-task-runners.json:
1. ✅ `"allowed-env": ["NODE_PATH"]` - Whitelist the variable
2. ✅ `"env-overrides": {"NODE_PATH": "/path1:/path2"}` - Set the value

Both are required!

### Deployment Issues

#### Config changes not taking effect
**Cause**: Launcher caches config at startup

**Solution**:
1. Rebuild image with new config
2. Restart the launcher container (not just the runners)

#### Module not accessible in Code node
**Cause**: Module not whitelisted in NODE_FUNCTION_ALLOW_EXTERNAL

**Solution**:
1. Install the package in Dockerfile.extended
2. Add to NODE_FUNCTION_ALLOW_EXTERNAL in n8n-task-runners.json
3. Rebuild image
4. Restart container

## Build Process

### Two-Stage Build

```bash
# 1. Build base image (upstream's clean version)
docker buildx build \
  -f docker/images/runners/Dockerfile \
  -t gcr.io/PROJECT/n8n-runners-base:latest \
  .

# 2. Build extended image (with Claude Code)
docker buildx build \
  -f docker/images/runners/Dockerfile.extended \
  --build-arg BASE_IMAGE=gcr.io/PROJECT/n8n-runners-base:latest \
  -t gcr.io/PROJECT/n8n-runners:latest \
  .
```

### Cloud Build (cloudbuild.yaml)

The build pipeline:
1. **Step 0**: Build n8n artifacts (`pnpm run build:n8n`)
2. **Step 1**: Build base image → `n8n-runners-base:$COMMIT_SHA`
3. **Step 2**: Build extended image → `n8n-runners:$COMMIT_SHA`

Each step depends on the previous one completing successfully.

## Security Patches

### Monkey Patches in Source Code

**Location**: `packages/@n8n/task-runner/src/js-task-runner/`

**What they do**:
1. **Global child_process patching** (`js-task-runner.ts:144`)
   - Strips `N8N_RUNNERS_GRANT_TOKEN` and `N8N_RUNNERS_AUTH_TOKEN` from subprocesses
   - Auto-disables prompt caching for non-Anthropic models
   - Protects against token leakage to untrusted code

2. **Require resolver wrapper** (`require-resolver.ts:56`)
   - Wraps `child_process` module when required by user code
   - Strips `ANTHROPIC_API_KEY`, `N8N_RUNNERS_GRANT_TOKEN`, `N8N_RUNNERS_AUTH_TOKEN`
   - Additional layer of defense

**Why they work in both images**:
- Patches are in TypeScript source code (git fork)
- Compiled to JavaScript during `pnpm build`
- Copied to both base and extended images via `COPY ./dist/...`
- Activate at runtime when task-runner starts

**No Docker changes needed** - these are source code modifications.

## Best Practices

### DO ✅

1. **Use npm in extended images** - Avoids pnpm store conflicts
2. **Install extras to /opt/extra-modules** - Preserves core dependencies
3. **Set NODE_PATH in both places** - allowed-env AND env-overrides
4. **Use --legacy-peer-deps** - Handles version conflicts gracefully
5. **Match upstream's cleanup logic** - Remove catalog: and workspace: refs thoroughly
6. **Test builds early** - Each iteration takes ~30 minutes

### DON'T ❌

1. **Don't delete node_modules** - Contains critical task-runner dependencies
2. **Don't use pnpm in extended images** - Store location conflicts
3. **Don't forget allowed-env** - env-overrides alone doesn't work
4. **Don't expect hot-reload** - Config is cached, requires container restart
5. **Don't skip comprehensive cleanup** - Check both dependencies AND devDependencies
6. **Don't assume changes apply immediately** - Image must be rebuilt and redeployed

## File Reference

### Key Files

- `Dockerfile` - Upstream base image (keep clean, merge upstream changes)
- `Dockerfile.extended` - Our customizations (Claude Code, extra deps)
- `n8n-task-runners.json` - Runner configuration (baked into image)
- `cloudbuild.yaml` - Two-stage build pipeline for GCP
- `README.md` - Build and usage documentation

### Configuration Locations

**In Image**:
- `/etc/n8n-task-runners.json` - Default config (baked in)
- `/opt/runners/task-runner-javascript/` - Task runner code
- `/opt/extra-modules/` - Our additional packages
- `/usr/local/bin/claude` - Claude Code CLI

**Source Code**:
- `packages/@n8n/task-runner/src/js-task-runner/js-task-runner.ts` - Security patches
- `packages/@n8n/task-runner/src/js-task-runner/require-resolver.ts` - Module wrapper

## Future Upstream Merges

### Merge Strategy

1. **Fetch upstream changes**:
   ```bash
   git fetch upstream master
   ```

2. **Test merge first** (don't commit):
   ```bash
   git merge --no-commit --no-ff upstream/master
   ```

3. **Check for conflicts**:
   ```bash
   git diff --name-only --diff-filter=U
   ```

4. **Resolve conflicts**:
   - Keep `Dockerfile` clean (upstream version)
   - Preserve `Dockerfile.extended` customizations
   - Merge `n8n-task-runners.json` carefully (combine allowed-env lists)
   - Keep source code patches (usually no conflicts)

5. **Abort if needed**:
   ```bash
   git merge --abort
   ```

### Likely Conflict Points

- `docker/images/runners/Dockerfile` - Keep upstream's version
- `docker/images/runners/n8n-task-runners.json` - Merge our env vars with upstream's
- `packages/@n8n/task-runner/` - Usually no conflicts (our patches only)

## Additional Notes

### Why Two-Stage Build?

**Base Image** (`n8n-runners-base`):
- Upstream compatible
- Can be used as-is if Claude Code not needed
- Easier to merge future upstream changes

**Extended Image** (`n8n-runners`):
- Our customizations isolated
- Can rebuild quickly without rebuilding base
- Clear separation of concerns

### Module Resolution Order

When user code does `require('moment')`:
1. Check `/opt/runners/task-runner-javascript/node_modules/` (via NODE_PATH)
2. Check `/opt/extra-modules/node_modules/` (via NODE_PATH)
3. Check global node_modules
4. Fail if not found

This allows:
- Task-runner to find its core dependencies (@n8n/di)
- User code to find both core and extra packages (moment, claude-agent-sdk)
- No conflicts between the two

### Cost Optimization

**Build time**: ~30 minutes per full build
- Step 0 (artifacts): ~17 minutes
- Step 1 (base image): ~2 minutes (with cache)
- Step 2 (extended image): ~1 minute (with cache)

**Recommendations**:
- Use Cloud Build caching (--cache=true, --cache-ttl=168h)
- Only rebuild when necessary
- Test Dockerfile changes locally first with small test images

---

**Last Updated**: 2025-11-21
**Based on**: n8n v1.121.0, task-runner-launcher v1.4.1
