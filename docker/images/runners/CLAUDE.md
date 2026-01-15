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
- [Build Monitoring with gcloud](#build-monitoring-with-gcloud)
- [Troubleshooting](#troubleshooting)
- [Adding Comprehensive Linux Toolset](#adding-comprehensive-linux-toolset)
- [Quick Reference: Common Library Dependencies](#quick-reference-common-library-dependencies)

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

## Build Monitoring with gcloud

### Finding Latest Build Status

After pushing code changes, a Cloud Build automatically triggers. Monitor it:

**1. Find the latest build ID:**
```bash
gcloud builds list \
  --region=us-east4 \
  --limit=5 \
  --format=json(id,createTime,status)
```

This returns recent builds with their IDs and status (QUEUED, WORKING, SUCCESS, FAILURE).

**2. Fetch build logs:**
```bash
# Replace BUILD_ID with the actual ID from step 1
gcloud logging read \
  resource.labels.build_id=BUILD_ID \
  --project=GCP_PROJECT_ID \
  --order=desc \
  --limit=50 \
  --format='value(timestamp,textPayload)'
```

**3. Monitor specific build steps:**
```bash
# Watch Step #2 (extended image build) specifically
gcloud logging read \
  resource.labels.build_id=BUILD_ID \
  --project=GCP_PROJECT_ID \
  --order=asc \
  --format='value(textPayload)' \
  | grep "Step #2"
```

### Typical Workflow

```bash
# 1. Make changes and push
git add .
git commit -m "fix: your change"
git push origin master

# 2. Wait 30 seconds for build to queue
sleep 30

# 3. Find the new build
BUILD_ID=$(gcloud builds list --region=us-east4 --limit=1 --format='value(id)')

# 4. Monitor logs
gcloud logging read \
  resource.labels.build_id=$BUILD_ID \
  --project=GCP_PROJECT_ID \
  --order=desc \
  --limit=100 \
  --format='value(timestamp,textPayload)'
```

### Build Step Breakdown

- **Step #0** (build-artifacts): TypeScript compilation, ~4-6 minutes
- **Step #1** (build-base-image): Base runner image, ~1-2 minutes
- **Step #2** (build-extended-image): Claude Code + tools, ~1-2 minutes

Total: ~6-10 minutes (with caching)

## Troubleshooting

### Docker Image Extension Issues

#### "Error loading shared library libXXX.so: No such file or directory"
**Cause**: Binary depends on a library that wasn't copied from tools-installer

**Diagnosis**: The error shows which tool and which library:
```
Error loading shared library libpcre2-8.so.0: No such file or directory (needed by git)
```

**Solution**: Copy the missing library in Dockerfile.extended:
```dockerfile
COPY --from=tools-installer /usr/lib/libpcre2-8.so.* /usr/lib/
```

#### "failed to eval symlinks: EvalSymlinks: too many links"
**Cause**: Trying to copy a library that already exists in base image with conflicting symlinks

**Example**: `libz.so.*` exists in python:3.13-alpine base image
```
COPY --from=tools-installer /usr/lib/libz.so.* /usr/lib/  # ❌ CONFLICTS
```

**Solution**: Skip libraries already in base image
- Base image (python:3.13-alpine) includes: libz, libbz2, liblzma, libgcc_s
- Only copy libraries that DON'T exist in base image
- Use "WARN No files to copy" messages to identify which libraries don't exist

#### "exit status 1" with no output from RUN commands
**Cause**: Could be several issues:
1. Unicode characters (✓, ⚠) in echo statements - busybox shell doesn't support UTF-8
2. `set -e` combined with complex subshell logic
3. RUN with bind mounts failing mysteriously in Kaniko

**Solutions**:
1. **Use ASCII only** in echo statements:
   ```dockerfile
   # ❌ Fails in busybox
   echo "  ✓ Copied successfully"

   # ✅ Works
   echo "  [OK] Copied successfully"
   ```

2. **Remove set -e** if using conditional logic:
   ```dockerfile
   # ❌ Can fail silently with set -e
   RUN set -e && (command || echo "warning")

   # ✅ Better - let conditionals handle errors
   RUN (command || echo "warning")
   ```

3. **Use simple COPY instead of RUN + bind mounts**:
   ```dockerfile
   # ❌ Mysteriously fails in Kaniko
   RUN --mount=type=bind,from=tools-installer,source=/usr/lib,target=/src \
       cp /src/lib*.so.* /usr/lib/

   # ✅ Simple and reliable
   COPY --from=tools-installer /usr/lib/libcurl.so.* /usr/lib/
   ```

#### Chicken-and-Egg: /bin/sh needs library to run RUN commands
**Symptom**:
```
Error loading shared library libpcre2-8.so.0 (needed by /bin/sh)
exit status 127
```

**Cause**: Busybox /bin/sh needs libpcre2 to execute, but you're trying to use a RUN command to copy libpcre2

**Solution**: Copy libpcre2 using COPY (doesn't need shell) BEFORE any RUN commands:
```dockerfile
# ✅ COPY doesn't need /bin/sh - copy libpcre2 first
COPY --from=tools-installer /usr/lib/libpcre2-8.so.* /usr/lib/

# ✅ Now RUN commands work because /bin/sh has libpcre2
RUN echo "Shell works now!"
```

#### CRITICAL: Busybox Hardlink Corruption

**MOST IMPORTANT ISSUE** - This will break ALL shell commands if not handled correctly.

**Symptom**:
```
mkdir: invalid option -- 'p'
Usage: mkdir [OPTION]... PATTERNS [FILE]...
```

Every command (mkdir, ls, cat, tar, etc.) shows **grep's usage message** instead of working.

**Root Cause**:

When `apk add grep` (or tar, gzip, etc.) in Alpine, if the tool is also a busybox applet:
1. Alpine replaces `/bin/busybox` with the full version (e.g., GNU grep)
2. Creates **hardlink**: `/bin/grep` ⇔ `/bin/busybox` (same inode)
3. Both files point to the SAME data (the grep binary)

When you `COPY --from=tools-installer /bin/grep`:
- Kaniko **preserves the hardlink**
- Copies BOTH /bin/grep AND /bin/busybox as grep binary
- **Overwrites the base image's real busybox** with grep!
- All busybox applets break (mkdir, chmod, rm, ls, cat, cp, mv, touch, head, tail, etc.)

**Detection**:
```javascript
// Runtime test to detect this issue
const fs = require('fs');
const busyboxStat = fs.statSync('/bin/busybox');
const grepStat = fs.statSync('/bin/grep');

if (busyboxStat.ino === grepStat.ino) {
  console.log('HARDLINK DETECTED - busybox is corrupted!');
}

// Check what busybox actually is
const { execSync } = require('child_process');
const version = execSync('busybox --version 2>&1', { shell: '/bin/bash', encoding: 'utf-8' });
if (version.includes('grep')) {
  console.log('CONFIRMED: busybox has been replaced with grep!');
}
```

**Solution - Category-Wide Rule**:

**NEVER copy tools from /bin/ except bash:**

```dockerfile
# ✅ SAFE: Only copy bash from /bin/
COPY --from=tools-installer /bin/bash /bin/bash

# ❌ DANGEROUS: Never copy these (hardlinked to busybox)
# COPY --from=tools-installer /bin/grep /bin/grep
# COPY --from=tools-installer /bin/tar /bin/tar
# COPY --from=tools-installer /bin/gzip /bin/gzip
# COPY --from=tools-installer /bin/cat /bin/cat
# COPY --from=tools-installer /bin/ls /bin/ls
# etc.

# ✅ SAFE: Copy tools from /usr/bin/ (not busybox applets)
COPY --from=tools-installer /usr/bin/git /usr/bin/git
COPY --from=tools-installer /usr/bin/curl /usr/bin/curl
# etc.
```

**Prevent at Source - Don't Install Replacements**:

```dockerfile
# In tools-installer:
RUN apk add --no-cache \
    git \
    bash \
    curl \
    wget \
    ripgrep \
    jq \
    make \
    file \
    tree \
    # ❌ DON'T add these (they replace busybox applets via hardlinks):
    # grep, tar, gzip - CONFIRMED corrupts busybox
    # unzip - CONFIRMED corrupts busybox (test showed busybox became unzip)
    # findutils (find, xargs) - replaces busybox applets
    # less - replaces busybox applet
    # coreutils (mkdir, chmod, etc.) - replaces busybox applets
```

**Complete List of Dangerous Packages** (verified via testing and web research):

| Package | Provides | Location | Danger | Evidence |
|---------|----------|----------|--------|----------|
| grep | grep, egrep, fgrep | /bin/ | ❌ HARDLINK | Creates /bin/grep ⇔ /bin/busybox |
| tar | tar | /bin/ | ❌ HARDLINK | Replaces /bin/busybox |
| gzip | gzip, gunzip | /bin/ | ❌ HARDLINK | Replaces /bin/busybox |
| **unzip** | **unzip** | **/usr/bin/** | ❌ **HARDLINK** | **CONFIRMED: busybox became unzip (test)** |
| **tree** | **tree** | **/usr/bin/** | ❌ **HARDLINK** | **CONFIRMED: busybox became tree (test)** |
| **wget** | **wget** | **/usr/bin/** | ❌ **HARDLINK** | **CONFIRMED: inode 15379 = busybox inode** |
| **file** | **file** | **/usr/bin/** | ❌ **HARDLINK** | Busybox applet (per docs) |
| findutils | find, xargs | /usr/bin/ | ❌ HARDLINK | Replaces busybox applets |
| less | less | /usr/bin/ | ❌ HARDLINK | Replaces busybox applet |
| coreutils | mkdir, chmod, rm, cp, mv, ls, cat, etc. | /usr/bin/ | ❌ HARDLINK | Replaces 100+ busybox applets |

**Critical Insight**: Hardlinks can occur in **ANY directory** (/bin/ OR /usr/bin/)! The key is whether the tool is a busybox applet, NOT which directory it's in.

**Safe Packages** (verified via inode testing to NOT be busybox applets):

| Package | Purpose | Safe? | Verification Method |
|---------|---------|-------|---------------------|
| git | Version control | ✅ YES | Too complex for busybox, different binary |
| bash | Full shell | ✅ YES | Standalone binary, not busybox applet |
| **curl** | **HTTP client** | ✅ **YES** | **VERIFIED: inode 15376 ≠ busybox inode 15379** |
| ripgrep (rg) | Fast grep alternative | ✅ YES | Rust program, completely different from busybox grep |
| jq | JSON processor | ✅ YES | NOT in busybox at all |
| make | Build tool | ✅ YES | GNU make, not in busybox |

**Inode Verification Methodology**:
```javascript
// Test any tool before adding to Dockerfile
const fs = require('fs');
const toolInode = fs.statSync('/usr/bin/TOOL').ino;
const busyboxInode = fs.statSync('/bin/busybox').ino;
const isSafe = toolInode !== busyboxInode;
// If isSafe = true, tool can be safely copied
```

**Why Base Image's Busybox is Sufficient**:
- Base image has working busybox with 300+ essential applets
- Busybox versions work fine for Claude Code's static analysis needs
- No need for GNU versions (busybox sufficient for shell operations)
- Avoids hardlink corruption entirely
- Maintains system stability

**THE COMPLETE FIX FOR BUSYBOX CORRUPTION**:

The base image itself may have busybox corruption. Here's the complete solution:

```dockerfile
# STEP 1: Delete all corrupted hardlinks from base image
RUN rm -f /bin/grep /bin/egrep /bin/fgrep /bin/tar /bin/gzip /bin/gunzip /bin/zcat /bin/busybox || true

# STEP 2: Copy clean busybox from tools-installer
COPY --from=tools-installer /bin/busybox /bin/busybox

# STEP 3: Reinstall all busybox applets using CLEAN busybox
RUN mkdir -p /tmp && chmod 1777 /tmp && \
    /bin/busybox --install -s /usr/bin
```

**Why This Works**:
1. `rm -f` removes all corrupted files that were hardlinked to busybox
2. Clean busybox is copied from tools-installer (where packages don't corrupt it)
3. `busybox --install -s` creates proper **symlinks** (not hardlinks) for all applets
4. Symlinks point to the clean busybox binary

**Testing Symlinks vs Hardlinks**:
```javascript
// WRONG: statSync follows symlinks, can't distinguish symlink from hardlink
const grepStat = fs.statSync('/usr/bin/grep'); // Follows symlink to busybox
if (grepStat.ino === busyboxInode) {
  // This triggers for BOTH symlinks (correct) and hardlinks (bad)
}

// CORRECT: lstatSync does NOT follow symlinks
const grepStat = fs.lstatSync('/usr/bin/grep'); // Doesn't follow symlink
if (grepStat.isSymbolicLink()) {
  console.log('✓ Symlink (correct) - busybox is safe');
} else if (grepStat.ino === busyboxInode) {
  console.log('✗ Hardlink (corruption) - busybox is broken');
}
```

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

#### "no such file or directory" for /usr/local/bin/npm

**Cause**: npm location differs between official node images and apk-installed nodejs

**When using apk add nodejs npm** (in python:3.13-alpine):
- npm binary: `/usr/bin/npm` (not /usr/local/bin/npm)
- npx binary: `/usr/bin/npx` (not /usr/local/bin/npx)
- npm packages: `/usr/lib/node_modules/npm` (not /usr/local/lib/node_modules/npm)

**When using official node:alpine images**:
- npm binary: `/usr/local/bin/npm`
- npx binary: `/usr/local/bin/npx`
- npm packages: `/usr/local/lib/node_modules/npm`

**Solution**: Match COPY paths to your installation method:
```dockerfile
# If using apk add nodejs:
COPY --from=tools-installer /usr/bin/npm /usr/bin/npm
COPY --from=tools-installer /usr/lib/node_modules/npm /usr/lib/node_modules/npm

# If using official node image:
COPY --from=tools-installer /usr/local/bin/npm /usr/local/bin/npm
COPY --from=tools-installer /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
```

### Runtime Errors

#### child_process returns "0\n" for all commands

**Symptom**:
```javascript
const { execSync } = require('child_process');
execSync('echo test', { encoding: 'utf-8' })  // Returns: "0\n"
execSync('git --version', { encoding: 'utf-8' })  // Returns: "0\n"
```

Every command returns just "0\n" with no stderr, no actual execution.

**Root Causes**:

**Cause 1: Alpine Version Mismatch**
- tools-installer uses node:22-alpine (Alpine 3.22)
- Base uses python:3.13-alpine (Alpine 3.20)
- libpcre2 version mismatch → /bin/sh crashes silently
- Fix: Use **same base image** (python:3.13-alpine) for tools-installer

**Cause 2: Busybox Hardlink Corruption** (see section above)
- Copying /bin/grep overwrites /bin/busybox
- All busybox applets break
- Fix: Never copy from /bin/ except bash

**Cause 3: Default Shell (/bin/sh) Broken**
- /bin/sh is busybox, often has issues
- /bin/bash works reliably
- Fix: **Always specify shell: '/bin/bash'**

**Solution Pattern**:
```javascript
// ❌ WRONG: Uses /bin/sh (default)
execSync('mkdir -p /tmp/test')

// ✅ CORRECT: Explicitly use bash
execSync('mkdir -p /tmp/test', { shell: '/bin/bash' })

// ✅ BEST: Create wrapper for consistency
function exec(cmd, opts = {}) {
  return execSync(cmd, { ...opts, shell: '/bin/bash' });
}
```

**Diagnostic Approach**:

When child_process fails, test in this order:
1. Does fs module work? (bypasses shell entirely)
2. Does bash work? `execSync('echo test', { shell: '/bin/bash' })`
3. Does sh work? `execSync('echo test', { shell: '/bin/sh' })`
4. Check for hardlink corruption: `fs.statSync('/bin/busybox').ino === fs.statSync('/bin/grep').ino`
5. Check libpcre2: `fs.existsSync('/usr/lib/libpcre2-8.so.0')`

#### "Command failed: mkdir -p /tmp/..." or /tmp not writable
**Cause**: `/tmp` directory doesn't exist or lacks proper permissions for runner user

**Symptom**: Code using child_process to create temp directories fails:
```javascript
execSync('mkdir -p /tmp/mydir')  // ❌ Fails
```

**Solution**: Create `/tmp` with sticky bit BEFORE library copies in Dockerfile.extended:
```dockerfile
FROM ${BASE_IMAGE}
USER root

# Must be BEFORE library copies (Kaniko RUN bug kicks in after)
RUN mkdir -p /tmp && chmod 1777 /tmp

# Then copy libraries...
```

The `1777` permissions = sticky bit + world writable (standard for `/tmp`).

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

### Complete Library Fix Solutions

This section documents the comprehensive fixes for all library dependency issues encountered.

#### curl Missing Compression Libraries

**Symptoms**:
```
Error relocating /usr/lib/libcurl.so.4: BrotliDecoderVersion: symbol not found
Error relocating /usr/lib/libcurl.so.4: ZSTD_versionNumber: symbol not found
Error relocating /usr/lib/libcurl.so.4: psl_latest: symbol not found
Error loading shared library libbrotlidec.so.1: No such file or directory
Error loading shared library libzstd.so.1: No such file or directory
Error loading shared library libpsl.so.5: No such file or directory
```

**Root Cause**: curl was compiled with support for modern compression formats (Brotli, Zstandard) and cookie domain validation (PSL), but the required libraries weren't copied.

**Complete Solution**:
```dockerfile
# Compression libraries (needed by curl for Brotli, Zstandard support)
COPY --from=tools-installer /usr/lib/libbrotlidec.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libbrotlicommon.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libzstd.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libpsl.so.* /usr/lib/

# Also need HTTP/3 support libraries
COPY --from=tools-installer /usr/lib/libnghttp3.so.* /usr/lib/
```

**Verification**:
```bash
curl --version
# Should show: brotli/1.2.0 zstd/1.5.7 libpsl/0.21.5 nghttp3/1.13.1
```

#### jq Missing Library

**Symptom**:
```
Error loading shared library libjq.so.1: No such file or directory (needed by /usr/bin/jq)
```

**Solution**:
```dockerfile
# Tool-specific libraries (added by jq, file packages)
COPY --from=tools-installer /usr/lib/libjq.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libonig.so.* /usr/lib/
```

#### git HTTPS Cloning Fails

**Symptom**:
```
git: 'remote-https' is not a git command. See 'git --help'.
fatal: remote helper 'https' aborted session
```

**Root Cause**: Only the main git binary was copied, but git uses separate "helper" programs for different protocols (HTTPS, HTTP, FTP, SSH).

**Complete Solution**:
```dockerfile
# Git binary
COPY --from=tools-installer /usr/bin/git /usr/bin/git

# Git helper programs (CRITICAL for HTTPS/HTTP cloning)
# Includes git-remote-https, git-remote-http, and 160+ other utilities
COPY --from=tools-installer /usr/libexec/git-core /usr/libexec/git-core

# Git templates (prevents "templates not found" warning)
COPY --from=tools-installer /usr/share/git-core/templates /usr/share/git-core/templates
```

**What This Includes**:
- `git-remote-https` - HTTPS protocol handler
- `git-remote-http` - HTTP protocol handler
- `git-remote-ftp` - FTP protocol handler
- `git-remote-ftps` - FTPS protocol handler
- All other git-core utilities (diff, log, status helpers, etc.)

**Verification**:
```bash
# Test HTTPS cloning
git clone https://github.com/anthropics/anthropic-quickstarts
# Should work without errors or warnings
```

#### Complete Curl Library Chain

Curl has a complex dependency chain. Here's the complete set needed:

```dockerfile
# Network libraries (added by git, curl, wget packages)
COPY --from=tools-installer /usr/lib/libcurl.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libnghttp2.so.* /usr/lib/      # HTTP/2
COPY --from=tools-installer /usr/lib/libnghttp3.so.* /usr/lib/      # HTTP/3
COPY --from=tools-installer /usr/lib/libidn2.so.* /usr/lib/         # International domains
COPY --from=tools-installer /usr/lib/libunistring.so.* /usr/lib/    # Unicode strings
COPY --from=tools-installer /usr/lib/libcares.so.* /usr/lib/        # Async DNS resolver

# Compression libraries (needed by curl)
COPY --from=tools-installer /usr/lib/libbrotlidec.so.* /usr/lib/    # Brotli decompression
COPY --from=tools-installer /usr/lib/libbrotlicommon.so.* /usr/lib/ # Brotli common
COPY --from=tools-installer /usr/lib/libzstd.so.* /usr/lib/         # Zstandard
COPY --from=tools-installer /usr/lib/libpsl.so.* /usr/lib/          # Public Suffix List
```

**Note**: SSL/TLS libraries (libssl, libcrypto) are already in python:3.13-alpine base, no need to copy.

#### Testing All Fixes

After implementing these fixes, verify with:

```javascript
// Test curl
const { execSync } = require('child_process');
const result = execSync('curl --version', { shell: '/bin/bash', encoding: 'utf-8' });
console.log(result);
// Should show: brotli/1.2.0 zstd/1.5.7 libpsl/0.21.5 nghttp3/1.13.1

// Test jq
const jqVersion = execSync('jq --version', { shell: '/bin/bash', encoding: 'utf-8' });
console.log(jqVersion); // Should show: jq-1.8.1

// Test git HTTPS
execSync('git clone --depth 1 https://github.com/anthropics/anthropic-quickstarts /tmp/test', {
  shell: '/bin/bash',
  encoding: 'utf-8'
});
// Should clone without errors or warnings
```

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

## Adding Comprehensive Linux Toolset

### Tools Installed for Claude Code Static Analysis

The extended image includes comprehensive Linux tools for Claude Code's static analysis capabilities:

**Core utilities**: git, bash, curl, wget
**Search/find**: grep, find, xargs, ripgrep (rg)
**Archives**: tar, unzip, gzip
**Text processing**: jq, less
**Build tools**: make
**Analysis**: file, tree
**Node.js**: npm, npx
**AI**: Claude Code CLI

### Library Dependencies Required

Each tool requires specific shared libraries. Here's what we learned about library management:

#### Libraries That MUST Be Copied

```dockerfile
# Core - needed by /bin/sh itself
COPY --from=tools-installer /usr/lib/libpcre2-8.so.* /usr/lib/

# Network libraries (curl, wget, git)
COPY --from=tools-installer /usr/lib/libcurl.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libnghttp2.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libidn2.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libunistring.so.* /usr/lib/

# SSL/TLS (HTTPS support)
COPY --from=tools-installer /usr/lib/libssl.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libcrypto.so.* /usr/lib/

# Tool-specific
COPY --from=tools-installer /usr/lib/libonig.so.* /usr/lib/      # jq
COPY --from=tools-installer /usr/lib/libmagic.so.* /usr/lib/    # file
COPY --from=tools-installer /usr/lib/libstdc++.so.* /usr/lib/   # ripgrep
```

#### Libraries to SKIP (Already in Base Image)

**DO NOT COPY** these - they cause "too many links" symlink conflicts:
- `libz.so.*` - Already in python:3.13-alpine
- `libbz2.so.*` - Not needed (not in tools-installer anyway)
- `liblzma.so.*` - Not needed (not in tools-installer anyway)
- `libgcc_s.so.*` - Not needed (not in tools-installer /lib)
- `libssh2.so.*` - Not needed (git works fine for HTTPS repos)

The base image's compression libraries are sufficient.

### Multi-Stage Build for Tools

Use a multi-stage build to install tools with Alpine package manager:

**CRITICAL: Use the SAME base image for tools-installer to ensure library compatibility!**

```dockerfile
# Stage 1: Install tools - MUST use same base as runtime!
# ❌ WRONG: FROM node:22.21.0-alpine AS tools-installer
# Different Alpine version = incompatible libraries = child_process broken

# ✅ CORRECT: Match the base image exactly
FROM python:3.13-alpine AS tools-installer

# Add Node.js to the Python image (needed for npm packages)
RUN apk add --no-cache nodejs npm

# Install tools - AVOID grep, tar, gzip (they corrupt busybox!)
RUN apk add --no-cache \
    git \
    bash \
    curl \
    wget \
    findutils \
    ripgrep \
    unzip \
    jq \
    less \
    make \
    file \
    tree

# Stage 2: Copy to final image
FROM ${BASE_IMAGE}  # python:3.13-alpine based
USER root

# Set up busybox applets FIRST (before copying anything)
RUN mkdir -p /tmp && chmod 1777 /tmp && \
    busybox --install -s /usr/bin || true

# Copy tool binaries from /usr/bin/ (SAFE)
COPY --from=tools-installer /usr/bin/git /usr/bin/git
COPY --from=tools-installer /usr/bin/curl /usr/bin/curl
# ... etc

# ONLY copy bash from /bin/ (never copy grep, tar, gzip - hardlinked!)
COPY --from=tools-installer /bin/bash /bin/bash

# Copy required libraries (matching Alpine version)
COPY --from=tools-installer /usr/lib/libpcre2-8.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libcurl.so.* /usr/lib/
# ... etc
```

**Why This Pattern**:
1. **Same Alpine version** = compatible library versions = /bin/sh works = child_process works
2. **busybox --install first** = sets up applets before copying anything
3. **Never copy /bin/ tools** (except bash) = avoids hardlink corruption
4. **apk add nodejs npm** = gets Node.js with correct paths for Alpine

### Critical: Kaniko RUN Command Limitation

**IMPORTANT DISCOVERY**: After copying libraries with COPY commands, **any subsequent RUN command fails in Kaniko** with mysterious "exit status 1" and no stderr output.

**Symptoms**:
```dockerfile
COPY --from=tools-installer /usr/lib/libcurl.so.* /usr/lib/
COPY --from=tools-installer /usr/lib/libssl.so.* /usr/lib/
# ... more library copies

RUN echo "test"  # ❌ Fails with exit status 1, no output
RUN npm install # ❌ Fails with exit status 1, no output
RUN mkdir -p /tmp # ❌ Fails with exit status 1, no output
```

Even the simplest commands fail. This appears to be a Kaniko bug when many library files are copied.

**The Workaround Pattern**:

```dockerfile
# Stage 1: Install EVERYTHING in tools-installer (RUN works here)
FROM node:22.21.0-alpine AS tools-installer

RUN apk add --no-cache git bash curl...
RUN npm install -g @anthropic-ai/claude-code
RUN mkdir -p /opt/extra-modules && \
    cd /opt/extra-modules && \
    npm install @anthropic-ai/claude-agent-sdk moment

# Stage 2: COPY EVERYTHING to final image (avoid RUN after library copies)
FROM ${BASE_IMAGE}
USER root

# Do ANY RUN commands FIRST (before library copies)
RUN mkdir -p /tmp && chmod 1777 /tmp

# Copy binaries
COPY --from=tools-installer /usr/bin/git /usr/bin/git
# ...

# Copy libraries
COPY --from=tools-installer /usr/lib/libcurl.so.* /usr/lib/
# ...

# Copy installed packages
COPY --from=tools-installer /opt/extra-modules /opt/extra-modules

# ⚠️ NO RUN COMMANDS AFTER THIS POINT - they will fail!
ENV SHELL=/bin/bash
USER runner
```

**Why This Works**:
1. All package installations happen in tools-installer (where RUN is fine)
2. All setup RUN commands happen BEFORE library copies
3. Only COPY and ENV commands after libraries (these work in Kaniko)
4. Everything you need is installed in tools-installer and copied over

### Tool Validation Layer

**NOTE**: Build-time validation is currently not possible due to the Kaniko RUN bug described above. Even simple validation commands fail after library copies.

**Alternative**: Verify tools work at runtime by testing them in your deployed container.

```bash
# Test in running container
docker exec -it n8n-runners /bin/sh
git --version
curl --version
jq --version
claude --version
node -e "require('@anthropic-ai/claude-agent-sdk')"
```

## Best Practices

### DO ✅

1. **Install ALL packages in tools-installer stage** - Avoids Kaniko RUN bug
2. **Do setup RUN commands BEFORE library copies** - RUN works early in the stage
3. **Use COPY for everything after libraries** - COPY works, RUN doesn't
4. **Use npm in extended images** - Avoids pnpm store conflicts
5. **Install extras to /opt/extra-modules** - Preserves core dependencies
6. **Set NODE_PATH in both places** - allowed-env AND env-overrides
7. **Use --legacy-peer-deps** - Handles version conflicts gracefully
8. **Create /tmp early with 1777 permissions** - Needed for workspace operations
9. **Test builds early** - Each iteration takes ~6-10 minutes with cache

### DON'T ❌

1. **Don't use RUN after library copies** - Kaniko bug causes silent failures
2. **Don't install packages in final stage** - Install in tools-installer, then COPY
3. **Don't delete node_modules** - Contains critical task-runner dependencies
4. **Don't use pnpm in extended images** - Store location conflicts
5. **Don't forget allowed-env** - env-overrides alone doesn't work
6. **Don't expect hot-reload** - Config is cached, requires container restart
7. **Don't skip /tmp setup** - Claude Agent SDK needs writable workspace
8. **Don't assume changes apply immediately** - Image must be rebuilt and redeployed

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

## Quick Reference: Common Library Dependencies

| Tool | Required Libraries | Notes |
|------|-------------------|-------|
| git | libpcre2, libcurl, libnghttp2 | Core VCS tool |
| bash | libpcre2 | Also used by /bin/sh |
| curl | libcurl, libnghttp2, libidn2, libssl, libcrypto | HTTPS support |
| wget | libssl, libcrypto | HTTPS support |
| ripgrep (rg) | libstdc++, libgcc_s | C++ tool, fast grep |
| jq | libonig | JSON processor |
| file | libmagic | File type detection |
| npm/npx | (node built-in) | From Node.js install |

**Verification**: Build logs show "WARN No files to copy" for libraries that don't exist in tools-installer. This is expected and can be ignored if the tool still validates successfully.

---

**Last Updated**: 2026-01-13
**Based on**: n8n v2.3.0, task-runner-launcher v1.4.2

**Recent Fixes** (2026-01-13):
- ✅ BusyBox corruption fully resolved (delete corrupted files, copy clean busybox)
- ✅ curl compression libraries added (Brotli, Zstandard, PSL)
- ✅ jq library dependencies added (libjq.so.1)
- ✅ git HTTPS cloning fixed (git-remote-https helpers + templates)
- ✅ Complete test suite: 46/46 tools tests + 44/44 git tests passing (100%)
