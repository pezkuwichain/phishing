// Copyright 2020-2026 @pezkuwi/phishing authors & contributors
// SPDX-License-Identifier: Apache-2.0

// What this repository says about itself must be true, and must be something the
// build toolchain can read.
//
// On 2026-04-21 a commit pointed repository/homepage/bugs at our Gitea instance
// ("migrate git dependencies to Gitea mirror"). Nothing else moved: origin is
// still GitHub, the published package still says GitHub, and
// git.pezkuwichain.io/pezkuwichain/phishing answers 500 — so every installer of
// @pezkuwi/phishing got dead links for its homepage and its bug tracker.
//
// It also broke `yarn build` from 2026-09-13, when the toolchain started reading
// the field. @pezkuwi/dev does this, and it is ours:
//
//     const repoPath = pkg.repository.url
//       .split('https://github.com/')[1]
//       .split('.git')[0];
//
// A URL from any other host makes [1] undefined and the build dies with
// "Cannot read properties of undefined (reading 'split')" — a message that names
// neither the field nor the file.
//
// So this check is also the tripwire for the migration that was started and left
// half-done: moving this repository to Gitea for real means fixing @pezkuwi/dev
// first, so that a toolchain built for a state that hosts its own git stops
// assuming github.com. Until that happens, this check turns the metadata red
// here rather than letting it fail as an unreadable stack trace, or ship as a
// dead link.
//
//   node scripts/checkRepoMeta.mjs

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';

const errors = [];

function check (name, ok, detail) {
  console.log((ok ? 'ok    ' : 'FAIL  ') + name + (ok ? '' : `   — got: ${JSON.stringify(detail)}`));

  if (!ok) {
    errors.push(name);
  }
}

// Exactly the expression @pezkuwi/dev uses, so this fails where the build fails.
function toolchainCanRead (url) {
  try {
    const path = String(url).split('https://github.com/')[1].split('.git')[0];

    return !!path && path.includes('/');
  } catch {
    return false;
  }
}

const files = ['package.json'];

for (const dir of readdirSync('packages', { withFileTypes: true })) {
  if (dir.isDirectory() && existsSync(`packages/${dir.name}/package.json`)) {
    files.push(`packages/${dir.name}/package.json`);
  }
}

check('every package describes itself', files.length > 1, files);

const hosts = new Set();

for (const file of files) {
  const pkg = JSON.parse(readFileSync(file, 'utf8'));
  const url = pkg.repository?.url;

  check(`${file}: has a repository url`, !!url, pkg.repository);
  check(`${file}: the build toolchain can read that url`, toolchainCanRead(url), url);
  check(`${file}: homepage and bugs live on the same host as the repository`,
    !!url && !!pkg.homepage && !!pkg.bugs &&
      new URL(pkg.homepage).host === new URL(url).host &&
      new URL(String(pkg.bugs)).host === new URL(url).host,
    { bugs: pkg.bugs, homepage: pkg.homepage, url });

  if (url) {
    hosts.add(new URL(url).host);
  }
}

check('the whole repository agrees on one host', hosts.size === 1, [...hosts]);

// And that host is where the code actually is. Without this the metadata can be
// internally consistent and still point somewhere the code has never been.
let origin = '';

try {
  origin = execFileSync('git', ['remote', 'get-url', 'origin'], { encoding: 'utf8' }).trim();
} catch {
  origin = '';
}

if (origin) {
  check('the metadata names the remote the code is actually pushed to',
    hosts.has(new URL(origin.replace(/^git@([^:]+):/, 'https://$1/')).host),
    { hosts: [...hosts], origin }
  );
} else {
  console.log('ok    (no origin remote here — nothing to compare against)');
}

console.log(errors.length ? `FAILED: ${errors.length}` : 'all repository metadata checks passed');
process.exit(errors.length ? 1 : 0);
