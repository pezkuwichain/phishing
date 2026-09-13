// Copyright 2020-2026 @pezkuwi/phishing authors & contributors
// SPDX-License-Identifier: Apache-2.0

// node scripts/checkLists.mjs [dir]
//
// Whether the committed lists can be published: well formed, sharded the way the package reads
// them, none of our own domains blocked, our own entries in place, and every file exactly what
// sortAll writes. CI runs it on every change; the daily sync must pass it before it commits.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { problems, readLists, readOverlay } from './lists.mjs';

const dir = path.resolve(process.argv[2] ?? '.');
const lists = readLists(dir);
const found = problems(lists, readOverlay(dir));

/**
 * Every file under a directory, relative path to contents.
 * @param {string} root
 * @returns {Record<string, string>}
 */
function tree (root) {
  /** @type {Record<string, string>} */
  const files = {};

  for (const entry of fs.readdirSync(root, { recursive: true, withFileTypes: true })) {
    if (entry.isFile()) {
      const full = path.join(entry.parentPath, entry.name);

      files[path.relative(root, full)] = fs.readFileSync(full, 'utf8');
    }
  }

  return files;
}

// sortAll is the one writer of these files. Run it on a copy: if the copy comes out different,
// the committed files were edited into a shape the next sync would rewrite, or the metadata is
// missing entries that sortAll would stamp with today's date on every run.
const copy = fs.mkdtempSync(path.join(os.tmpdir(), 'phishing-canonical-'));

try {
  for (const name of ['all.json', 'address.json', 'meta']) {
    fs.cpSync(path.join(dir, name), path.join(copy, name), { recursive: true });
  }

  const sortAll = fileURLToPath(new URL('./sortAll.mjs', import.meta.url));
  const run = spawnSync(process.execPath, [sortAll], { cwd: copy, encoding: 'utf8' });

  if (run.status !== 0) {
    found.push(`sortAll failed: ${run.stderr.trim()}`);
  } else {
    for (const name of ['all.json', 'address.json']) {
      if (fs.readFileSync(path.join(dir, name), 'utf8') !== fs.readFileSync(path.join(copy, name), 'utf8')) {
        found.push(`${name} is not in the form sortAll writes`);
      }
    }

    for (const name of ['all', 'meta']) {
      if (JSON.stringify(tree(path.join(dir, name))) !== JSON.stringify(tree(path.join(copy, name)))) {
        found.push(`${name}/ is not what sortAll writes`);
      }
    }
  }
} finally {
  fs.rmSync(copy, { force: true, recursive: true });
}

if (found.length) {
  for (const problem of found) {
    console.error(`FAIL ${problem}`);
  }

  console.error(`${found.length} problem(s)`);
  process.exit(1);
}

console.log(`lists OK: ${lists.all.deny.length} blocked sites, ${Object.values(lists.address).flat().length} scam addresses, ${Object.keys(lists.shards).length} shards`);
