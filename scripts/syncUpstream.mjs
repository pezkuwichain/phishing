// Copyright 2020-2026 @pezkuwi/phishing authors & contributors
// SPDX-License-Identifier: Apache-2.0

// node scripts/syncUpstream.mjs <upstream git ref>
//
// Brings the lists to polkadot-js/phishing at the ref given (the caller fetches it), lays our own
// entries over them (pezkuwi/overlay.json), and lets sortAll write every derived file. Then it
// checks the result and compares it with what was committed before:
//
//   exit 0   publishable; the working tree holds the lists (unchanged if upstream did not move)
//   exit 2   a check or a limit refused them; commit nothing, a person decides
//
// The last line is always one of:
//   SYNC upstream=<sha> changed=<yes|no> deny=+<n>/-<n> addresses=+<n>/-<n>
//   SYNC-REFUSED upstream=<sha> problems=<n>

import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import { changes, guard, mergeAll, mergeMeta, problems, readLists, readOverlay, writeJson } from './lists.mjs';

const ref = process.argv[2];

if (!ref) {
  console.error('usage: node scripts/syncUpstream.mjs <upstream git ref>');
  process.exit(64);
}

/** @param {string[]} args */
function git (...args) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
}

/** @param {string} file */
function upstream (file) {
  return git('show', `${ref}:${file}`);
}

const upstreamSha = git('rev-parse', '--verify', `${ref}^{commit}`).trim();
const before = readLists('.');
const overlay = readOverlay('.');

// Upstream's metadata as it is, with our entries added: the months sortAll reads it from.
/** @type {{ date: string; url: string }[]} */
const meta = /** @type {string[]} */ (JSON.parse(upstream('meta/index.json')))
  .flatMap((month) => JSON.parse(upstream(`meta/${month}.json`)));
/** @type {Record<string, { date: string; url: string }[]>} */
const months = {};

for (const item of mergeMeta(meta, overlay)) {
  (months[item.date.slice(0, 7)] ??= []).push(item);
}

fs.rmSync('meta', { force: true, recursive: true });
fs.mkdirSync('meta');

for (const [month, items] of Object.entries(months)) {
  writeJson(`meta/${month}.json`, items);
}

writeJson('meta/index.json', Object.keys(months).sort((a, b) => b.localeCompare(a)));
writeJson('all.json', mergeAll(JSON.parse(upstream('all.json')), overlay));
fs.writeFileSync('address.json', upstream('address.json'));
fs.writeFileSync('known.json', upstream('known.json'));

const sortAll = spawnSync(process.execPath, [fileURLToPath(new URL('./sortAll.mjs', import.meta.url))], { stdio: 'inherit' });
const after = readLists('.');
const change = changes(before, after);
const found = sortAll.status === 0
  ? [...problems(after, overlay), ...guard(change)]
  : [`sortAll failed with status ${sortAll.status}`];

if (found.length) {
  for (const problem of found) {
    console.error(`FAIL ${problem}`);
  }

  console.log(`SYNC-REFUSED upstream=${upstreamSha} problems=${found.length}`);
  process.exit(2);
}

const changed = git('status', '--porcelain', '--', 'all.json', 'address.json', 'known.json', 'all', 'meta').trim() !== '';

// Recorded only when the lists moved: upstream commits that touch only its package would
// otherwise rewrite this file every day.
if (changed) {
  fs.mkdirSync('pezkuwi', { recursive: true });
  writeJson('pezkuwi/upstream.json', { commit: upstreamSha });
}

for (const url of change.removed) {
  console.log(`unblocked: ${url}`);
}

console.log(`SYNC upstream=${upstreamSha} changed=${changed ? 'yes' : 'no'} deny=+${change.added.length}/-${change.removed.length} addresses=+${change.addressesAdded.length}/-${change.addressesRemoved.length}`);
