// Copyright 2020-2026 @pezkuwi/phishing authors & contributors
// SPDX-License-Identifier: Apache-2.0

// node --test scripts/lists.test.mjs
//
// The rules in lists.mjs, and the sync end to end against a scratch upstream repository: our
// entries survive every sync, our own domains are never blocked, and a day out of bounds writes
// nothing a commit could pick up.

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { blocks, changes, guard, LIMITS, mergeAll, mergeMeta, problems, validAddress } from './lists.mjs';

const SCRIPTS = path.dirname(fileURLToPath(import.meta.url));
// From the package's own tests: a Polkadot-prefix address and a generic-prefix one.
const ADDRESS = '14Vxs7UB9FqfQ53wwTJUBAJThs5N7b3bg89HscRU6eBqrFhQ';
const ADDRESS_42 = '5FkmzcdNekhdSA7j4teSSyHGUnKT8bzNBFvVVeZSGmbSpYHH';
const OURS = { date: '2026-09-13', reason: 'test', url: 'pezkuwichain.org' };

/** @param {Partial<import('./lists.mjs').Overlay>} [extra] */
function overlay (extra = {}) {
  return { deny: [], protect: [], undeny: [], ...extra };
}

/**
 * A list with its shards laid out the way sortAll writes them.
 * @param {string[]} deny
 * @param {Partial<import('./lists.mjs').Lists>} [extra]
 */
function lists (deny, extra = {}) {
  /** @type {Record<string, string[]>} */
  const shards = {};

  for (const url of deny) {
    (shards[url.split('.').pop() ?? ''] ??= []).push(url);
  }

  return { address: {}, all: { allow: [], deny, denySub: [] }, shards, ...extra };
}

void describe('blocks', () => {
  void it('matches the site and every subdomain of it', () => {
    assert.equal(blocks('polkadotfund.com', 'polkadotfund.com'), true);
    assert.equal(blocks('polkadotfund.com', 'some.where.polkadotfund.com'), true);
  });

  void it('matches by whole labels, not by text', () => {
    assert.equal(blocks('chain.io', 'pezkuwichain.io'), false);
    assert.equal(blocks('pezkuwichain.io.evil.com', 'pezkuwichain.io'), false);
  });

  void it('lets a short entry block everything under it', () => {
    assert.equal(blocks('io', 'pezkuwichain.io'), true);
  });
});

void describe('validAddress', () => {
  void it('accepts the addresses the package accepts', () => {
    assert.equal(validAddress(ADDRESS), true);
    assert.equal(validAddress(ADDRESS_42), true);
  });

  void it('refuses a broken checksum, a foreign alphabet and a short key', () => {
    assert.equal(validAddress(`${ADDRESS.slice(0, -1)}R`), false);
    assert.equal(validAddress(ADDRESS.replace('V', '0')), false);
    assert.equal(validAddress(ADDRESS.slice(0, 20)), false);
  });
});

void describe('mergeAll and mergeMeta', () => {
  void it('adds our entries and drops the ones we unblocked', () => {
    const merged = mergeAll(
      { allow: ['polkadot.network'], deny: ['scam.com', 'wrong.com'], denySub: [] },
      overlay({ deny: [OURS], undeny: [{ date: '2026-09-13', reason: 'test', url: 'wrong.com' }] })
    );

    assert.deepEqual(merged, { allow: ['polkadot.network'], deny: ['scam.com', 'pezkuwichain.org'], denySub: [] });
  });

  void it('dates our entries once, and never again', () => {
    const meta = [{ date: '2026-01-05', url: 'scam.com' }];

    assert.deepEqual(mergeMeta(meta, overlay({ deny: [OURS] })), [...meta, { date: '2026-09-13', url: 'pezkuwichain.org' }]);
    assert.deepEqual(mergeMeta([...meta, { date: '2026-09-13', url: 'pezkuwichain.org' }], overlay({ deny: [OURS] })).length, 2);
  });
});

void describe('problems', () => {
  void it('finds none in a clean list', () => {
    assert.deepEqual(problems(lists(['scam.com', 'pezkuwichain.org'], { address: { 'polkadot.center': [ADDRESS] } }), overlay({ deny: [OURS], protect: ['pezkuwichain.io'] })), []);
  });

  void it('refuses a list that blocks one of our domains, exactly or from above', () => {
    assert.match(problems(lists(['pezkuwichain.io']), overlay({ protect: ['pezkuwichain.io'] })).join(), /is ours/);
    assert.match(problems(lists(['wallet.pezkuwichain.io', 'chain.io']), overlay({ protect: ['wallet.pezkuwichain.io'] })).join(), /is ours/);
  });

  void it('refuses a list that lost one of our entries, or kept one we unblocked', () => {
    assert.match(problems(lists(['scam.com']), overlay({ deny: [OURS] })).join(), /is not blocked/);
    assert.match(problems(lists(['wrong.com']), overlay({ undeny: [{ date: '2026-09-13', reason: 'test', url: 'wrong.com' }] })).join(), /although we unblocked/);
  });

  void it('refuses malformed and duplicate entries', () => {
    for (const bad of ['scam.com/path', 'www.scam.com', 'nodot', 'sc am.com', 'scam.com?x', 'scam.xyz.']) {
      assert.match(problems(lists([bad]), overlay()).join(), /malformed/, bad);
    }

    assert.match(problems(lists(['scam.com', 'scam.com']), overlay()).join(), /duplicate/);
  });

  void it('refuses a site both denied and allowed', () => {
    const allowed = lists(['polkadot.network', 'app.subsocial.network'], {});

    allowed.all.allow = ['polkadot.network', '*.subsocial.network'];
    assert.equal(problems(allowed, overlay()).filter((p) => p.includes('denied and allowed')).length, 2);
  });

  void it('refuses shards that disagree with all.json', () => {
    const drifted = lists(['scam.com', 'scam.org']);

    drifted.shards['org'] = [];
    assert.match(problems(drifted, overlay()).join(), /all\/org\/all\.json/);
  });

  void it('refuses an invalid scam address', () => {
    assert.match(problems(lists(['scam.com'], { address: { 'scam.com': [`${ADDRESS.slice(0, -1)}R`] } }), overlay()).join(), /invalid addresses/);
  });
});

void describe('guard', () => {
  const before = lists(Array.from({ length: 40 }, (_, i) => `scam${i}.com`), { address: { 'scam0.com': Array(12).fill(ADDRESS).map((a, i) => i ? `${a}${i}` : a) } });

  void it('lets an ordinary day through', () => {
    assert.deepEqual(guard(changes(before, lists([...before.all.deny.slice(3), 'new.com'], { address: before.address }))), []);
  });

  void it('stops a day that unblocks more sites than the limit', () => {
    const after = lists(before.all.deny.slice(LIMITS.maxDenyRemoved + 1), { address: before.address });

    assert.match(guard(changes(before, after)).join(), /would be unblocked/);
  });

  void it('stops a day that adds more sites than the limit', () => {
    const after = lists([...before.all.deny, ...Array.from({ length: LIMITS.maxDenyAdded + 1 }, (_, i) => `new${i}.com`)], { address: before.address });

    assert.match(guard(changes(before, after)).join(), /would be added/);
  });

  void it('does not count a trailing dot folded away as an unblocked site', () => {
    const dotted = lists([...before.all.deny, ...before.all.deny.map((url) => `${url}.`)], { address: before.address });

    assert.deepEqual(changes(dotted, before).removed, []);
  });

  void it('does not count a subdomain folded into its newly listed parent as unblocked', () => {
    const after = lists(['prenads.xyz', ...before.all.deny], { address: before.address });

    assert.deepEqual(changes(lists(['monad.prenads.xyz', ...before.all.deny], { address: before.address }), after).removed, []);
  });

  void it('stops a day that drops more scam addresses than the limit', () => {
    assert.match(guard(changes(before, lists(before.all.deny))).join(), /scam addresses would be dropped/);
  });
});

void describe('syncUpstream.mjs, end to end', () => {
  /**
   * @param {string} cwd
   * @param {string[]} args
   */
  function git (cwd, ...args) {
    return execFileSync('git', ['-c', 'user.email=test@example.invalid', '-c', 'user.name=test', ...args], { cwd, encoding: 'utf8' });
  }

  /**
   * @param {string} dir
   * @param {string} file
   * @param {unknown} value
   */
  function write (dir, file, value) {
    fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    fs.writeFileSync(path.join(dir, file), `${JSON.stringify(value, null, '\t')}\n`);
  }

  /**
   * A new upstream commit holding these lists.
   * @param {string} upstream
   * @param {string[]} deny
   */
  function publish (upstream, deny) {
    write(upstream, 'all.json', { allow: [], deny, denySub: [] });
    write(upstream, 'address.json', { 'polkadot.center': [ADDRESS] });
    write(upstream, 'known.json', {});
    write(upstream, 'meta/index.json', ['2026-01']);
    write(upstream, 'meta/2026-01.json', [...deny, 'polkadot.center'].map((url) => ({ date: '2026-01-05', url })));
    git(upstream, 'add', '-A');
    git(upstream, 'commit', '-qm', 'lists');
  }

  /** @param {(dirs: { ours: string; upstream: string }) => void} body */
  function withRepos (body) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'phishing-sync-test-'));
    const upstream = path.join(root, 'upstream');
    const ours = path.join(root, 'ours');

    try {
      git(root, 'init', '-q', '-b', 'master', upstream);
      git(root, 'init', '-q', '-b', 'master', ours);

      // Only the scripts, no node_modules: the sync must run without the build toolchain.
      for (const script of ['checkLists.mjs', 'lists.mjs', 'sortAll.mjs', 'syncUpstream.mjs']) {
        fs.mkdirSync(path.join(ours, 'scripts'), { recursive: true });
        fs.copyFileSync(path.join(SCRIPTS, script), path.join(ours, 'scripts', script));
      }

      write(ours, 'pezkuwi/overlay.json', overlay({ deny: [OURS], protect: ['pezkuwichain.io'] }));
      write(ours, 'all.json', { allow: [], deny: [], denySub: [] });
      write(ours, 'address.json', {});
      write(ours, 'meta/index.json', []);
      git(ours, 'add', '-A');
      git(ours, 'commit', '-qm', 'start');
      body({ ours, upstream });
    } finally {
      fs.rmSync(root, { force: true, recursive: true });
    }
  }

  /**
   * @param {string} ours
   * @param {string} upstream
   */
  function sync (ours, upstream) {
    git(ours, 'fetch', '-q', upstream, 'master');

    const run = spawnSync(process.execPath, ['scripts/syncUpstream.mjs', 'FETCH_HEAD'], { cwd: ours, encoding: 'utf8' });

    return { ...run, last: run.stdout.trim().split('\n').pop() ?? '' };
  }

  const SCAMS = Array.from({ length: 30 }, (_, i) => `scam${i}.com`);

  void it('lays our entries over upstream and writes every derived file', () => {
    withRepos(({ ours, upstream }) => {
      publish(upstream, [...SCAMS, 'polkadot-js.org']);

      const run = sync(ours, upstream);

      assert.equal(run.status, 0, run.stderr);
      assert.match(run.last, /^SYNC upstream=[0-9a-f]{40} changed=yes deny=\+33\/-0 addresses=\+1\/-0$/);

      const all = JSON.parse(fs.readFileSync(path.join(ours, 'all.json'), 'utf8'));
      const org = JSON.parse(fs.readFileSync(path.join(ours, 'all/org/all.json'), 'utf8'));

      assert.equal(all.deny.includes('pezkuwichain.org'), true);
      assert.deepEqual(org, ['pezkuwichain.org', 'polkadot-js.org']);
      assert.equal(JSON.parse(fs.readFileSync(path.join(ours, 'pezkuwi/upstream.json'), 'utf8')).commit, git(upstream, 'rev-parse', 'HEAD').trim());

      const check = spawnSync(process.execPath, ['scripts/checkLists.mjs'], { cwd: ours, encoding: 'utf8' });

      assert.equal(check.status, 0, check.stderr);
    });
  });

  void it('files a name written with a trailing dot under its real top-level domain', () => {
    withRepos(({ ours, upstream }) => {
      publish(upstream, [...SCAMS, 'scam0.com.', 'only-dotted.xyz.']);

      const run = sync(ours, upstream);

      assert.equal(run.status, 0, run.stderr);
      assert.equal(fs.existsSync(path.join(ours, 'all/all.json')), false);
      assert.deepEqual(JSON.parse(fs.readFileSync(path.join(ours, 'all/xyz/all.json'), 'utf8')), ['only-dotted.xyz']);
      assert.equal(JSON.parse(fs.readFileSync(path.join(ours, 'all.json'), 'utf8')).deny.filter((url) => url.startsWith('scam0.com')).length, 1);
    });
  });

  void it('changes nothing when upstream has not moved', () => {
    withRepos(({ ours, upstream }) => {
      publish(upstream, SCAMS);
      assert.equal(sync(ours, upstream).status, 0);
      git(ours, 'add', '-A');
      git(ours, 'commit', '-qm', 'synced');
      assert.match(sync(ours, upstream).last, /changed=no deny=\+0\/-0/);
    });
  });

  void it('refuses a day on which upstream would block one of our domains', () => {
    withRepos(({ ours, upstream }) => {
      publish(upstream, [...SCAMS, 'pezkuwichain.io']);

      const run = sync(ours, upstream);

      assert.equal(run.status, 2);
      assert.match(run.last, /^SYNC-REFUSED /);
      assert.match(run.stderr, /pezkuwichain\.io is ours/);
    });
  });

  void it('refuses a day that unblocks more sites than the limit', () => {
    withRepos(({ ours, upstream }) => {
      publish(upstream, SCAMS);
      assert.equal(sync(ours, upstream).status, 0);
      publish(upstream, SCAMS.slice(0, 3));

      const run = sync(ours, upstream);

      assert.equal(run.status, 2);
      assert.match(run.stderr, /27 blocked sites would be unblocked/);
    });
  });
});
