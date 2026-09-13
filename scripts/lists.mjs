// Copyright 2020-2026 @pezkuwi/phishing authors & contributors
// SPDX-License-Identifier: Apache-2.0

// What the Pezkuwi copy of the lists is held to. Plain Node, no dependencies, so the daily
// upstream sync, the lists check and their tests run without the build toolchain:
//
//   - how our own entries (pezkuwi/overlay.json) are laid over polkadot-js/phishing;
//   - what a list must look like before it is published;
//   - how much one sync may change it before a person has to look.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** @typedef {{ allow: string[]; deny: string[]; denySub: string[] }} AllList */
/** @typedef {{ date: string; reason: string; url: string }} OverlayEntry */
/** @typedef {{ deny: OverlayEntry[]; protect: string[]; undeny: OverlayEntry[] }} Overlay */
/** @typedef {{ address: Record<string, string[]>; all: AllList; shards: Record<string, string[]> }} Lists */
/** @typedef {{ added: string[]; addressesAdded: string[]; addressesRemoved: string[]; removed: string[] }} Change */

// Upstream added 701 sites and removed 3 in the eight months to September 2026. A sync that
// removes more than this, or adds more, is not an ordinary day, and a person decides.
export const LIMITS = { maxAddressesRemoved: 10, maxDenyAdded: 5000, maxDenyRemoved: 25 };

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** @param {string} file */
export function readJson (file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * The layout sortAll writes: tab-indented, with a trailing newline.
 * @param {string} file
 * @param {unknown} value
 */
export function writeJson (file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, '\t')}\n`);
}

/**
 * @param {string} dir
 * @returns {Lists}
 */
export function readLists (dir) {
  /** @type {Record<string, string[]>} */
  const shards = {};
  const allDir = path.join(dir, 'all');

  // Only directories are shards. Anything else in all/ is not something the package reads; the
  // lists check still flags it, because it is not what sortAll writes.
  const tops = fs.existsSync(allDir)
    ? fs.readdirSync(allDir, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map(({ name }) => name).sort()
    : [];

  for (const top of tops) {
    shards[top] = readJson(path.join(allDir, top, 'all.json'));
  }

  return {
    address: readJson(path.join(dir, 'address.json')),
    all: readJson(path.join(dir, 'all.json')),
    shards
  };
}

/**
 * @param {string} dir
 * @returns {Overlay}
 */
export function readOverlay (dir) {
  return readJson(path.join(dir, 'pezkuwi', 'overlay.json'));
}

/** @param {string} host */
export function hostParts (host) {
  return host.toLowerCase().replace(/\.$/, '').split('.').reverse();
}

/**
 * Whether a deny entry blocks a host, by the package's own rule (checkHostParts in
 * packages/phishing/src/bundle.ts): the entry's labels match the host's, counted from the right.
 * @param {string} entry
 * @param {string} host
 */
export function blocks (entry, host) {
  const e = hostParts(entry);
  const h = hostParts(host);

  return e.length <= h.length && e.every((part, i) => h[i] === part);
}

/**
 * @param {AllList} upstream
 * @param {Overlay} overlay
 * @returns {AllList}
 */
export function mergeAll (upstream, overlay) {
  const undeny = new Set(overlay.undeny.map(({ url }) => url));

  return {
    allow: upstream.allow,
    deny: upstream.deny.filter((url) => !undeny.has(url)).concat(overlay.deny.map(({ url }) => url)),
    denySub: upstream.denySub
  };
}

/**
 * Our entries carry their own date. Without it sortAll would stamp them with the day it runs,
 * and every daily sync would rewrite the metadata.
 * @param {{ date: string; url: string }[]} meta
 * @param {Overlay} overlay
 */
export function mergeMeta (meta, overlay) {
  const have = new Set(meta.map(({ url }) => url));

  return meta.concat(
    overlay.deny
      .filter(({ url }) => !have.has(url))
      .map(({ date, url }) => ({ date, url }))
  );
}

/** @param {string} text */
function base58 (text) {
  let n = 0n;

  for (const ch of text) {
    const value = BASE58.indexOf(ch);

    if (value < 0) {
      return null;
    }

    n = (n * 58n) + BigInt(value);
  }

  /** @type {number[]} */
  const bytes = [];

  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }

  for (const ch of text) {
    if (ch !== '1') {
      break;
    }

    bytes.unshift(0);
  }

  return Uint8Array.from(bytes);
}

/**
 * An SS58 address holding a 32-byte key with a valid checksum: what the package's decodeAddress
 * accepts, and what the upstream test checks with @pezkuwi/util-crypto.
 * @param {string} address
 */
export function validAddress (address) {
  const bytes = typeof address === 'string' ? base58(address) : null;

  if (!bytes || bytes.length < 35) {
    return false;
  }

  const prefixLength = (bytes[0] & 0b0100_0000) ? 2 : 1;

  if (bytes.length !== prefixLength + 32 + 2) {
    return false;
  }

  const hash = crypto
    .createHash('blake2b512')
    .update(Buffer.concat([Buffer.from('SS58PRE'), bytes.subarray(0, bytes.length - 2)]))
    .digest();

  return hash[0] === bytes[bytes.length - 2] && hash[1] === bytes[bytes.length - 1];
}

/**
 * Everything that makes a list unfit to publish.
 * @param {Lists} lists
 * @param {Overlay} overlay
 * @returns {string[]}
 */
export function problems ({ address, all, shards }, overlay) {
  /** @type {string[]} */
  const found = [];
  const seen = new Set();

  for (const url of all.deny) {
    // A trailing dot sorts the entry under an empty top-level domain, where the package never looks.
    if (typeof url !== 'string' || !url.includes('.') || /[/?\s]/.test(url) || url.startsWith('www.') || url.endsWith('.')) {
      found.push(`malformed deny entry: ${url}`);
    } else if (seen.has(url)) {
      found.push(`duplicate deny entry: ${url}`);
    }

    seen.add(url);
  }

  // The upstream test's rule: a denied site may not be an allowed one, or match an allowed '*.' pattern.
  for (const url of all.deny) {
    const allowed = all.allow.find((t) =>
      (t.startsWith('*.') && url.split('.').length === t.split('.').length)
        ? (url.endsWith(t.substring(1)) || url === t.substring(2))
        : url === t
    );

    if (allowed) {
      found.push(`${url} is both denied and allowed (${allowed})`);
    }
  }

  // The package reads a site's list from all/<top-level domain>/all.json, not from all.json.
  /** @type {Record<string, string[]>} */
  const byTop = {};

  for (const url of all.deny) {
    (byTop[url.split('.').pop() ?? ''] ??= []).push(url);
  }

  for (const top of new Set([...Object.keys(byTop), ...Object.keys(shards)])) {
    if (JSON.stringify(byTop[top] ?? []) !== JSON.stringify(shards[top] ?? [])) {
      found.push(`all/${top}/all.json does not match all.json`);
    }
  }

  for (const [site, addresses] of Object.entries(address)) {
    const bad = Array.isArray(addresses)
      ? addresses.filter((a) => !validAddress(a))
      : ['(not a list)'];

    if (bad.length) {
      found.push(`invalid addresses for ${site}: ${bad.join(', ')}`);
    }
  }

  for (const domain of overlay.protect) {
    const entry = all.deny.find((url) => blocks(url, domain));

    if (entry) {
      found.push(`${domain} is ours and would be blocked by the entry ${entry}`);
    }
  }

  for (const { url } of overlay.deny) {
    if (!all.deny.some((entry) => blocks(entry, url))) {
      found.push(`our entry ${url} is not blocked`);
    }
  }

  for (const { url } of overlay.undeny) {
    if (all.deny.includes(url)) {
      found.push(`${url} is blocked although we unblocked it`);
    }
  }

  return found;
}

/**
 * @param {Lists} before
 * @param {Lists} after
 * @returns {Change}
 */
export function changes (before, after) {
  const was = before.all.deny;
  const now = after.all.deny;
  const wasSet = new Set(was);
  const nowSet = new Set(now);
  const wasAddresses = new Set(Object.values(before.address).flat());
  const nowAddresses = new Set(Object.values(after.address).flat());

  return {
    added: now.filter((url) => !wasSet.has(url)),
    addressesAdded: [...nowAddresses].filter((a) => !wasAddresses.has(a)),
    addressesRemoved: [...wasAddresses].filter((a) => !nowAddresses.has(a)),
    // Sites no longer blocked, not entries no longer written. sortAll drops a subdomain once its
    // parent is listed (monad.prenads.xyz when prenads.xyz arrived), and folds "scam.xyz." into
    // "scam.xyz" (816 entries in September 2026); in both the site stays blocked, by blocks()'s rule.
    removed: was.filter((url) => !nowSet.has(url) && !now.some((entry) => blocks(entry, url)))
  };
}

/**
 * The limits one sync may not cross on its own.
 * @param {Change} change
 * @param {typeof LIMITS} [limits]
 * @returns {string[]}
 */
export function guard (change, limits = LIMITS) {
  /** @type {string[]} */
  const found = [];

  if (change.removed.length > limits.maxDenyRemoved) {
    found.push(`${change.removed.length} blocked sites would be unblocked (limit ${limits.maxDenyRemoved}): ${change.removed.slice(0, 20).join(', ')}`);
  }

  if (change.added.length > limits.maxDenyAdded) {
    found.push(`${change.added.length} sites would be added (limit ${limits.maxDenyAdded})`);
  }

  if (change.addressesRemoved.length > limits.maxAddressesRemoved) {
    found.push(`${change.addressesRemoved.length} scam addresses would be dropped (limit ${limits.maxAddressesRemoved})`);
  }

  return found;
}
