// Copyright 2020-2026 @pezkuwi/phishing authors & contributors
// SPDX-License-Identifier: Apache-2.0

// Whether the Deno build can still reach its dependencies.
//
// The build rewrites every @pezkuwi/* import into a deno.land URL:
// @pezkuwi/util becomes https://deno.land/x/pezkuwi/util/mod.ts. Upstream can do
// that because deno.land/x/polkadot is published; our fork renamed the prefix to
// x/pezkuwi and never published there, so deno.land/x/pezkuwi answers 404 and
// `deno check` failed on three modules — for months, unnoticed, because the PR
// job carries continue-on-error and can never turn a pull request red.
//
// import_map.in.json is the tooling's own hook for this: pezkuwi-dev-deno-map
// merges its entries into the generated import_map.json. The three externals are
// mapped to npm: specifiers, which Deno resolves natively, so the Deno build uses
// the very packages we already publish. Nothing new has to be published, and
// claiming the deno.land/x/pezkuwi namespace stays a decision we can take later
// rather than one this build forces.
//
// What can rot: a dependency is bumped in packages/phishing/package.json and the
// map keeps pointing at the old range, so `deno check` type-checks a different
// version of @pezkuwi/util than the node build compiles against. That divergence
// would not fail anything — it would just quietly check the wrong code.
//
//   node scripts/checkDenoMap.mjs

import { existsSync, readFileSync } from 'node:fs';

const errors = [];

function check (name, ok, detail) {
  console.log((ok ? 'ok    ' : 'FAIL  ') + name + (ok ? '' : `   — got: ${JSON.stringify(detail)}`));

  if (!ok) {
    errors.push(name);
  }
}

check('the deno import map exists', existsSync('import_map.in.json'));

if (errors.length) {
  console.log(`FAILED: ${errors.length}`);
  process.exit(1);
}

const map = JSON.parse(readFileSync('import_map.in.json', 'utf8')).imports || {};
const pkg = JSON.parse(readFileSync('packages/phishing/package.json', 'utf8'));
const deps = pkg.dependencies || {};

// Every @pezkuwi dependency the package pulls in has to be reachable from Deno,
// because the build turns all of them into deno.land URLs.
const external = Object.keys(deps).filter((d) => d.startsWith('@pezkuwi/'));

check('the package has @pezkuwi dependencies to map', external.length > 0, external);

for (const dep of external) {
  const short = dep.replace('@pezkuwi/', '');
  const key = `https://deno.land/x/pezkuwi/${short}/mod.ts`;
  const want = `npm:${dep}@${deps[dep]}`;

  check(`${dep}: the deno build has somewhere to resolve it`, !!map[key], { have: Object.keys(map), key });
  check(`${dep}: the deno build and the node build agree on the version`, map[key] === want, { map: map[key], want });
}

// And nothing in the map points at a package we no longer depend on, which would
// hide a removed dependency behind a mapping that still resolves.
for (const [key, value] of Object.entries(map)) {
  const named = String(value).replace(/^npm:/, '').replace(/@[^@/]*$/, '');

  check(`${key}: maps to a dependency we still declare`, external.includes(named), { named, value });
}

console.log(errors.length ? `FAILED: ${errors.length}` : 'all deno map checks passed');
process.exit(errors.length ? 1 : 0);
