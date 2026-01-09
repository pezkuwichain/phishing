// Copyright 2017-2026 @pezkuwi/phishing authors & contributors
// SPDX-License-Identifier: Apache-2.0

import { createBundle } from '@pezkuwi/dev/config/rollup';

const pkgs = [
  '@pezkuwi/phishing'
];

const external = [
  ...pkgs,
  '@pezkuwi/util',
  '@pezkuwi/util-crypto'
];

const entries = {};

const overrides = {};

export default pkgs.map((pkg) => {
  const override = (overrides[pkg] || {});

  return createBundle({
    external,
    pkg,
    ...override,
    entries: {
      ...entries,
      ...(override.entries || {})
    }
  });
});
