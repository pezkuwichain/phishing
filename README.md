# @pezkuwi/phishing

A curated list of potentially less-than-honest sites inclusive of a simple JS utility function to check any host against this list.


## How the lists are kept

These lists are Pezkuwi's copy of [polkadot-js/phishing](https://github.com/polkadot-js/phishing): they follow upstream, with a few entries of our own.

- **Daily sync.** [`sync-upstream.yml`](.github/workflows/sync-upstream.yml) takes upstream's lists every day, lays [`pezkuwi/overlay.json`](pezkuwi/overlay.json) over them, and commits the result to `master`. On a day out of bounds it writes nothing and opens an issue instead: more than 25 sites unblocked or 5000 added, more than 10 scam addresses dropped, one of our own domains blocked, or one of our entries lost ([`scripts/lists.mjs`](scripts/lists.mjs)).
- **Our entries.** `overlay.json` holds the sites we block that upstream does not (`deny`), upstream entries we deliberately do not block (`undeny`), and our own domains, which no entry may ever block (`protect`). Each entry records why and since when. Change our entries there, not in `all.json`, which every sync rewrites from upstream.
- **Publishing.** phishing.pezkuwichain.io pulls `master` every hour and checks the lists again before it serves them ([`pezkuwi/host/`](pezkuwi/host/)).
- **Checks.** [`lists.yml`](.github/workflows/lists.yml) runs the rules' tests and [`scripts/checkLists.mjs`](scripts/checkLists.mjs) on every change. Neither needs the build toolchain.


### Additions

Report a new site or scam address to [polkadot-js/phishing](https://github.com/polkadot-js/phishing), and the daily sync brings it here. A site that targets Pezkuwi specifically, and that upstream would not list, goes in the `deny` section of [`pezkuwi/overlay.json`](pezkuwi/overlay.json), with its reason and date.


### Availability

Changes reach [phishing.pezkuwichain.io/all.json](https://phishing.pezkuwichain.io/all.json) and [phishing.pezkuwichain.io/address.json](https://phishing.pezkuwichain.io/address.json) within the hour after they land on `master`. These can be consumed via [@pezkuwi/phishing](https://github.com/pezkuwichain/phishing/tree/master/packages/phishing) and other tools capable of parsing JSON.


## Notable users

The following wallets integrate either address or site blocking from these lists:

<!--

Note to editors: Additions welcome. Keep it alphabetical after the
org-specific projects, i.e. Pezkuwi first, rest alphabetical
following that

-->

- [Pezkuwi Extension](https://github.com/pezkuwichain/pezkuwi-extension)
- [Pezkuwi SDK UI](https://github.com/pezkuwichain/pwap)
- [Pezkuwi Apps](https://pezkuwichain.app)


### Integration

Since the lists are published as JSON, integration for any non-JS wallets (only a JS library that is provided) should be simple - retrieve the applicable list, parse the JSON, and do the required checks either on the host or address as per the requirements. The Javascript library does have some features that may be worth thinking about for other integrations -

- instead of retrieving the list each time a request is made, a local copy is cached for 45 minutes and then re-retrieved when the timer expires (as a request is made)
- for address checks, the check is done on the decoded ss58 address to ensure that network-jumps with the same keys are avoided (so addresses do not have to be re-added for other networks, a single entry will cover all)


### Contributing

These lists are intended to be maintained with active input from the community, so contributions are welcome, either via a pull request (edit above as described in additions) or by [logging an issue](https://github.com/pezkuwichain/phishing/issues).
