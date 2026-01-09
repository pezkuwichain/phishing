# @pezkuwi/phishing

A curated list of potentially less-than-honest sites inclusive of a simple JS utility function to check any host against this list.


### Additions

To add a new site, edit [all.json](https://github.com/pezkuwichain/phishing/edit/master/all.json) and add any new entries, single or multiple is allowed per edit.

To add a new scam address (typically per site), edit [address.json](https://github.com/pezkuwichain/phishing/edit/master/address.json) and add it in the correct section (which is keyed by the site providing them).


### Availability

Making additions to the list will be reflected on merge at [phishing.pezkuwichain.io/all.json](https://phishing.pezkuwichain.io/all.json) &  [phishing.pezkuwichain.io/address.json](https://phishing.pezkuwichain.io/address.json). These can be consumed via [@pezkuwi/phishing](https://github.com/pezkuwichain/phishing/tree/master/packages/phishing) and other tools capable of parsing JSON.

The `{address, all}.json` files are also published to IPFS, via [ipns/phishing.pezkuwichain.io](https://ipfs.io/ipns/phishing.pezkuwichain.io/). Libraries can also consume from here for a decentralized approach.


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
