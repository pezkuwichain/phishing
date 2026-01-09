# @pezkuwi/phishing

To check for sites that are on the list -

```js
import { checkIfDenied } from '@pezkuwi/phishing';

const isOnDeny = await checkIfDenied(window.location.host);

console.log(`isOnDeny=${isOnDeny}`);
```

To check for addresses that are on the list -

```js
import { checkAddress } from '@pezkuwi/phishing';

const info = await checkAddress('1b....');

if (info) {
  console.log(`The address is reported as ${info}`);
} else {
  console.log('Not reported');
}
```
