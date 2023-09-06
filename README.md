ts-multipass
============

Shopify Multipass module for TypeScript.

Install
-------

```bash
npm install ts-multipass
```

Example
-------

```typescript
import {Multipass, CustomerDataEssentials} from 'ts-multipass';

interface CustomerData extends CustomerDataEssentials {
  return_to: string;
  remote_ip: string;
  identifier: string;
}

const multipass = new Multipass<CustomerData>('YOUR_SECRET');

const token = multipass.generateToken({
  email: 'foo@example.com',
  return_to: 'https://yourstore.com/some_specific_site',
  remote_ip: '192.0.2.1',
  identifier: 'nic123',
});
```

License
-------

MIT License.

Copyright (c) 2023 KOMIYA Atsushi.
