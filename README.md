# no-ssrf

**Stop user-supplied URLs from reaching your server's own network.** Zero dependencies. The URL
and address checks run anywhere (Node, Bun, Deno, edge runtimes, browsers), and `@qaweem321/no-ssrf/node`
makes the request with the address checked at connect time, so DNS rebinding doesn't get through.

**[▶ Try the playground: can your SSRF filter catch these?](https://qaweem321.github.io/no-ssrf/)**

![Two common filters get 11/37 and 18/37 of the gallery right; no-ssrf gets 37/37](https://raw.githubusercontent.com/qaweem321/no-ssrf/main/docs/playground.jpg)

## Why

Webhooks, link previews, "import from URL", OAuth discovery: any feature where your server fetches
a URL a user typed can be pointed at `http://169.254.169.254/` (your cloud credentials),
`localhost` admin ports or your private network. The usual defence is a regex, and it loses:

```js
new URL("https://[::ffff:169.254.169.254]/").hostname   // "[::ffff:a9fe:a9fe]"
```

A regex looking for `169.254.` or `::ffff:169.254.` never sees that string. And even a perfect URL
check isn't enough on its own: `hooks.attacker.com` can resolve to `10.0.0.5`, or resolve to a
public address when you check and a private one when you connect.

## Install

```bash
npm install @qaweem321/no-ssrf
```

## Use

```ts
import { checkUrl } from "@qaweem321/no-ssrf";
import { safeRequest } from "@qaweem321/no-ssrf/node";

// 1. When the user saves the URL: give a clear message.
const verdict = checkUrl(input, { allowedPorts: [443] });
if (!verdict.ok) return { error: `That address can't be used: ${verdict.reason}.` };

// 2. When you send: checks the URL, every DNS answer and every redirect.
const res = await safeRequest(verdict.url, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(event),
  timeoutMs: 5000,
  maxResponseBytes: 64_000,
});
console.log(res.status);
```

`safeRequest` throws an `SsrfError` when it refuses, with a reason like
`hooks.example.com resolves to 10.0.0.5: private network`.

### Already have an HTTP client?

Use the checked DNS lookup with anything built on Node's `http`, `https` or `net`:

```ts
import https from "node:https";
import { safeLookup } from "@qaweem321/no-ssrf/node";

const agent = new https.Agent({ lookup: safeLookup() });
```

The lookup only runs for host names. Node connects to an IP typed into the URL (`http://127.0.0.1/`)
without asking DNS, so also run `checkUrl` on every URL before sending it, redirects included.
And keep this agent for user-supplied URLs only: a connection pooled by another agent never runs
the lookup.

### Checking addresses yourself

```ts
import { checkAddress, isPrivateAddress } from "@qaweem321/no-ssrf";

isPrivateAddress("::ffff:7f00:1");   // true: 127.0.0.1 as IPv4-mapped IPv6
checkAddress("64:ff9b::a9fe:a9fe");
// { allowed: false, reason: "link-local (includes the cloud metadata service 169.254.169.254), as NAT64 (169.254.169.254)" }
```

## What it blocks

- **IPv4**: `0.0.0.0/8`, private ranges (`10/8`, `172.16/12`, `192.168/16`), loopback, link-local
  and the metadata service, carrier-grade NAT (`100.64/10`, used by Alibaba Cloud's metadata
  service), documentation, benchmarking, the old 6to4 relay range, multicast, reserved and
  broadcast.
- **IPv6**: unspecified, loopback, unique local (`fc00::/7`, including AWS's IPv6 metadata
  address), link-local, site-local, multicast, documentation (`2001:db8::/32`, `3fff::/20`),
  discard, Teredo, local-use NAT64 (`64:ff9b:1::/48`).
- **IPv4 hidden inside IPv6**: IPv4-mapped (`::ffff:…`), NAT64 (`64:ff9b::/96`) and 6to4
  (`2002::/16`) are checked as the IPv4 address they carry, so NAT64 to a *public* address is
  allowed. The deprecated IPv4-compatible form (`::…`) is refused.
- **Names**: `localhost`, `*.localhost`, `*.local`, `*.internal` (e.g.
  `metadata.google.internal`), `*.home.arpa`, single-label names, with any case or a trailing dot.
- **URLs**: anything but `https:` (or `http:` with `allowHttp`), credentials in the URL, ports
  outside `allowedPorts`.
- **Requests** (`@qaweem321/no-ssrf/node`): every address a name resolves to; redirects aren't followed unless
  you set `maxRedirects`, and then each hop is checked again (and `Authorization` and `Cookie`
  headers are dropped when a redirect leaves the original origin). Every request opens its own
  connection, so a pooled one can't skip the check. A timeout for the whole request and a response
  size limit are on by default.

### Options

| Option | Default | |
| --- | --- | --- |
| `allowHttp` | `false` | Also allow `http://` |
| `allowedPorts` | any | e.g. `[443]` for webhooks |
| `allowHosts` | none | Hostnames or IPs that are always allowed (a service you trust); with `safeRequest`, a listed name may also resolve to a private address |
| `allowAddresses` | none | (`@qaweem321/no-ssrf/node`) resolved addresses that are always allowed |
| `maxRedirects` | `0` | Redirects to follow, each one re-checked |
| `timeoutMs` | `10000` | Whole request, redirects included |
| `maxResponseBytes` | `1000000` | The rest of the body isn't downloaded |

## How it's tested

- **The gallery**: 37 URLs (the playground's list), each with the verdict a correct check must
  give, from `[::ffff:169.254.169.254]` to `0177.0.0.1` and `gopher://127.0.0.1:6379/`.
- **Parity with Node's own code**: the IP parser is compared with `node:net`'s `isIP` on 20,000
  generated strings, and the range matching with `node:net`'s `BlockList` on 100,000 random
  addresses. Every IPv6 form `new URL()` produces is round-tripped 5,000 times.
- **Real requests** against a local server: private IPs refused before connecting, a public-looking
  name resolving to `127.0.0.1` refused (DNS rebinding), redirects to `[::1]` refused, `303`
  turning `POST` into `GET`, timeouts and size limits.
- **Runtimes**: CI runs the tests on Node 20, 22 and 24, and the built package under Bun and Deno.

```bash
npm install
npm run check   # type check, tests, build, playground build
```

## Limits

`checkUrl` alone can't know what a name resolves to: always send with `safeRequest` or
`safeLookup` (or check DNS answers with `checkAddress`) when you make the request. `fetch()` in
Node ignores a custom lookup, so don't use it for URLs users typed. Proxies configured through
environment variables bypass the lookup check; send these requests without one.

## Maintenance

no-ssrf is small, has no dependencies, and is maintained in my spare time. Security reports come
first; other issues and pull requests are welcome, but replies may take a while.

## License

MIT
