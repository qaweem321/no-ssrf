// no-ssrf: stop user-supplied URLs from reaching your server's own network.
// This entry point has no dependencies and runs anywhere (Node, Bun, Deno, edge, browsers).
// For making the request safely in Node, import from "no-ssrf/node".
export { type AddressVerdict, checkAddress, IPV4_BLOCKED, IPV6_BLOCKED, isPrivateAddress } from "./address.js";
export { parseIp, parseIPv4, parseIPv6 } from "./ip.js";
export { checkUrl, type UrlOptions, type UrlVerdict } from "./url.js";
