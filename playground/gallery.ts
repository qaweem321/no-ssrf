// Tricky URLs and what a correct SSRF check must decide. Shared by the tests and the playground.
export type GalleryEntry = { url: string; block: boolean; why: string };

export const gallery: GalleryEntry[] = [
  { url: "https://hooks.slack.com/services/T0/B0/X", block: false, why: "A normal public webhook." },
  { url: "https://93.184.215.14/", block: false, why: "A public IPv4 address." },
  { url: "https://[2606:4700:4700::1111]/", block: false, why: "A public IPv6 address." },
  { url: "https://[64:ff9b::808:808]/", block: false, why: "NAT64 to a public IPv4 address (8.8.8.8)." },
  { url: "http://169.254.169.254/latest/meta-data/", block: true, why: "The cloud metadata service: AWS, GCP and Azure credentials live here." },
  { url: "https://[::ffff:169.254.169.254]/", block: true, why: "The same, as IPv4-mapped IPv6. new URL() rewrites it to [::ffff:a9fe:a9fe], which regexes miss." },
  { url: "https://[::ffff:127.0.0.1]/", block: true, why: "Loopback as IPv4-mapped IPv6 (becomes [::ffff:7f00:1])." },
  { url: "https://[0:0:0:0:0:ffff:7f00:1]/", block: true, why: "The same, written in full." },
  { url: "https://[::127.0.0.1]/", block: true, why: "Old IPv4-compatible IPv6 form of loopback (becomes [::7f00:1])." },
  { url: "https://[64:ff9b::a9fe:a9fe]/", block: true, why: "NAT64 pointing at the metadata service." },
  { url: "https://[2002:a9fe:a9fe::]/", block: true, why: "6to4 address hiding 169.254.169.254." },
  { url: "https://127.0.0.1/", block: true, why: "Loopback: the server itself." },
  { url: "https://127.1/", block: true, why: "Short form; new URL() turns it into 127.0.0.1." },
  { url: "https://2130706433/", block: true, why: "Loopback as one decimal number." },
  { url: "https://0x7f.0.0.1/", block: true, why: "Hex octet." },
  { url: "https://0177.0.0.1/", block: true, why: "Octal octet (0177 = 127)." },
  { url: "https://0.0.0.0/", block: true, why: "0.0.0.0 reaches the server itself on Linux." },
  { url: "https://[::]/", block: true, why: "The IPv6 unspecified address." },
  { url: "https://[::1]/", block: true, why: "IPv6 loopback." },
  { url: "https://10.0.0.5/", block: true, why: "Private network." },
  { url: "https://172.20.1.1/", block: true, why: "Private network (172.16.0.0/12)." },
  { url: "https://192.168.1.1/", block: true, why: "Your router." },
  { url: "https://100.100.100.200/", block: true, why: "Alibaba Cloud's metadata service (carrier-grade NAT range)." },
  { url: "https://[fd00:ec2::254]/", block: true, why: "AWS metadata over IPv6 (unique local range)." },
  { url: "https://[fe80::1]/", block: true, why: "IPv6 link-local." },
  { url: "https://localhost/", block: true, why: "The server itself, by name." },
  { url: "https://LOCALHOST./", block: true, why: "Upper case and a trailing dot: still localhost." },
  { url: "https://api.localhost/", block: true, why: "Every *.localhost name is the server itself." },
  { url: "https://metadata.google.internal/", block: true, why: "Google Cloud's metadata service by name." },
  { url: "https://printer.local/", block: true, why: "mDNS names on the local network." },
  { url: "https://intranet/", block: true, why: "A single-label name: only the local network can resolve it." },
  { url: "https://user:pass@example.com/", block: true, why: "Credentials in the URL." },
  { url: "http://example.com/", block: true, why: "Plain http (allowed only with allowHttp)." },
  { url: "file:///etc/passwd", block: true, why: "Not a web URL." },
  { url: "gopher://127.0.0.1:6379/_FLUSHALL", block: true, why: "A classic: talking to Redis through gopher://." },
  { url: "https://255.255.255.255/", block: true, why: "Broadcast." },
  { url: "https://224.0.0.1/", block: true, why: "Multicast." },
];

// Filters people commonly write. Shown next to no-ssrf in the playground.
export const naiveFilters: { name: string; code: string; blocks: (url: string) => boolean }[] = [
  {
    name: "Regex on the raw string",
    code: "/^https?:\\/\\/(localhost|127\\.|10\\.|192\\.168\\.|169\\.254\\.)/",
    blocks: (url) => /^https?:\/\/(localhost|127\.|10\.|192\.168\.|169\.254\.)/i.test(url),
  },
  {
    name: "Regex on new URL().hostname",
    code: "/^(localhost|127\\.|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|169\\.254\\.|\\[::1\\])/",
    blocks: (url) => {
      try {
        const { hostname, protocol } = new URL(url);
        if (protocol !== "https:" && protocol !== "http:") return true;
        return /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|\[::1\])/.test(hostname);
      } catch {
        return true;
      }
    },
  },
];
