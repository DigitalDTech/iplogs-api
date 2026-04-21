# IPLogs — Free VPN, Proxy & Datacenter IP Detection API

> Public README and integration examples for the IPLogs detection API at [iplogs.com](https://iplogs.com). This repository contains documentation and client examples only — the detection engine itself is a hosted service.

[![Website](https://img.shields.io/badge/site-iplogs.com-22c55e)](https://iplogs.com)
[![API](https://img.shields.io/badge/API-free-blue)](https://iplogs.com/docs)
[![Blog](https://img.shields.io/badge/blog-research-orange)](https://iplogs.com/blog)

---

## What it does

IPLogs classifies any IPv4 address into one of four verdicts — `clean`, `suspicious`, `vpn_likely`, `vpn_detected` — by combining seven independent detection layers:

1. **IP intelligence** — known VPN server lists (NordVPN, Mullvad, PIA, ProtonVPN, SoftEther), datacenter ASNs, Tor exit nodes (refreshed hourly), hosting-backed residential-proxy backbones.
2. **TCP/IP fingerprint** — MSS, TTL, window-size anomalies.
3. **TLS / JA3 / JA4 fingerprint** — hash of the TLS ClientHello matched against known VPN client libraries.
4. **RTT analysis** — [SNITCH](https://www.ndss-symposium.org/ndss2025/) TCP vs TLS RTT differential and cross-layer RTT checks (NDSS 2025).
5. **Active probing** — OpenVPN HARD_RESET, WireGuard handshake init, IKEv2 SA_INIT, REALITY cert-switch on SNI fuzzing.
6. **Client signals** — browser timezone, language, WebRTC ICE leak.
7. **Port & network sanity** — non-standard ports, reverse DNS mismatch, hosting-provider naming.

Every verdict returns the full list of signals that produced it — no black-box scoring.

---

## Free. Public. No signup.

- **Endpoint:** `POST https://iplogs.com/v1/check`
- **Rate limit:** ~60 requests/minute per source IP
- **Auth:** none
- **CORS:** enabled

---

## Quickstart

### curl

```bash
curl -X POST https://iplogs.com/v1/check \
  -H 'content-type: application/json' \
  -d '{"ip":"8.8.8.8"}'
```

### Python

```python
import requests

r = requests.post(
    "https://iplogs.com/v1/check",
    json={"ip": "45.82.245.81"},
    timeout=10,
)
data = r.json()
print(data["verdict"], data["score"])
for signal in data["signals"]:
    if signal["matched"]:
        print(" ", signal["type"], signal["detail"])
```

### Node.js / TypeScript

```typescript
const resp = await fetch("https://iplogs.com/v1/check", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ ip: "45.82.245.81" }),
});
const data = await resp.json();
console.log(data.verdict, data.score);
```

### Go

```go
body := strings.NewReader(`{"ip":"45.82.245.81"}`)
resp, _ := http.Post(
    "https://iplogs.com/v1/check",
    "application/json",
    body,
)
defer resp.Body.Close()
```

### PHP

```php
$ch = curl_init('https://iplogs.com/v1/check');
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['ip' => '45.82.245.81']));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$resp = json_decode(curl_exec($ch), true);
echo $resp['verdict'];
```

### Ruby

```ruby
require 'net/http'
require 'json'
uri = URI('https://iplogs.com/v1/check')
req = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
req.body = { ip: '45.82.245.81' }.to_json
res = Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |h| h.request(req) }
puts JSON.parse(res.body)['verdict']
```

---

## Response schema

```jsonc
{
  "verdict": "clean" | "suspicious" | "vpn_likely" | "vpn_detected",
  "score": 0.0,              // 0–1, sum of matched signal weights
  "is_vpn": false,
  "confidence": 0.2,         // 0–1, how confident we are in the verdict
  "ip_info": {
    "ip": "8.8.8.8",
    "asn": "AS15169",
    "org": "Google LLC",
    "isp": "Google LLC",
    "country": "United States",
    "country_code": "US",
    "city": "Mountain View",
    "lat": 37.422,
    "lon": -122.085,
    "type": "datacenter",
    "is_vpn": false,
    "is_proxy": false,
    "vpn_provider": null
  },
  "signals": [
    {
      "type": "dc_ip",
      "weight": 0.1,
      "matched": true,
      "detail": "Datacenter / hosting ASN AS15169 (Google LLC)"
    }
    // ...25+ signals evaluated per request
  ],
  "request_id": "req_6d740eec-9ed"
}
```

### Verdict thresholds

| Score | Verdict |
|---|---|
| `≥ 0.75` | `vpn_detected` |
| `0.50–0.75` | `vpn_likely` |
| `0.30–0.50` | `suspicious` |
| `< 0.30` | `clean` |

---

## Signal catalog

| Signal | Layer | Meaning |
|---|---|---|
| `known_vpn_exact` | IP intel | IP on curated VPN list |
| `known_vpn_cidr` | IP intel | IP inside a known VPN CIDR range |
| `tor_exit` | IP intel | IP in current Tor exit-node list |
| `vpn_asn` | IP intel | ASN classified as a commercial VPN provider |
| `vpn_org_keyword` | IP intel | ASN org name contains a VPN keyword |
| `dc_ip` | IP intel | Datacenter or hosting IP |
| `mtu_anomaly` | TCP/IP | Non-standard MSS consistent with tunneling |
| `ttl_os_mismatch` | TCP/IP | TTL doesn't match claimed OS |
| `tcp_window_anomaly` | TCP/IP | Non-default TCP window |
| `ja3_known_vpn` | TLS | JA3 hash matches a known VPN client |
| `rtt_snitch` | RTT | TCP vs TLS RTT differential (NDSS 2025) |
| `geo_rtt_mismatch` | RTT | Cross-layer RTT inconsistent with geolocation |
| `active_probe_openvpn` | Probe | Port 1194 responds to OpenVPN |
| `active_probe_wireguard` | Probe | Port 51820 responds to WireGuard |
| `active_probe_ikev2` | Probe | Port 500 responds to IKEv2 |
| `active_probe_reality` | Probe | REALITY cert-switch via SNI fuzzing |
| `tz_mismatch` | Client | Browser timezone differs from IP geo |
| `lang_mismatch` | Client | Browser language incongruent with region |
| `webrtc_leak` | Client | WebRTC exposes different public IP |
| `nonstandard_port` | Port | Service on non-standard port |

---

## Request fields

| Field | Type | Description |
|---|---|---|
| `ip` | string, optional | IPv4 to check. Omit to check caller's IP. |
| `user_agent` | string, optional | Client UA, for OS/browser cross-check. |
| `timezone` | string, optional | IANA timezone (e.g. `America/New_York`). |
| `language` | string, optional | BCP47 language tag. |
| `webrtc_ip` | string, optional | WebRTC-revealed public IP. |
| `tcp_rtt_ms` | number, optional | Client-measured TCP handshake RTT. |
| `tls_rtt_ms` | number, optional | Client-measured TLS handshake RTT. |

---

## Use cases

- **Fraud prevention** — gate signup, checkout, password reset behind a VPN check.
- **Geo-licensing** — enforce streaming or regulatory geo-restrictions.
- **Bot & scraper defense** — flag datacenter-origin traffic without CAPTCHAs.
- **Security research** — instrument detection into custom log pipelines.
- **Ad-fraud auditing** — verify media-buy traffic isn't proxy-farm origin.
- **Compliance logging** — record verdict alongside privileged requests.

---

## Related

- **Website:** [iplogs.com](https://iplogs.com)
- **Full docs:** [iplogs.com/docs](https://iplogs.com/docs)
- **FAQ:** [iplogs.com/faq](https://iplogs.com/faq)
- **Blog (research-backed posts):** [iplogs.com/blog](https://iplogs.com/blog)
  - [How the Great Firewall of China works in 2026](https://iplogs.com/blog/how-the-great-firewall-of-china-works-2026)
  - [How VPN detection actually works — the 7-layer method](https://iplogs.com/blog/how-vpn-detection-actually-works)
  - [Russia's TSPU: how Roskomnadzor blocks VPNs](https://iplogs.com/blog/russia-tspu-how-it-blocks-vpns)
  - [Iran's internet censorship: NIN, SIAM, mobile surveillance](https://iplogs.com/blog/iran-internet-censorship-siam-nin)
  - [JA3 and JA4 TLS fingerprinting explained](https://iplogs.com/blog/ja3-ja4-tls-fingerprinting-explained)
- **Data pages:**
  - [Live Tor exit-node list](https://iplogs.com/tor-exit-nodes)
  - [Datacenter IP ranges catalog](https://iplogs.com/datacenter-ip-ranges)

---

## Dedicated tier

For sustained multi-million-request workloads, email **admin@iplogs.com** with your use case, expected volume, and SLA requirements. Dedicated infrastructure, higher rate limits, and enterprise SLAs are available.

---

## Contact

- **Email:** admin@iplogs.com
- **Website:** [iplogs.com](https://iplogs.com)
- **Built by:** [DigitalD.tech](https://digitald.tech)

---

## Citation

If you reference IPLogs in a paper, blog post, or product documentation:

```
IPLogs (2026). Free multi-layer VPN and proxy detection service.
DigitalD.tech. https://iplogs.com.
```
