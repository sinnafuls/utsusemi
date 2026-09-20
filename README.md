# Utsusemi

Utsusemi routes your whole Windows desktop through a [Webshare](https://www.webshare.io/)
residential proxy from the command line.

Webshare ships a Chrome extension, which only covers Chrome. This covers the
machine: browsers, Electron apps, and anything else that honours the Windows
system proxy.

The name comes from the ninja substitution trick. What gets struck is a husk
that was left behind, not the person. That is roughly what a proxy does with
your IP address.

```
utsusemi connect "user-de-rotate:password@p.webshare.io:80"
utsusemi status
utsusemi disconnect
```

## What problem this solves

You cannot paste `user:pass@p.webshare.io:80` into the Windows proxy settings
and expect it to work. Windows stores the proxy address but has nowhere to put
the username and password, so applications either pop up an authentication box
or fail outright with `407 Proxy Authentication Required`.

Utsusemi works around that by putting a small proxy of its own in the middle:

```
  your app  ->  127.0.0.1:18080  ->  p.webshare.io:80  ->  the site
                (Utsusemi relay,      (your Webshare
                 needs no password)    credentials go on here)
```

The Windows system proxy is pointed at the loopback listener, which needs no
password, and Utsusemi attaches your Webshare credentials as traffic leaves.

A useful side effect: changing exit country or rolling a session only changes
the relay's upstream. Windows settings are written once when you connect and
restored once when you disconnect, and never touched in between.

## Building

You need Rust 1.82 or newer. Install it from [rustup.rs](https://rustup.rs/) if
you do not have it.

```
git clone https://github.com/sinnafuls/utsusemi.git
cd utsusemi
cargo build --release
```

The binary is written to `target\release\utsusemi.exe`. Copy it somewhere on
your `PATH`, or run it from that path directly.

To check it built correctly:

```
target\release\utsusemi.exe --help
```

## Getting an endpoint

In the Webshare dashboard, open **Rotating Residential > Endpoint Generator**,
pick your country and session type, and copy the value from the
**Endpoint:Port** tab. It looks like this:

```
user-de-fr-nl-rotate:yourpassword@p.webshare.io:80
```

That whole string is what you hand to Utsusemi. Quote it in the shell, because
it contains characters your shell would otherwise interpret.

## Using it

### Connecting and disconnecting

```
utsusemi connect "user-de-rotate:password@p.webshare.io:80"
```

Before starting anything, `connect` opens one test tunnel through the endpoint.
If the upstream rejects it, nothing is started and the Windows settings are
left alone: a dead endpoint fails in your terminal instead of quietly breaking
every request on the desktop. `switch` and `rotate` test the new endpoint the
same way, and keep the current one if it does not work.

Otherwise Utsusemi starts in the background and gives you your prompt back.
Your desktop is now going through the proxy. When you are done:

```
utsusemi disconnect
```

If you would rather watch it run and see the log live, add `-f` to keep it in
the foreground. Ctrl+C then disconnects cleanly.

### Saving endpoints as profiles

Typing the full endpoint every time gets old, so save the ones you use:

```
utsusemi profile add germany "user-de-rotate:password@p.webshare.io:80"
utsusemi profile add tokyo   "user-jp-city_tokyo-rotate:password@p.webshare.io:80"
utsusemi profile default germany
```

Then:

```
utsusemi connect            uses the default profile
utsusemi connect tokyo      uses a named profile
utsusemi profile list       shows what you have saved
```

### Choosing where you come out

Webshare encodes geo targeting inside the proxy username. Utsusemi understands
that format, so you can override it on the command line instead of generating a
new endpoint in the dashboard:

```
utsusemi connect germany --country nl
utsusemi connect germany --country us --city los_angeles
utsusemi connect germany --country us --state arizona
utsusemi connect germany --country us --zip 77001
utsusemi connect germany --asn 7922
```

Webshare allows only one of city, state or zip at a time, and an ASN cannot be
combined with a country. Utsusemi rejects those combinations before connecting
rather than letting them silently do nothing.

Country targeting only picks from the proxies your plan actually holds, and
Webshare keeps two of those per account:

- **your proxy list** — the dedicated/shared proxies you bought, reached with
  the plain username. Only the countries in that list work, and geo filters
  beyond country are not served.
- **the rotating residential pool** — 80 million IPs in ~195 countries, with
  city, state, ZIP and ASN targeting. It has its own default username (your
  proxy username with `residential` appended), so `--residential` is what
  selects it:

```
utsusemi connect --country de --rotate --residential
utsusemi connect --country us --city houston --rotate --residential
utsusemi account                        which plans and usernames you have
```

Asking for a country your proxy list does not hold gets a bare 407 from the
backbone. `connect` turns that into an answer: it retries the same credentials
against the residential pool and with the targeting peeled back, then tells you
which variant Webshare accepts and the exact flags to reconnect with.

### Rotating and sticky sessions

```
utsusemi connect germany --rotate        new exit IP on every request
utsusemi connect germany --sticky        one IP, new random session id
utsusemi connect germany --sticky 4242   one IP, reuse session id 4242
utsusemi connect germany --rotate --pin  hunt for an exit that works, keep it
```

While connected, `utsusemi rotate` hunts a fresh exit: it probes eight
candidate sessions at once and pins the first that carries traffic, so you get
a new IP that is known to work rather than a random one that may not be.

### Dead exits, and why `--pin` exists

Residential exits are other people's machines. A share of them accept the
tunnel and then answer nothing, and that share is not small: measured on a
live account, fresh exits carried TLS about one time in ten during a bad
spell, while the same pool served plain HTTP every time. A browser survives
this by accident — it opens one tunnel per origin and reuses it, so one lucky
exit serves the whole site.

Utsusemi does three things about it:

- Every new tunnel **races up to four exits** and takes the first that
  answers, instead of waiting out each dead one in turn.
- A tunnel that finds no exit at all is **counted and explained** rather than
  left hanging, so `utsusemi status` names the target that failed.
- When several connections in a row find nothing, the relay **hunts a working
  sticky session and pins it**, which is what `--pin` does from the start.
  Pinning trades rotation for reliability: every request then leaves from the
  same exit until it goes bad, at which point the hunt runs again.

### Changing endpoint without disconnecting

```
utsusemi switch tokyo
utsusemi switch germany --country fr --sticky
```

The listeners and the Windows settings stay exactly as they are. Only new
connections use the new exit.

### Checking it actually works

```
utsusemi ip            the IP the internet sees through the proxy
utsusemi ip --direct   your real IP, to compare against
utsusemi status        endpoint, targeting, uptime, connections, bytes moved
utsusemi status --json same thing for scripts
```

`status` also prints the most recent connection failure and its age, which is
usually the fastest way to tell a broken upstream from an idle one.

### Proxying one program instead of the whole machine

If you do not want to touch the system settings, connect with
`--no-system-proxy` and launch programs through `run`, which sets the usual
proxy environment variables for that process only:

```
utsusemi connect germany --no-system-proxy
utsusemi run -- curl https://ipinfo.io/json
utsusemi run -- yt-dlp <url>
```

You can also point any application at `127.0.0.1:18080` for HTTP or
`127.0.0.1:11080` for SOCKS5 yourself.

### Using a Webshare API key

This is optional. Everything above works with a pasted endpoint and no API key.

If you add a key from
[the dashboard](https://dashboard.webshare.io/userapi/keys), Utsusemi can read
your proxy credentials from the account and build endpoints itself, so nothing
needs pasting:

```
utsusemi login <api-key>
utsusemi account
utsusemi connect --country de --rotate
utsusemi endpoint --country jp --city tokyo --sticky
```

`utsusemi endpoint` just prints an endpoint string for use in another tool.

## What does and does not get proxied

| Traffic | Proxied |
| --- | --- |
| Browsers, Electron apps, anything using the Windows system proxy | yes |
| Programs launched with `utsusemi run` | yes |
| Anything pointed at `127.0.0.1:18080` or SOCKS5 `127.0.0.1:11080` | yes |
| Windows services that use WinHTTP | only with `--winhttp`, needs Administrator |
| Programs that ignore proxy settings, most games, raw UDP | no |

Catching that last row means installing a virtual network adapter and running
as Administrator. That is deliberately not part of this tool.

DNS for proxied connections is resolved at the exit node, not on your machine.
Hostnames are passed through CONNECT and SOCKS5 untouched. If they were
resolved locally your real location would leak and geo targeting would be
pointless.

Residential exits are consumer machines, and a small share of them are black
holes at any moment: the CONNECT is accepted by the backbone and then nothing
comes back. Each tunnel therefore gets 5 seconds per exit and up to three
exits; on a rotating endpoint every retry lands on a different IP, so a dead
exit costs a few seconds rather than a hung tab.

## How it treats your Windows settings

Utsusemi writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`.
Before the first change it saves your existing `ProxyEnable`, `ProxyServer`,
`ProxyOverride` and `AutoConfigURL` into `sysproxy-backup.json`, and puts them
back on disconnect, on Ctrl+C, and when you close the console window.

If the process is killed outright, the backup file survives. `utsusemi status`
notices the leftover setting and tells you, and `utsusemi disconnect` puts
everything back.

If you have a PAC script configured (`AutoConfigURL`), Utsusemi clears it while
connected. This is necessary because Windows gives a PAC script priority over
the manual proxy, so leaving it in place would quietly bypass the relay. It is
restored with everything else.

By default, loopback, link local and private network addresses bypass the proxy
so that local development servers, printers and NAS boxes keep working. You can
change that list under `[system_proxy] bypass` in the config file.

## Files and settings

```
utsusemi where
```

prints the four paths it uses:

```
%APPDATA%\utsusemi\config.toml           profiles, API key, listener addresses
%APPDATA%\utsusemi\state.json            the live connection, owner readable only
%APPDATA%\utsusemi\utsusemi.log          log from the background relay
%APPDATA%\utsusemi\sysproxy-backup.json  your original Windows proxy settings
```

Two environment variables are read:

- `UTSUSEMI_HOME` moves all four files somewhere else, which is handy for a
  portable install on a USB stick.
- `UTSUSEMI_LOG` sets the log level, for example `UTSUSEMI_LOG=debug`.

Those files contain your proxy password in plain text, the same as the endpoint
string you pasted. They are written owner readable only where the platform
supports it. Do not commit them anywhere.

## Limitations

- Changing the Windows system proxy is Windows only. The relay itself is
  portable, so on other systems use `--no-system-proxy` together with
  `utsusemi run` or the standard proxy environment variables.
- One connection at a time. Use `utsusemi switch` to re-target the running one.
- The plain HTTP path speaks HTTP/1.x. HTTPS is tunnelled through untouched, so
  HTTP/2 works normally.

## Licence

MIT. See [LICENSE](LICENSE).
