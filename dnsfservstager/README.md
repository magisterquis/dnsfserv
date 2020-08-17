Stager Using dnsfserv
=====================
This is a simple stager which downloads a payload using DNS and runs it as Go
source code.  It's more or less a thin wrapper around
[`dnsfservget`](https://github.com/magisterquis/dnsfserv/dnsfservget) and
[`yaegi`](https://github.com/containous/yaegi).

Features
- Executes staged Go source code
- Downloads over
  - DNS
  - DNS over HTTPS (DoH)
  - Domain-fronted DoH
- Cross-platform

Not very well-tested.  Use at your own risk.

For legal use only

Payload
-------
The payload can be nearly any Go source code.  Please see the documentation for
[`yaegi`](https://github.com/containous/yaegi/blob/master/README.md) and
[`interp.Interpreter.Eval`](https://godoc.org/github.com/containous/yaegi/interp#Interpreter.Eval)
for more information about what might be interpreted.

Configuration and Building
--------------------------
There are four configurable parameters, set with `-ldflags="-X ..."` at
compile-time:

Parameter     | Required | Example                         | Description
--------------|----------|---------------------------------|------------
`main.domain` | Yes      | `example.com`                   | The base domain to query.  This can include subdomains.  A label requesting chunks of the payload will be prepended.
`main.fname`  | Yes      | `payload`                       | The filename of the payload
`main.dohURL` | No       | `https://example.net/dns-query` | If set, requests will be made to the DoH server URL
`main.dohSNI` | No       | `example.org`                   | If set a different SNI (and hostname for DNS resolution) to use for DoH, for domain-fronting

If `main.dohURL` is set, queries will be performed via DNS-over-HTTPS.  If not,
queries will use traditional DNS.

Example:
```sh
go build \
        -ldflags="-X main.domain=example.com -X main.fname=payload -x main.dohURL=https://example.net/dns-query -X main.dohSNI=example.org" \
        -o stager \
        github.com/magisterquis/dnsfserv/dnsfservstager
```
