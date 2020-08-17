DNS Fileserver Getter Library
=============================
This is a small library to wrap Go's
[`net.Lookup*`](https://golang.org/pkg/net/) functions to get a file from
[dnsfserv](github.com/magisterquis/dnsfserv).  As well as making DNS queries,
it can also do DNS over HTTPS.

Files are presented as an
[`io.ReadCloser`](https://golang.org/pkg/io/#ReadCloser).  This is to help get
around the issue that serving files over DNS is painfully slow.  It allows for
a partial read if only the start of the file is interesting.

Please see the godoc for more details.  An example program,
[`dnsfservstager`](https://github.com/magisterquis/dnsfserv/tree/master/dnsfsrevstager),
demonstrates how to use this library.

Not very well-tested.  Use at your own risk.

For legal use only.

DNS Over HTTPS (DoH)
--------------------
This library provides a simple DoH implementation as a Querier.  A pair of
standalone functions, `AppendQuery` and `ParseDoHAnswer` are available to
generate a query suitable for sending to a DoH server and to parse the
response.

Windows
-------
In order to support DoH in Windows environments where proxy settings are
complicated, `DOHQuerier` can be used to make a `Querier` which uses a custom
HTTP client.  A library such as [`go-ole`](https://github.com/go-ole/go-ole)
can be used for this.  For convience, `WrapPOST` can be used to use an existing
function similar to `http.Post`.
