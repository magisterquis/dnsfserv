package dnsfservget

/*
 * doh.go
 * fserve using DNS over HTTPS
 * By J. Stuart McMurray
 * Created 20200809
 * Last Modified 20200817
 */

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// DefaultDOHPort is used by BuiltinDFPost as the default port for TLS
	// connections
	DefaultDOHPort = "443"

	// MaxPOSTBody is the maximum number of bytes from a POST response body
	// which will be used by the POSTClients returned from the functions
	// in this package.
	MaxPOSTBody = 65535
)

/* bufPool holds a pool of buffers for rolling and unrolling DNS messages */
var bufPool = sync.Pool{
	New: func() interface{} { return make([]byte, MaxPOSTBody) },
}

/* getBuf gets a buffer from bufPool.  The buffer will have a length and cap of
MaxPOSTBody bytes */
func getBuf() []byte {
	var b []byte
	/* There should never be a under-capacity buffer in the pool, but just
	in case, remove those which are */
	for MaxPOSTBody > cap(b) {
		b = bufPool.Get().([]byte)
	}
	return b[:MaxPOSTBody]
}

/* putBuf puts b into the pool if cap(b) == MaxPOSTBody */
func putBuf(b []byte) {
	if MaxPOSTBody != cap(b) {
		return
	}
	bufPool.Put(b[:MaxPOSTBody])
}

// A POSTClient is an function which performs an HTTP POST query for the URL,
// sending it reqBody as the POST body, and returns the body of the response.
// An error should be returned for any non-2xx response, in accordance with
// https://tools.ietf.org/html/rfc8484#section-4.2.1
type POSTClient func(URL string, reqBody []byte) (resBody []byte, err error)

// DOHConfig is used to configure a querier which uses DoH
type DOHConfig struct {
	// URL is the URL of the DoH server, e.g. https://dns.quad9.net/dns-query
	URL string

	// POSTClient will be used to perform HTTP queries.  If this is not
	// set, BuiltinPOST() will be used.
	POST POSTClient
}

// dohQuerier implements Querier but performs the lookups using DNS over HTTPS
// (https://tools.ietf.org/html/rfc8484).
type dohQuerier struct {
	u    string /* URL */
	post POSTClient
}

// dohQuerier implements Querier but performs the lookups using DNS over HTTPS
// (https://tools.ietf.org/html/rfc8484).  The returned Querier will not
// resolve CNAME records into A records.  This is a known limitation.
func DOHQuerier(conf DOHConfig) Querier {
	q := dohQuerier{
		u:    conf.URL,
		post: conf.POST,
	}
	if nil == q.post {
		q.post = BuiltinPOST()
	}

	return q
}

/* dohQuery does a DoH query for the given name and record type */
func (d dohQuerier) dohQuery(name string, qtype QType) ([]string, error) {
	/* Buffer for the query */
	qb := getBuf()
	defer putBuf(qb)

	/* Roll a Query */
	var err error
	qb, err = AppendQuery(name, qtype, qb[:0])
	if nil != err {
		return nil, fmt.Errorf("generating query: %w", err)
	}

	/* Send query off */
	res, err := d.post(d.u, qb)
	if nil != err {
		return nil, fmt.Errorf("sending query: %w", err)
	}
	defer putBuf(res)

	/* Send back answer */
	as, err := ParseDoHAnswer(res, qtype)
	if nil != err {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return as, nil
}

/* A implements Querier.A */
func (d dohQuerier) A(name string) ([]string, error) {
	return d.dohQuery(name, TypeA)
}

/* AAAA implements Querier.AAAA */
func (d dohQuerier) AAAA(name string) ([]string, error) {
	return d.dohQuery(name, TypeAAAA)
}

/* TXT implements Querier.TXT */
func (d dohQuerier) TXT(name string) ([]string, error) {
	return d.dohQuery(name, TypeTXT)
}

// BuiltinPOST returns a POSTClient which is a thin wrapper around
// http.Client.Post.  It is a convenience function for WrapPOST(http.Post).
func BuiltinPOST() POSTClient {
	return WrapPOST(http.Post)
}

// BuiltinDFPOST returns a POSTClient which is a thing wrapper around
// http.Client.Post but uses the provided sni both to obtain the IP address of
// the server as well as in the SNI of the TLS connection.  An optional port
// may be supplied with the SNI in host:port form.  If not, DefaultDOHPort will
// be used.
func BuiltinDFPOST(sni string) POSTClient {
	/* Make sure we have a port */
	_, p, err := net.SplitHostPort(sni)
	if "" == p || nil != err {
		sni = net.JoinHostPort(sni, DefaultDOHPort)
	}

	/* Roll a domain-fronting HTTP client */
	d := new(tls.Dialer)
	return WrapPOST((&http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(
				ctx context.Context,
				network string,
				addr string,
			) (net.Conn, error) {
				return d.DialContext(ctx, "tcp", sni)
			},
		},
	}).Post)
}

// WrapPOST wraps a function like http.Post into a POSTClient
func WrapPOST(post func(URL string, contentType string, body io.Reader) (resp *http.Response, err error)) POSTClient {
	return func(URL string, reqBody []byte) (resBody []byte, err error) {
		/* Make the query */
		res, err := post(
			URL,
			/* Kinda an edge case.  Setting it to the proper type
			gives defenders more info, but may be required.
			Testing indicates it's not. */
			"",
			bytes.NewReader(reqBody),
		)
		if nil != err {
			return nil, fmt.Errorf("making request: %w", err)
		}
		defer res.Body.Close()
		/* Non-200's are bad */
		if 200 < res.StatusCode || 200 > res.StatusCode {
			return nil, fmt.Errorf(
				"non-2xx response status %d %s",
				res.StatusCode,
				res.Status,
			)
		}
		/* Slurp the body */
		b := getBuf()
		n, err := io.ReadFull(res.Body, b)
		if nil != err && !errors.Is(err, io.ErrUnexpectedEOF) {
			putBuf(b)
			return nil, fmt.Errorf(
				"reading response body: %w",
				err,
			)
		}
		/* Send it back */
		return b[:n], nil
	}
}

// AppendQuery appends a DNS query for the given domain and type suitable for a
// DoH POST request body to b and returns the resulting slice.  The class will
// always be inet.
func AppendQuery(qname string, qtype QType, b []byte) ([]byte, error) {
	/* Translate the type to dnsmessage */
	var qt dnsmessage.Type
	switch qtype {
	case TypeA:
		qt = dnsmessage.TypeA
	case TypeAAAA:
		qt = dnsmessage.TypeA
	case TypeTXT:
		qt = dnsmessage.TypeTXT
	default:
		return nil, ErrorUnsupportedQType{qtype}
	}

	/* Make sure the name ends with a . */
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}
	qn, err := dnsmessage.NewName(qname)
	if nil != err {
		return nil, fmt.Errorf(
			"error processing %q for query: %q",
			qname,
			err,
		)
	}

	/* Roll a DNS message */
	return (&dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  qn,
			Type:  qt,
			Class: dnsmessage.ClassINET,
		}},
	}).AppendPack(b)
}

// ParseDoHAnswer parses an answer from a DoH server.  It returns a slice of
// the records of the given type.  If no records of the requested type are
// found but there was no error indicated in the DNS response, ParseDoH answer
// returns a nil error and a 0-length slice.
//
// If the answer indicates an NXDomain, a *net.DNSError is returned with its
// IsNotFound field true.  Other errors may be represented by other types.
func ParseDoHAnswer(ans []byte, filt QType) ([]string, error) {
	/* Work out what type we need */
	var mt dnsmessage.Type
	switch filt {
	case TypeA:
		mt = dnsmessage.TypeA
	case TypeAAAA:
		mt = dnsmessage.TypeAAAA
	case TypeTXT:
		mt = dnsmessage.TypeTXT
	}

	/* Unpack the message */
	var m dnsmessage.Message
	if err := m.Unpack(ans); nil != err {
		return nil, fmt.Errorf("unpacking response: %w", err)
	}

	/* Make sure we got a good answer */
	switch m.Header.RCode {
	case dnsmessage.RCodeSuccess: /* Good. */
		break
	case dnsmessage.RCodeNameError: /* NXDomain */
		/* Maybe we get a name */
		var n string
		if 0 != len(m.Questions) {
			n = m.Questions[0].Name.String()
		}
		return nil, &net.DNSError{
			Err:        "name not found",
			Name:       n,
			IsNotFound: true,
		}
	default: /* Other error */
		return nil, fmt.Errorf(
			"unsuccessful DNS response code %s (%d)",
			m.Header.RCode,
			m.Header.RCode,
		)
	}

	/* Extract the records */
	var ss []string
	for _, ans := range m.Answers {
		/* Skip records we don't care about */
		if ans.Header.Type != mt {
			continue
		}
		/* Extract the answer itself */
		switch ar := ans.Body.(type) {
		case *dnsmessage.AResource:
			ss = append(ss, net.IP(ar.A[:]).String())
		case *dnsmessage.AAAAResource:
			ss = append(ss, net.IP(ar.AAAA[:]).String())
		case *dnsmessage.TXTResource:
			ss = append(ss, ar.TXT...)
		default:
			continue
		}
	}

	return ss, nil
}
