package dnsfservget

/*
 * dnsfservget.go
 * Get files from dnsfserv
 * By J. Stuart McMurray
 * Created 20200805
 * Last Modified 20200817
 */

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

const (
	// MaxDecode is the maximum amount of decoded data decoded by
	// DecodeRespnose.
	MaxDecode = 160
)

// QType is a DNS query type.
type QType string

// PayloadSize returns the maximum number of payload bytes returnable by a
// query of type q.
func (q QType) PayloadSize() (uint, error) {
	switch q {
	case TypeA:
		return 3, nil
	case TypeAAAA:
		return 8, nil
	case TypeTXT:
		return 160, nil
	default:
		return 0, ErrorUnsupportedQType{q}
	}
}

// ErrorUnsupportedQType is returned when an unsupported QType is encountered.
type ErrorUnsupportedQType struct {
	Type QType // QType which caused the error
}

// Erorr implenents the error interface
func (e ErrorUnsupportedQType) Error() string {
	return fmt.Sprintf("unsupported query type %q", e.Type)
}

// Supported QTypes
const (
	TypeA    QType = "A"
	TypeAAAA QType = "AAAA"
	TypeTXT  QType = "TXT"
)

// Getter gets a file from dnsfserv.  Its Get method makes all of the necessary
// requests and sends the file to the io.ReadCloser.  Getter's NextQuery and
// ParseResponse may be used intead of Get if a custom HTTP transport is
// desirable.  Getter must not be modified after first use.
//
// Due to limitations of Go's stdlib, TypeA and TypeAAAA queries may both be
// made if Getter.Type is set to either.  In general, TypeAAAA will be faster
// but it may be desirable to set TypeA explicitly in case AAAA queries are
// unavailable.
//
// A minimum getter is something along the lines of
//   Getter{Type: TypeA, Name: "payload", Domain: "example.com"}
type Getter struct {
	Type   QType  /* Type of queries to use */
	Name   string /* Name of file to retrieve */
	Domain string /* Domain from which to retrieve file */

	/* The following two fields control how much of the file to retrieve.
	The retrieved part of the file will start at StartOff and extend for
	Max bytes if Max is nonzero.  Additional bytes may be retrieved but
	will not be returned by Getter.Get. */
	StartOff uint /* Initial offset to retrieve */
	Max      uint /* Maximum number of bytes to return, only used by Getter.Get */

	/* If set, Querier is used to perfrom the queries.  If unset,
	DefaultQuerier() is used. */
	Querier Querier

	off uint /* Offset into file */
	l   sync.Mutex
}

// Get gets the file described by g.  The returned io.ReadCloser will be closed
// when the file has been retrieved or on error.  If g.Type is set to an
// invalid QType, the first read from the returned io.ReadCloser return an
// error.
func (g *Getter) Get() io.ReadCloser {
	pr, pw := io.Pipe()
	go g.get(pw)
	return pr
}

/* get makes the queries to get the file */
func (g *Getter) get(pw *io.PipeWriter) {
	/* Make sure we have something with which to make queries */
	if nil == g.Querier {
		g.Querier = DefaultQuerier()
	}

	var (
		q    string
		as   []string
		err  error
		n    int
		de   *net.DNSError
		buf  = make([]byte, MaxDecode)
		umax = 0 == g.Max
	)
	for {
		/* If we've got no more to write, we're done */
		if 0 == g.Max && !umax {
			pw.Close()
			return
		}

		/* Roll a query */
		q, err = g.NextName()
		if nil != err {
			pw.CloseWithError(
				fmt.Errorf("generating query name: %w", err),
			)
			return
		}
		switch g.Type {
		case TypeA:
			as, err = g.Querier.A(q)
		case TypeAAAA:
			as, err = g.Querier.AAAA(q)
		case TypeTXT:
			as, err = g.Querier.TXT(q)
		default:
			pw.CloseWithError(ErrorUnsupportedQType{g.Type})
			return
		}
		if nil != err {
			/* NXDomain == EOF */
			if errors.As(err, &de) && de.IsNotFound {
				pw.Close()
			} else {
				pw.CloseWithError(fmt.Errorf(
					"querying for %q: %w",
					q,
					err,
				))
			}
			return
		}
		/* No answer probably means someone's blocking something */
		if 0 == len(as) {
			pw.CloseWithError(fmt.Errorf(
				"empty response to query for %q",
				q,
			))
			return
		}
		/* Decode the response and send it back */
		n, err = g.DecodeResponse(buf, as[0])
		if nil != err {
			pw.CloseWithError(fmt.Errorf(
				"decoding response %q to %q: %w",
				as[0],
				q,
				err,
			))
			return
		}
		if 0 > n {
			pw.CloseWithError(errors.New(
				"negative number of bytes decoded",
			))
		}
		/* Don't write too many bytes */
		if g.Max < uint(n) && !umax {
			n = int(g.Max)
		}
		if _, err = pw.Write(buf[:n]); nil != err {
			pw.CloseWithError(err)
			return
		}
		/* Note how many we've written */
		if !umax {
			g.Max -= uint(n)
		}
	}
}

// NextName returns a DNS name which can be queried to get the next chunk of
// the file.  NextName should not be called after Get has been called.
func (g *Getter) NextName() (string, error) {
	g.l.Lock()
	defer g.l.Unlock()

	/* If we're starting, make sure to start at the right offset */
	if 0 == g.off && 0 != g.StartOff {
		g.off = g.StartOff
	}

	/* Roll the query */
	q := fmt.Sprintf(
		"%s-%s.%s",
		strconv.FormatUint(uint64(g.off), 36),
		g.Name,
		g.Domain,
	)

	/* Advance the offset for the next call */
	a, err := g.Type.PayloadSize()
	if nil != err {
		return "", fmt.Errorf("determining payload size: %w", err)
	}
	g.off += a

	return q, nil
}

// DecodeResponse extracts the bytes of the file from the DNS response and
// places the decoded bytes in buf.  If buf is too small DecodeResponse returns
// an error.  The appropriate size for the buffer can be found using
// Getter.Type.PayloadSize.
func (g *Getter) DecodeResponse(buf []byte, res string) (int, error) {
	switch g.Type {
	case TypeA, TypeAAAA:
		return g.decodeA(buf, res)
	case TypeTXT:
		return g.decodeTXT(buf, res)
	default:
		return 0, ErrorUnsupportedQType{g.Type}
	}
}

/* decodeA decodes an IPv4 or IPv6 address and places the payload in buf.  The
number of decoded bytes is returned. */
func (g *Getter) decodeA(buf []byte, res string) (int, error) {
	/* Parse as an IP address */
	ip := net.ParseIP(res)
	if nil == ip {
		return 0, fmt.Errorf("invalid IP address %q", res)
	}
	/* Parse with the appropriate length */
	var plen, start int
	switch g.Type {
	case TypeA:
		ip = ip.To4()
		plen = 4
		start = 1
	case TypeAAAA:
		ip = ip.To16()
		plen = 16
		start = 8
	}
	/* If we didn't get an address of the right size, someone goofed */
	if nil == ip {
		return 0, fmt.Errorf("unable to parse IP address %s", res)
	}
	/* Make sure we have enough buffer */
	if plen > len(buf) {
		return 0, fmt.Errorf(
			"buffer too small for record of type %s",
			g.Type,
		)
	}
	/* Extract the payload */
	return copy(buf, ip[start:]), nil
}

/* decodeTXT decodes a TXT record and places the payload in buf.  The number of
decoded bytes is returned. */
func (g *Getter) decodeTXT(buf []byte, txt string) (int, error) {
	if base64.RawStdEncoding.DecodedLen(len(txt)) > len(buf) {
		return 0, errors.New("buffer too small for decoded payload")
	}
	n, err := base64.RawStdEncoding.Decode(buf, []byte(txt))
	if nil != err {
		return n, fmt.Errorf("decoding TXT record: %s", err)
	}
	return n, nil
}
