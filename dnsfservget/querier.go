package dnsfservget

/*
 * querier.go
 * Canned query-makers
 * By J. Stuart McMurray
 * Created 20200809
 * Last Modified 20200817
 */

import (
	"context"
	"net"
)

// Querier performs DNS queries.  It can be used to plug different protocols
// into Getter or as its own standalone resolver.  The methods retrieve DNS
// records for a DNS name.
type Querier interface {
	A(name string) ([]string, error)
	AAAA(name string) ([]string, error)
	TXT(name string) ([]string, error)
}

// DefaultQuerier returns a querier which wraps the appropriate net.Lookup*
// functions.  Due to limitations of net.LookupHost, the returned querier's A
// and AAAA methods may make requests for A and AAAA records even though only
// one type of address is returned.
func DefaultQuerier() Querier {
	return defaultQuerier{}
}

/* defaultQuerier is a Querier which wraps the net.Lookup methods */
type defaultQuerier struct{}

/* A wraps net.LookupHost but only returns IPv4 addresses */
func (defaultQuerier) A(name string) ([]string, error) {
	as, err := net.DefaultResolver.LookupIP(
		context.Background(),
		"ip4",
		name,
	)
	return ips2Strings(as), err
}

/* AAAA wraps net.LookupHost but only returns IPv6 addresses */
func (defaultQuerier) AAAA(name string) ([]string, error) {
	as, err := net.DefaultResolver.LookupIP(
		context.Background(),
		"ip6",
		name,
	)
	return ips2Strings(as), err
}

/* TXT wraps net.LookupTXT */
func (defaultQuerier) TXT(name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(context.Background(), name)
}

/* ips2Strings returns a slice of strings formed from calling the String method
of each ip in ips.  If ips is nil, the returned slice will also be nil. */
func ips2Strings(ips []net.IP) []string {
	if nil == ips {
		return nil
	}

	ss := make([]string, len(ips))
	for i, ip := range ips {
		ss[i] = ip.String()
	}

	return ss
}
