package dnsfservget

/*
 * doc_test.go
 * Example for dnsfservget
 * By J. Stuart McMurray
 * Created 20200817
 * Last Modified 20200817
 */

import (
	"io"
	"os"
)

func ExampleGetter() {
	/* Copy the file named payload hosted using
	dnsfserv at example.com to stdout */
	io.Copy(
		os.Stdout,
		(&Getter{
			Name:   "payload",
			Type:   TypeA,
			Domain: "example.com",
		}).Get(),
	)
}
