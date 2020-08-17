// Package dnsfservget is a wrapper to get files from dnsfserv
//
// Users of this package should make a Getter and set at least its Type, Name,
// and Domain fields.  The Getter may either be used to retrieve the file
// itself with its Get method or the Getter's NextName and DecodeResponse
// methods may be used to generate query names and extract the payload from
// responses without actually making traffic.
//
// Please see the Getter example for a minimal working example.
package dnsfservget
