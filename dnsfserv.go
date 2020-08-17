// Program dnsfserv serves files over DNS
package main

/*
 * dnsfserv.go
 * Serve files over DNS
 * By J. Stuart McMurray
 * Created 20200805
 * Last Modified 20200817
 */

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	/* netbuflen is the maximum size of a packet we get from or send to
	the network */
	netbuflen = 1024

	/* rxPause is the amount of time to wait before trying to receive
	another packet after a temporary error */
	rxPause = time.Second

	/* ansAFirstByte is the first byte of an A record response */
	ansAFirstByte = 3

	/* ansTXTMax is the maximum amount of plaintext to put in a TXT
	record */
	ansTXTMax = 160
)

var (
	/* ansAAAAFirstHalf is the first half on an AAAA record response */
	ansAAAAFirstHalf = []byte{
		0x26, 0x00, 0x90, 0x00, 0x53, 0x05, 0xce, 0x00,
	}
)

var (
	/* bufpool hands out buffers which hold netbuflen bytes */
	bufpool = sync.Pool{
		New: func() interface{} { return make([]byte, netbuflen) },
	}
	/* msgpool hands out dns message buffers */
	msgpool = sync.Pool{
		New: func() interface{} { return new(dnsmessage.Message) },
	}
)

/* Set by flags */
var (
	ttl  uint
	fdir string
)

func main() {
	var (
		laddr = flag.String(
			"listen",
			"127.0.0.1:5353",
			"Listen `address`",
		)
	)
	flag.StringVar(
		&fdir,
		"dir",
		"fserv",
		"Name of `directory` containing files to serve",
	)
	flag.UintVar(
		&ttl,
		"ttl",
		1800,
		"Response TLL in `seconds`",
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Serves chunks of files from a directory in response to DNS queries.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Log nicer */
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	/* Listen for DNS queries */
	pc, err := net.ListenPacket("udp", *laddr)
	if nil != err {
		log.Fatalf("Error listening on %s: %s", *laddr, err)
	}
	log.Printf("Listening for DNS queries on %s", pc.LocalAddr())

	/* Serve queries */
	var te interface{ Temporary() bool }
	for {
		/* Get a query */
		buf := bufpool.Get().([]byte)
		n, addr, err := pc.ReadFrom(buf)
		if nil != err {
			if errors.As(err, &te) {
				bufpool.Put(buf)
				log.Printf("Temporary receive error: %s", err)
				time.Sleep(rxPause)
				continue
			}
			log.Fatalf("Receiving packet: %s", err)
		}
		/* Process it and recycle the buffer */
		go func() {
			defer bufpool.Put(buf)
			if 0 == n {
				return
			}
			handle(pc, addr, buf, n)
		}()
	}
}

/* handle responds to the dnsquery of n bytes in buf, as sent from addr to
pc.  A file from fdir is served. */
func handle(pc net.PacketConn, addr net.Addr, buf []byte, n int) {
	/* Parse the DNS query */
	msg := msgpool.Get().(*dnsmessage.Message)
	defer msgpool.Put(msg)
	if err := (*msg).Unpack(buf[:n]); nil != err {
		log.Printf(
			"[%s] Error unpacking %d byte message: %s",
			addr,
			n,
			err,
		)
		return
	}

	/* Set up the header */
	msg.Header.Response = true
	msg.Header.Authoritative = true
	msg.Header.RecursionAvailable = false
	msg.Header.RCode = dnsmessage.RCodeSuccess

	/* Make sure there's at least one question.  We'll only respond to one
	per message, to keep things simple. */
	if 0 == len(msg.Questions) {
		log.Printf("[%s] Got query with 0 questions", addr)
		return
	}

	/* Get the filename and offset */
	q := strings.ToLower(msg.Questions[0].Name.String())
	labels := strings.SplitN(q, ".", 2)
	if 0 == len(labels) {
		log.Printf("[%s] Empty query", addr)
		return
	}
	q = fmt.Sprintf("%s(%s)", q, msg.Questions[0].Type)
	parts := strings.SplitN(labels[0], "-", 2)
	if 2 != len(parts) {
		log.Printf("[%s] Badly-formatted query %q", addr, q)
		return
	}
	if 0 == len(parts[0]) {
		log.Printf("[%s] No offset in %q", addr, q)
		return
	}
	foff, err := strconv.ParseUint(parts[0], 36, 64)
	if nil != err {
		log.Printf(
			"[%s] Error parsing file offset %q in %q: %s",
			addr,
			parts[0],
			q,
			err,
		)
		return
	}
	fname := filepath.Clean(parts[1])

	/* Try to open the file */
	fname = filepath.Join(fdir, fname)
	f, err := os.OpenFile(fname, os.O_RDONLY, 000)
	if nil != err {
		log.Printf(
			"[%s] Error opening file %q for %q: %s",
			addr,
			fname,
			q,
			err,
		)
		return
	}
	defer f.Close()

	/* Seek to the offset */
	flen, err := f.Seek(0, os.SEEK_END)
	if nil != err {
		log.Printf(
			"[%s] Error getting size of %s: %s",
			addr,
			f.Name(),
			err,
		)
	}
	if foff >= uint64(flen) { /* EOF */
		log.Printf(
			"[%s] EOF at offset %d of %s for %q",
			addr,
			foff,
			f.Name(),
			q,
		)
		sendEOF(pc, addr, buf, msg, q)
		return
	}
	if _, err := f.Seek(int64(foff), os.SEEK_SET); nil != err {
		log.Printf(
			"[%s] Error seeking to %d in %s for %q: %s",
			addr,
			foff,
			f.Name(),
			q,
			err,
		)
		return
	}

	/* Roll a response record */
	var rr dnsmessage.Resource
	rr.Header.Name = msg.Questions[0].Name
	rr.Header.Type = msg.Questions[0].Type
	rr.Header.Class = msg.Questions[0].Class
	rr.Header.TTL = uint32(ttl)
	switch rr.Header.Type {
	case dnsmessage.TypeA:
		var ans dnsmessage.AResource
		ans.A[0] = ansAFirstByte
		n, err = f.Read(ans.A[1:])
		rr.Body = &ans
	case dnsmessage.TypeAAAA:
		var ans dnsmessage.AAAAResource
		copy(ans.AAAA[:], ansAAAAFirstHalf)
		_, err = f.Read(ans.AAAA[len(ansAAAAFirstHalf):])
		rr.Body = &ans
	case dnsmessage.TypeTXT:
		var ans dnsmessage.TXTResource
		if n, err = f.Read(buf[:ansTXTMax]); nil != err {
			break
		}
		ans.TXT = []string{
			base64.RawStdEncoding.EncodeToString(buf[:n]),
		}
		rr.Body = &ans
	default:
		log.Printf(
			"[%s] Unsupported %s request for %q",
			addr,
			msg.Questions[0].Type,
			q,
		)
		return
	}
	if errors.Is(err, io.EOF) {
		log.Printf(
			"[%s] Unexpected EOF at offset %d of %s for %q",
			addr,
			foff,
			f.Name(),
			q,
		)
		sendEOF(pc, addr, buf, msg, q)
		return
	} else if nil != err {
		log.Printf(
			"[%s] Error reading from %s for answer to %q: %s",
			addr,
			f.Name(),
			q,
			err,
		)
		return
	}
	msg.Answers = append(msg.Answers, rr)

	/* Send the answer back */
	if serr := sendResponse(pc, addr, buf, msg); nil != serr {
		log.Printf("[%s] Error sending response: %s", addr, serr)
	}
	log.Printf(
		"[%s] Responded starting at offset %d of %s for %s",
		addr,
		foff,
		f.Name(),
		q,
	)
}

/* sendResponse sends the message to addr via pc.  It will be stored in buf. */
func sendResponse(
	pc net.PacketConn,
	addr net.Addr,
	buf []byte,
	msg *dnsmessage.Message,
) error {
	/* Marshal the message */
	p, err := msg.AppendPack(buf[:0])
	if nil != err {
		return err
	}

	/* Send it back */
	_, err = pc.WriteTo(p, addr)
	return err
}

/* sendEOF sets msg to be an NXDomain and sends it to addr via pc, using buf */
func sendEOF(
	pc net.PacketConn,
	addr net.Addr,
	buf []byte,
	msg *dnsmessage.Message,
	q string,
) {
	msg.RCode = dnsmessage.RCodeNameError
	if err := sendResponse(pc, addr, buf, msg); nil != err {
		log.Printf("[%s] Error sending EOF for %q: %s", addr, q, err)
	}
}
