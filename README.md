DNS Fileserver
--------------
Serves files over DNS.  It's not a fast way to transfer files.

Sometimes you get a stager running, but HTTP/WebDAV/NFS/netcat/SMB/etc just
don't work.  This provides one more option to get a file on target, DNS.

Features:
- Serves files over...
  - A records
  - AAAA records
  - TXT records
- Easy to add other record types
- Doesn't try to solve cache invalidation
- Easy to set up and use
- Handles multiple domains (or any domains, really, as the eTLD+1 is ignored)
- No answers for invalid queries

A library named [dnsfservget](github.com/magisterquis/dnsfserv/tree/master/dnsfservget)
may be used to abstract away the comms between an implant and dnsfserv.  There
is an example stager named
[dnsfservstager](github.com/magisterquis/dnsfservstager) which uses
dnsfservget.

Limitations and solutions:
- No caching (so don't use unique labels when possible)
- Filenames and offsets must fit in a DNS label (use short names)
- Filenames must all be lower-case, as DNS is not case-sensitive (rename files)
- DNS is only served over UDP (Ok, you got me here)

Not very well-tested.  Use at your own risk.

For legal use only.

Quickstart
----------
```sh
go get github.com/magisterquis/dnsfserv
go install github.com/magisterquis/dnsfserv
./dnsfserv -listen 127.0.0.1:5353 -dir ~/fserv
```

The above requires NS records pointed at the right address as well as firewall
rules to forward 53 to 5353.

Protocol
--------
Only the first label in a query is used.  It should be of the form 
```
N-filename
```
where `N` is a base-36 offset into the file and `filename` is the name of the
file.  The bytes of the file are returned in a record-specific format, as
follows:

Record Type | Format
------------|-------
A           | Right three bytes contain the three bytes at that offset of the file.  The first byte is always `3`. 
AAAA        | Right 8 bytes contain eight bytes at that offset of the file.  The first 8 bytes are always `2600:9000:5305:ce00`.
TXT         | A base64-encoded chunk of the file, starting at the offset.

As there is no way to know the file length ahead of time, an NXDomain will be
returned when no more bytes are available.  For AAA records in response to
queries for the last few, there is no way to know if the last bytes of the
response are significant.  This limitation may be overcome at a future date.
For many file types (ELF, shell scripts, and so on) trailing NULL bytes aren't
a huge problem.
