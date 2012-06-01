wireshark-rtpmon
================

This is a patched version of [Wireshark](http://www.wireshark.org/)'s source [repo](https://github.com/avsej/wireshark), adding a couple of features useful for passive realtime RTP monitoring.


Motivation
----------

When the `-z rtp,streams` command line option is used, Wireshark collects information about RTP streams it sees on the wire. A report of these stats is printed on the terminal when Wireshark quits.

Even if Wireshark knows what's going on in realtime, it will only produce a summary. Not very useful to see if, for example, ten minutes ago RTP was experiencing high packet loss/delay.

These limitations have been overcome in the simplest possible way by periodically dumping a few data structures to file.

Everything is pretty much experimental and a GUI is still in the works.

Building
--------

    git clone "git@github.com:giuliano108/wireshark-rtpmon.git"
    ./autogen.sh
    mkdir build
    cd build
    export CFLAGS="-D_GCRYPT_IN_LIBGCRYPT=1"
    ../configure --disable-wireshark --enable-tshark --enable-rtpmon
    make

`export CFLAGS="-D_GCRYPT_IN_LIBGCRYPT=1"` should only be needed on Mac OS, when GCrypt warnings prevent Wireshark from being built successfully.


Usage
-----

Invoke `tshark` as you'd normally do:

    # ./tshark -i eth1 -q -M qpath=~/rtpmon

Here are the additional command line options:

    # ./tshark --help
    [..]
    RTP monitor:
      -M <key=value,..>        Enables the passive RTP monitor/stats collector.
                               Options take the form of key=value pairs.
                               Use a comma to separate multiple options.
        qpath=/tmp
            Statistics will be stored in the given path ("/tmp" by default).
            Multiple files, named "rtpmon-00000.bin", will be created.
            "rtpmonlast.txt" will contain the index to the last dumped sample.
            Each file is a sample of the "rtpstream_tapinfo_t" data structure
            (see "ui/cli/tap-rtp.c").
        qlen=600
            Keep (by default) 600 samples.
            That's 10 minutes worth of data at 1000 ms dump interval.
        dump-interval=1000
            Dump RTP statistics (by default) every 1000 milliseconds.
            Because timing is checked only as new RTP packets arrive, files
            might not get written at exact intervals.
    [..] 

Using the data produced by wiresark-rtpmon
------------------------------------------

* Run `./tshark -M describe-output`, check which structures are being dumped.
* Have a look at Wireshark's sources, decide which info you do need.
* Decode the files and do something with them.
