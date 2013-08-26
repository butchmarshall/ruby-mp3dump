Ruby MP3Dump
============

Captures packets on a specified network interface and saves them as files to a specified directory.  Will read id3 information and smartly rename files if available.

Dependencies
-----------

Libraries

    ruby ~> 1.8
    flex
    byacc
    libid3
    ffmpeg
    libpcap ~> 1.4
    tcpdump ~> 4.4.0

Gems

    pcap
    id3lib-ruby

Usage
-----------

    $ ruby ruby-mp3dump.rb eth0 ~/mp3out

