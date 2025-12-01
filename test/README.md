### Pattern modification

Here are some example patterns for traffic modification.

Put the patterns_fromclient and patterns_fromserver directories in /home/youpot/youpot

patterns_fromclient - modifications for traffic from the client to the server

patterns_fromserver - modifications for traffic from the server to the client


Each modification is  3 files:

descr_XX - text description what the modification does

pattern_XX - exact bytes which are matched (don't add a linefeed there if it's not in the traffic)

replace_XX - exact bytes which are put in place of the matched bytes

XX is a number 0-99


Note: this is matched byte for byte, with no regexps, no whitespace removal etc.


The youpot process will read the files on start and upon getting a SIGHUP



Please see the descr_XX files for a description of what each modification does
