# RAOP-Player

RAOP player and library (AirPlay)

This is a RAOP (airplay) player and python-library for the v2 protocol (with synchro). It should work for Windows, OSX, Linux x86 and ARM. It is based on the fantastic RAOP-Player C-Library by [philippe44](https://github.com/philippe44).
The sample player can play raw pcm files. Use ffmpeg to transform your files to pcm data e.g.

```shell
ffmpeg -y -i input.mp3  -acodec pcm_s16le -f s16le -ac 2 -ar 44100 output.pcm
```

The player is an example application of how to use these python bindings. An additional flag for password protected airplay receivers (`-pwd`) was added. Note that different devices might require different flags. For Apple TV 4 and Homepods for example you should not use the `-e` flag. If your Homepod is the default speaker for your Apple TV, stream to the Homepod, not the Apple TV. For `shairport-sync` the combination `-e -a` with an optional password should work.

```sh
usage: simple_player.py [-h] [-ntp NTP_FILE] [-p PORT] [-v VOLUME] [-l LATENCY] [-a] [-w WAIT] [-n START] [-nf START_FILE] [-e] [-pwd PASSWORD] [-s SECRET] [-d DEBUG]
                        [-i]
                        server_ip filename

Stream audio data to an airplay receiver

positional arguments:
  server_ip             IP address of the airplay server
  filename              the filename to stream to the airplay device

optional arguments:
  -h, --help                                  show this help message and exit
  -ntp NTP_FILE, --ntp-file NTP_FILE          write the current NTP to <NTP_FILE> and exit
  -p PORT, --port PORT                        the port number
  -v VOLUME, --volume VOLUME                  the default volume to use
  -l LATENCY, --latency LATENCY               the default latency (frames) to use
  -a, --alac                                  ALAC encode the audio stream
  -w WAIT, --wait WAIT                        start after <WAIT> milliseconds
  -n START, --start START                     start at NTP <START> + <WAIT>
  -nf START_FILE, --start_file START_FILE     start at NTP <FILE_START> + <WAIT>
  -e, --encrypt                               encrypt the audio stream
  -pwd PASSWORD, --password PASSWORD          optional airplay password of the receiver
  -s SECRET, --secret SECRET                  valid secret for AppleTV
  -d DEBUG, --debug DEBUG                     debug level (0 = silent)
  -i, --interactive                           interactive commands: 'p'=pause, 'r'=(re)start, 's'=stop, 'q'=exit'
```

It's possible to send synchronous audio to multiple players by using the NTP options (optionally combined with the wait option). Use the `-ntp` option to get NTP to be written to a file and reuse that file when calling the instances of `simple_player.py`.

## Installing

```sh
pip install git+https://github.com/Schlaubischlump/RAOP-Player-bindings
```
