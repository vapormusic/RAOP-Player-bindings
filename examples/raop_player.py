#!/usr/bin/env python3

# *****************************************************************************
# simple_player.py: Simple player example
#
# Copyright (C) 2021 David Klopp
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
# *****************************************************************************

# TODO: Test DAPP Information sending
# TODO: Add authenticate parameter (for old erport express ?)

import sys
import argparse
from threading import Thread
from logging import getLogger, DEBUG, WARN, INFO, NOTSET, ERROR, StreamHandler, Formatter
from datetime import datetime
from libraop import RaopClient, RAOP_ALAC, RAOP_PCM, MAX_SAMPLES_PER_CHUNK, RAOP_CLEAR, MS2TS, TS2MS, MS2NTP, SECNTP, \
                 get_ntp, NTP2MS, TS2NTP, RAOP_RSA, set_log_level


PLAYING = "playing"
STOPPED = "stopped"
PAUSED = "paused"


def setup_args():
    parser = argparse.ArgumentParser(description="Stream audio data to an airplay receiver")
    parser.add_argument("server_ip", type=str, help="IP address of the airplay server")
    parser.add_argument("filename", type=str, help="the filename to stream to the airplay device")
    parser.add_argument("-ntp", "--ntp-file", type=str, help="write the current NTP to <NTP_FILE> and exit")
    parser.add_argument("-p", "--port", type=int, default=5000, help="the port number")
    parser.add_argument("-v", "--volume", type=int, default=50, help="the default volume to use")
    parser.add_argument("-l", "--latency", type=int, default=None, help="the default latency (frames) to use")
    parser.add_argument("-a", "--alac", default=False, action="store_true", help="ALAC encode the audio stream")
    parser.add_argument("-w", "--wait", type=int, default=0, help="start after <WAIT> milliseconds")
    parser.add_argument("-n", "--start", type=int, default=0, help="start at NTP <START> + <WAIT>")
    parser.add_argument("-nf", "--start_file", type=str, help="start at NTP <FILE_START> + <WAIT>")
    parser.add_argument("-e", "--encrypt", default=False, action="store_true", help="encrypt the audio stream")
    parser.add_argument("-pwd", "--password", type=str, help="optional airplay password of the receiver")
    parser.add_argument("-pin", "--pin", default=False, action="store_true", help="request a new pin")
    parser.add_argument("-s", "--secret", type=str, help="valid secret for AppleTV")
    parser.add_argument("-d", "--debug", type=int, default=-2, help="debug level (0 = silent)")
    parser.add_argument("-i", "--interactive", default=False, action="store_true",
                        help="interactive commands: 'p'=pause, 'r'=(re)start, 's'=stop, 'q'=exit'")

    return parser.parse_args()


def setup_python_logger(level):
    """
    Setup the python logger instance.
    Note: You can use negative values to deactivate the logging inside the C code and only use the python logger.
    @param level the log level to use
    """
    class MsFormatter(Formatter):
        converter = datetime.fromtimestamp
        def formatTime(self, record, datefmt=None):
            ct = self.converter(record.created)
            if datefmt:
                s = ct.strftime(datefmt)
            else:
                t = ct.strftime("%Y-%m-%d %H:%M:%S")
                s = "%s,%03d" % (t, record.msecs)
            return s

    levels = [ERROR, WARN, INFO, DEBUG]
    level = levels[min(args.debug, len(levels)-1)]
    logger = getLogger()
    logger.setLevel(level)
    handler = StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(MsFormatter("[%(asctime)s] %(message)s", "%H:%M:%S.%f"))
    logger.addHandler(handler)
    return logger


def setup_keylistener(callback):
    """
    Listen for keyboard events an call a callback function if a key is pressed.
    @param callback: a callback function.
    """
    if sys.platform[:3] == 'win':
        import msvcrt
        def getkey():
            key = msvcrt.getch()
            if ord(key) == 224: #catch second event with arrow keys
                key = msvcrt.getch()
            return key
    else:
        import termios, os
        TERMIOS = termios

        def getkey():
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            new = termios.tcgetattr(fd)
            new[3] = new[3] & ~TERMIOS.ICANON & ~TERMIOS.ECHO
            new[6][TERMIOS.VMIN] = 1
            new[6][TERMIOS.VTIME] = 0
            termios.tcsetattr(fd, TERMIOS.TCSANOW, new)
            c = None
            try:
                c = os.read(fd, 1)
            finally:
                termios.tcsetattr(fd, TERMIOS.TCSAFLUSH, old)
            return c

    def listen():
        while True:
            if callback:
                callback(getkey().decode())
    t = Thread(target=listen)
    t.daemon = True
    t.start()


def handle_key_event(key):
    """
    Process different key events in ineractive mode.
    @param key: the currently pressed key
    """
    global status
    if key == "s" or key == "q":
        # stop
        client.stop()
        client.flush()
        status = STOPPED
        logger.info(f"Stopped at : {SECNTP(get_ntp())}")
        # Kill the key listener thread. The main thread will terminate in every case.
        exit(0)
    elif key == "p" and status == PLAYING:
        # pause
        client.pause()
        client.flush()
        status = PAUSED;
        logger.info(f"Pause at : {SECNTP(get_ntp())}")
    elif key == "r":
        now = get_ntp();
        start_at = now + MS2NTP(200) - TS2NTP(client.latency, client.sample_rate)
        status = PLAYING;
        client.start_at(start_at);
        logger.info(f"Resumed at : {SECNTP(get_ntp())}")


if __name__ == "__main__":
    # Parse the command line arguments
    args = setup_args()

    # Set the log level
    if args.debug >= 0:
        set_log_level(args.debug)

    # Set the python log level
    logger = setup_python_logger(args.debug)

    # Write the ntp and exit
    if args.ntp_file:
        with open(args.ntp_file, "w") as f:
            f.write(str(get_ntp()))
        exit()

    latency = args.latency if (args.latency is not None and args.latency >=0) else MS2TS(1000, 44100)

    # Create an initial connection
    client = RaopClient(args.server_ip, 0, 0, None, None, RAOP_ALAC if args.alac else RAOP_PCM, MAX_SAMPLES_PER_CHUNK,
                        latency, RAOP_RSA if args.encrypt else RAOP_CLEAR, False, args.password, args.secret, None,
                        None, 44100, 16, 2, RaopClient.float_volume(args.volume))

    # Read the NTP start
    start = args.start
    if args.start_file:
        with open(args.start_file, "r") as f:
            start = int(f.read())

    # Parse the input file
    infile = open(args.filename, "rb")

    # Connect to the client
    if not client.connect(args.port):
        client.destroy()
        logger.error(f"Can not connect to AirPlay device {args.server_ip}.")
        exit(1)

    # Ask for an Apple TV pin if required
    pin = None
    if args.pin:
        client.request_pin()
        pin = str(input("Enter pin: "))

    # Send the initial pairing information
    sucess, secret = client.pair(pin, True)
    if not sucess:
        client.destroy()
        logger.error(f"Pairing with AirPlay device {args.server_ip} failed.")
        exit(1)
    elif secret:
        logger.info(f"The Apple TV secret is: {secret}");

    logger.info(f"Connected to {args.server_ip} on port {args.port}" \
                f", player latency is {TS2MS(client.latency, client.sample_rate)} ms.")

    latency = client.latency

    # Delay the start according to the input parameters
    if start or args.wait:
        now = get_ntp()
        ntp_latency = TS2NTP(latency, client.sample_rate)
        start_at = (start or now) + MS2NTP(args.wait) - ntp_latency
        in_time = NTP2MS(start_at - now + ntp_latency) if (start_at + ntp_latency) > now else 0
        logger.info(f"Now {SECNTP(now)}, audio starts at NTP {SECNTP(start_at)} (in {in_time} ms)")
        client.start_at(start_at)

    # Begin streaming
    start = get_ntp()
    last, frames, last_keepalive = 0, 0, start
    status = PLAYING

    # Setup interactve mode if required
    if args.interactive:
        setup_keylistener(handle_key_event)

    iterate = True

    while iterate:
        now = get_ntp()

        # Update the last ntp
        if (now - last > MS2NTP(1000)):
            last = now
            if frames and frames > latency:
                logger.debug(f"At {SECNTP(now)}, ({NTP2MS(now - start)} ms after start)" \
                             f", played {TS2MS(frames - latency, client.sample_rate)} ms")

        # Send a keep alive message every 30 seconds for homepods
        if (NTP2MS(now - last_keepalive) >= 30000):
            logger.debug(f"Keep-alive at : {SECNTP(now)}, ({NTP2MS(now - start)} ms after start)" \
                         f", played {TS2MS(frames - latency, client.sample_rate)} ms")
            last_keepalive = now
            client.keepalive()

        # Stream the data
        if status == PLAYING and client.accept_frames() and (data := infile.read(MAX_SAMPLES_PER_CHUNK*4)):
            _, playtime = client.send_chunk(data);
            frames += len(data) // 4;

        iterate = client.is_playing

    # End streaming
    logger.info(f"End at : {SECNTP(get_ntp())}.")
    infile.close()
    client.disconnect()
    client.destroy()
