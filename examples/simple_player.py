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

import argparse
from libraop import RaopClient, RAOP_ALAC, RAOP_PCM, MAX_SAMPLES_PER_CHUNK, RAOP_CLEAR, MS2TS, TS2MS, MS2NTP, SECNTP, \
                 get_ntp, NTP2MS

parser = argparse.ArgumentParser(description="Stream audio data to an airplay receiver.")
parser.add_argument("server_ip", type=str, help="IP address of the airplay server.")
parser.add_argument("filename", type=str, help="The filename to stream to the airplay device.")
parser.add_argument("-i", "--interactive", default=False, action="store_true",
                    help="interactive commands: 'p'=pause, 'r'=(re)start, 's'=stop, 'q'=exit, ' '=block")
parser.add_argument("-a", "--alac", default=True, action="store_true", help="ALAC encode the audio stream.")
parser.add_argument("-p", "--port", type=int, default=5000, help="The port number.")
parser.add_argument("-v", "--volume", type=int, default=50, help="The default volume to use.")

args = parser.parse_args()

# Create an initial connection
latency = MS2TS(1000, 44100)
client = RaopClient(args.server_ip, 0, 0, None, None, RAOP_ALAC if args.alac else RAOP_PCM, MAX_SAMPLES_PER_CHUNK,
                    latency, RAOP_CLEAR, False, None, None, None, 44100, 16, 2,
                    RaopClient.float_volume(args.volume))

# Parse the input file
infile = open(args.filename, "rb")

# Connect to the client
if not client.connect(args.port, True):
    client.destroy()
    print(f"Can not connect to AirPlay device {args.server_ip}.")
    exit(1)

print(f"Connected to {args.server_ip} on port {args.port}" \
      f", player latency is {TS2MS(client.latency, client.sample_rate)} ms.")

# Begin streaming
start = get_ntp()
last, frames = 0, 0
status = "playing"

while last == 0 or client.is_playing:
    now = get_ntp()

    if (now - last > MS2NTP(1000)):
        last = now
        if frames and frames > client.latency:
            print(f"At {SECNTP(now)}, ({NTP2MS(now - start)} ms after start)" \
                  f", played {TS2MS(frames - client.latency, client.sample_rate)} ms")

    if status == "playing" and client.accept_frames():
        if not (data := infile.read(MAX_SAMPLES_PER_CHUNK*4)):
            continue
        _, playtime = client.send_chunk(data);
        frames += len(data) // 4;

print("End streaming...")
client.disconnect()
client.destroy()
