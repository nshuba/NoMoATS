#!/usr/bin/python

"""
Converts provided PCAP file to JSON format using tshark

USAGE:
$ ./pcap_to_json.py PATH_TO_PCAP_FILE

Example:
$ ./pcap_to_json.py data.pcapng
"""

#  This file is part of NoMoATS <http://athinagroup.eng.uci.edu/projects/nomoads/>.
#  Copyright (C) 2019 Anastasia Shuba.
#
#  NoMoATS is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  NoMoATS is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with NoMoATS.  If not, see <http://www.gnu.org/licenses/>.

import sys, os

from subprocess import call
from subprocess import check_output


def convert_pcap(pcap_file):
    dir_path = os.path.dirname(os.path.realpath(pcap_file))
    json_file = dir_path + "/tshark.json"
    cmd = ["tshark",
           "-o", "tcp.analyze_sequence_numbers:FALSE",
           "-o", "tcp.desegment_tcp_streams:FALSE",
           "-o", "http.desegment_body:FALSE",
           "-r", pcap_file, "-T", "json"]
    data = check_output(cmd)

    with open(json_file, "w") as jf:
        jf.write(data)

    print "Saved " + json_file

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "ERROR: incorrect number of arguments. Correct usage:"
        print "\t$ ./pcap_to_json.py PATH_TO_PCAP_FILE"
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    if not os.path.isfile(pcap_file):
        print "ERROR: please provide a PCAP file as the second argument"
        sys.exit(1)
    convert_pcap(pcap_file)