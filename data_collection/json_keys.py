#!/usr/bin/python

# This file is part of NoMoAds <http://athinagroup.eng.uci.edu/projects/nomoads/>.
# Copyright (C) 2018 Anastasia Shuba, University of California, Irvine.
#
# NoMoAds is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# NoMoAds is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NoMoAds.  If not, see <http://www.gnu.org/licenses/>.

package_name = "package_name"
version = "package_version"
type = "type"
ats_pkg = "ats_pkg"
id = "pkt_id"
pii_label = "pii_types"
predicted = "predicted"
list_label = "list_labels"

source = "_source"
layers = "layers"

dst_ip = "dst_ip"
ip = "ip"
tcp = "tcp"

http = "http"
method = "method"
uri = "uri"
headers = "headers"
referer = "referer"
domain = "domain"
host = "host"
dst_port = "dst_port"

http_req = http + ".request."
http_req_method = http_req + method
http_req_uri = http_req + uri
http_req_line = http_req + "line"

pkt_comment = "pkt_comment"
ats_label = "ats"
trace = "trace"

frame = "frame"
frame_num = frame + ".number"
frame_comment = frame + ".comment"
frame_ts = frame + ".time_epoch"

LOCATION_PII = [("33.67", "-117.77"), ("33.6", "-117.8")]

PII_VALUES = {
    "Device ID": "60848bbcf3f8f175",
    "IMEI": "355458060820348",
    "Email": "janetestdevel@gmail.com",
    "Password": "N0mad0nAndromeda",
    "Serial Number": "ZX1G322XQD",
    "Advertising ID": "7263697a-cb1e-4c6f-a641-c2bfe1683295",
    "MAC Address": "44:80:EB:EB:25:3E"
}
