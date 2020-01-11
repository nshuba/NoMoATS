#!/usr/bin/python

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

import argparse
import os
import subprocess
import json

from libradar_parser import LibRadarParserFactory
import extract_from_tshark

def readable_dir(prospective_dir):
    if not os.path.isdir(prospective_dir):
        raise Exception("readable_dir:{0} is not a valid path".format(prospective_dir))
    if os.access(prospective_dir, os.R_OK):
        return prospective_dir
    else:
        raise Exception("readable_dir:{0} is not a readable dir".format(prospective_dir))
        
def check_ret(ret):
    if ret != 0:
        print "ERROR: non-zero return value: " + str(ret)
        return False
    return True
    
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Runs the full NoMoATS pipeline')
    ap.add_argument('apps_dir', type=readable_dir, help='directory containing apks')
    ap.add_argument('libradar', help='LibRadar Python script location')
    ap.add_argument('--libradar_csv', help='LibRadar CSV file containing tag rules, indicates use of LibRadar++')
    ap.add_argument('-e', action='store_true', help='Indicates use of an emulator, false by default')

    args = ap.parse_args()
    
    parent_dir = os.path.dirname(os.path.abspath(args.apps_dir))
    libradar_dir = os.path.join(parent_dir, 'libradar_output')
    if not os.path.isdir(libradar_dir):
        os.makedirs(libradar_dir)
                
    apk_suffix_len = 4
    for apk_file in os.listdir(args.apps_dir):
        apk_path = os.path.join(args.apps_dir, apk_file)
        pkg_name = apk_file[:len(apk_file) - apk_suffix_len]
        print pkg_name
        
        anal_file_name = pkg_name + ".txt"
        anal_file_path = os.path.join(libradar_dir, anal_file_name)
        
        ret = 0
        libradar_parser = LibRadarParserFactory.create_parser(args.libradar_csv)
        if not os.path.isfile(anal_file_path):
            ret = libradar_parser.analyze(args.libradar, apk_path, anal_file_path)
            print "\tLibRadar Done: " + str(ret)
        else:
            print "\tSkipping LibRadar - already done"

        if not check_ret(ret):
            break
            
        # Droidbot will make the dir if necessary
        droidbot_dir = os.path.join(parent_dir, 'nomoats_output')
        droidbot_app_dir = os.path.join(droidbot_dir, pkg_name)
        pcap_path = os.path.join(droidbot_app_dir, pkg_name + ".pcapng")
        if not os.path.isfile(pcap_path):
            droidbot_cmd = ["droidbot", "-a", apk_path, "-o", droidbot_app_dir, #"-keep_app",
                                    "-policy", "bfs_naive",
                                    "-interval", "2",
                                    "-keep_env", "-grant_perm", "-ignore_ad", "-timeout", "300"]
            if args.e:
                droidbot_cmd.append("-is_emulator")
            ret = subprocess.call(droidbot_cmd)
            print "\tDroidbot Done: " + str(ret)
        else:
            print "\tSkipping Droidbot - already exists"
            
        if not check_ret(ret):
            break
        
        
        tshark_path = os.path.join(droidbot_app_dir, "tshark.json")
        if not os.path.isfile(tshark_path):
            ret = subprocess.call(["python", "pcap_to_json.py", pcap_path])
            print "\tPCAP to Tshark Done: " + str(ret)
        else:
            print "\tSkipping tshark - already exists"
            
        if not check_ret(ret):
            break
        
        extracted_dir = os.path.join(parent_dir, 'extracted_data')
        if not os.path.isdir(extracted_dir):
            os.makedirs(extracted_dir)
        
        webview_path = os.path.join(droidbot_app_dir, "webview_loads.json")
        extracted_file = os.path.join(extracted_dir, pkg_name + ".json")
        if not os.path.isfile(extracted_file):
            if not extract_from_tshark.extract(tshark_path, webview_path, anal_file_path, libradar_parser,
                                               extracted_file):
                break
            print "\tExtraction Done: " + str(ret)
            #break
        else:
             print "\tSkipping extraction - already exists"
