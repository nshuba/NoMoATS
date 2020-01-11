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

import json, csv

class LibRadarParserFactory:
    """
    Helper class for creating parsers for LibRadar and LibRadar++ data
    """

    @classmethod
    def create_parser(cls, literadar_csv_file=None):
        """
        Creates a correct parser instance based on the provided parameters
        :param literadar_csv_file: list of advertising and tracking package names (required if using LibRadar++)
        :return: a parser instance
        """
        if literadar_csv_file:
            print "INFO: Tag rules were passed, assuming LibRadar++ data format"
            return LibRadarParserPlusPlus(literadar_csv_file)
        else:
            print "INFO: Tag rules were not passed, assuming LibRadar data format"
            return LibRadarParser()

class LibRadarParser:
    """
    Helper class for parsing LibRadar output
    """
    
    ATS_TYPES = ["Advertisement", "Mobile Analytics"]

    def _analyze(self, python_cmd, libradar_path, apk_path, output_file):
        with open(output_file, "w") as anal_file:
            proc = subprocess.Popen([python_cmd, libradar_path, apk_path],
                                    stdout=anal_file, stderr=subprocess.PIPE)
            return proc.wait()

    def analyze(self, libradar_path, apk_path, output_file):
        """
        Analyzes the apk in the provided path and saves the result in the provided output file
        :param libradar_path: full path to the main LibRadar script
        :param apk_path: full path to the APK to analyze
        :param output_file: full path to where to save the analysis results
        :return: result of Popen.wait(), which indicates success or failure of running LibRadar
        """
        return self._analyze('python', libradar_path, apk_path, output_file)

    def parse(self, libradar_file):
        """
        Parse LibRadar data
        """

        key_type = 'Type'
        key_pkg = 'Package'
        with open(libradar_file) as jf:
            data = json.load(jf)

        ats_libs = []
        for lib in data:
            if key_type not in lib:
                continue

            lib_type = lib[key_type]
            if lib_type in LibRadarParser.ATS_TYPES:
                # change Lcom/crashlytics/android to com.crashlytics.android
                pkg = lib[key_pkg][1:].replace("/", ".")
                print pkg
                ats_libs.append(pkg)

            # Special case for Google:
            elif lib[key_pkg] == "Lcom/google/android/gms":
                # From https://developers.google.com/android/reference/packages
                ats_libs.append("com.google.android.gms.ads")
                ats_libs.append("com.google.android.gms.internal.ads")
                ats_libs.append("com.google.android.gms.analytics")

        print ats_libs
        return ats_libs

class LibRadarParserPlusPlus(LibRadarParser):
    """
    Helper class for parsing LibRadar++ output
    """

    def __init__(self, literadar_csv):
        self.global_ats_pkgs = self.parse_literadar_csv(literadar_csv)

    def analyze(self, libradar_path, apk_path, output_file):
        """
        parent:
        """
        return self._analyze('python3.7', libradar_path, apk_path, output_file)

    def parse_literadar_csv(self, csv_file):
        """
        Parses tag rules (currently provided by LiteRadar)
        """

        all_ats_pkgs = Set()
        with open(csv_file, 'rb') as f:
            reader = csv.reader(f, delimiter=',')

            # Get headers
            header_row = reader.next()
            for row in reader:
                pkg = row[header_row.index("Package Name")]
                type = row[header_row.index("Type")]
                if type in ats_types:
                    all_ats_pkgs.add(pkg)

        # print all_ats_pkgs
        print "Total packages: " + str(len(all_ats_pkgs))
        return all_ats_pkgs

    def parse(self, libradar_file):
        with open(libradar_file) as jf:
            ats_libs = Set()

            pkg_name_in_apk_idx = 0
            pkg_name_orig_idx = 1

            for line in jf:
                split_line = line.split()
                pkg_name_in_apk = split_line[pkg_name_in_apk_idx]
                pkg_name_orig = split_line[pkg_name_orig_idx]

                if pkg_name_orig in self.global_ats_pkgs:
                    # change Lcom/crashlytics/android to com.crashlytics.android
                    pkg = pkg_name_in_apk[1:].replace("/", ".")
                    print "\tFound ATS pkg: " + pkg
                    ats_libs.add(pkg)
                # Special case for Google:
                elif pkg_name_orig == "Lcom/google/android/gms":
                    # From https://developers.google.com/android/reference/packages
                    ats_libs.add("com.google.android.gms.ads")
                    ats_libs.add("com.google.android.gms.internal.ads")
                    ats_libs.add("com.google.android.gms.analytics")

        print ats_libs
        return ats_libs
