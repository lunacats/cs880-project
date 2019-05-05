# nvd_json.py
#
# Usage: nvd_json.py <input file>
# output goes to nvd.csv

import argparse
import csv
import json
import os
import sys


def main():
    '''main function'''
    parser = argparse.ArgumentParser(description='ELF binary stack protection parser')
    parser.add_argument('file_path', nargs=1)
    args = parser.parse_args()

    file_path = args.file_path[0]

    csv_fd = open("nvd.csv", 'w', newline='')
    nvd_csv = csv.writer(csv_fd, dialect='excel')
    nvd_csv.writerow(['cve_id', 'cve_type', 'cvssv3'])

    if not os.path.isfile(file_path):
        print("invalid file path")
        sys.exit(1)

    with open(file_path, 'r') as json_fd:
        json_data = json.load(json_fd)

    # get CVE data from the json data structure
    cves = json_data['CVE_Items']
    print("cve = %s" % (cves[0].keys()))
    for i, cve in enumerate(cves):
        print("processing record %s" % i)
        cve_id = cve['cve']['CVE_data_meta']['ID']
        cve_types = []
        for prob_data in cve['cve']['problemtype']['problemtype_data']:
            for desc in prob_data['description']:
                cve_types.append(desc['value'])
        if 'baseMetricV3' in cve['impact'].keys():
            cvssv3 = cve['impact']['baseMetricV3']['cvssV3']['baseScore']
        else:
            cvssv3 = -1.

        cve_types_str = ', '.join(cve_types)
        row = [cve_id, cve_types_str, cvssv3]
        nvd_csv.writerow(row)


if __name__ == "__main__":
    main()
