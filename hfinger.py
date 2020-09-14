#!/usr/bin/env python3

import sys
import shutil
import hfinger.tshark_wrappers
import hfinger.hreader
import tempfile
import os
import argparse
import magic
import subprocess
import json

TSHARK_EXEC = ""
TSHARK_VER = ""


def check_environment():
    if sys.version_info < (3, 3):
        print("Must be run with at least Python 3.3")
        return False
    locate = shutil.which("tshark")
    if locate is None:
        print("No Tshark instance found. Is it installed?")
        return False
    global TSHARK_EXEC
    global TSHARK_VER
    TSHARK_EXEC = locate
    TSHARK_VER = hfinger.tshark_wrappers.check_tshark_version()
    if not hfinger.tshark_wrappers.check_tshark_supports_json(TSHARK_VER):
        print("At least Tshark 2.2.0 version required")
        return False
    return True


def check_if_pcap_file(file_path):
    f_type = magic.from_file(file_path, mime=True)
    if f_type == "application/vnd.tcpdump.pcap":
        return True
    else:
        return False


def write_results_to_file(filename, outpath, results_to_write):
    n1 = os.path.basename(filename)
    try:
        path_to_file = os.path.join(outpath, n1 + ".json")
        with open(path_to_file, "w") as f_out:
            json.dump(results_to_write, f_out)
    except PermissionError:
        print(
            "Insufficient access rights to write to the directory"
        )
    except FileNotFoundError:
        print("Output directory does not exist!")


def run_tshark(pcap_path, rep_mode):
    with tempfile.TemporaryDirectory() as tmpdirname:
        fname = os.path.join(tmpdirname, "json.out")
        with open(fname, "w") as json_out_file:
            subprocess.call(
                [
                    TSHARK_EXEC,
                    "-T",
                    "json",
                    "-x",
                    "-Yhttp.request and tcp and not icmp",
                    "-r",
                    pcap_path,
                ],
                stdout=json_out_file,
            )
        hfinger.tshark_wrappers.repair_json(TSHARK_VER, fname)
        return hfinger.hreader.reader_wrapper(fname, rep_mode)


def direct_run():
    my_parser = argparse.ArgumentParser(
        description="Hfinger - fingerprinting HTTP requests stored in pcap files",
        allow_abbrev=False,
    )
    my_group = my_parser.add_mutually_exclusive_group(required=True)
    my_group.add_argument(
        "-f", "--file", action="store", type=str, help="Read single pcap file"
    )
    my_group.add_argument(
        "-d",
        "--directory",
        metavar="DIR",
        action="store",
        type=str,
        help="Read pcap files from directory DIR",
    )
    my_parser.add_argument(
        "-o",
        "--output-path",
        metavar="output_path",
        type=str,
        action="store",
        help="Path to the output directory",
    )
    my_parser.add_argument(
        "-m",
        "--mode",
        type=int,
        default=0,
        choices=[0, 1, 2],
        help="Fingerprint report mode. 0 - optimal (default), 1 - informative, 2 - all features",
    )
    args = my_parser.parse_args()
    if args.file:
        if not os.path.isfile(args.file) or not os.access(args.file, os.R_OK):
            print("Cannot access the file: " + args.file)
            sys.exit(2)
        if not check_if_pcap_file(args.file):
            print("Provided file is not a valid pcap file")
            sys.exit(1)
        if not check_environment():
            sys.exit(1)
        results = run_tshark(args.file, args.mode)
        if args.output_path is not None:
            write_results_to_file(args.file, args.output_path, results)
        else:
            print(json.dumps(results))
    else:
        no_pcaps_found_flag = True
        for x in os.listdir(args.directory):
            cur_file = os.path.join(args.directory, x)
            if not os.path.isfile(cur_file) or not os.access(cur_file, os.R_OK):
                print(
                    "Some problem with accessing files in directory: " + args.directory
                )
                sys.exit(1)
            if check_if_pcap_file(cur_file):
                no_pcaps_found_flag = False
                if not check_environment():
                    sys.exit(1)
                results = run_tshark(cur_file, args.mode)
                if args.output_path is not None:
                    write_results_to_file(cur_file, args.output_path, results)
                else:
                    print(json.dumps(results))
        if no_pcaps_found_flag:
            print("No pcap files found in the directory")


if __name__ == "__main__":
    direct_run()
