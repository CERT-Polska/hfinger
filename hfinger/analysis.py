import sys
import shutil
import tempfile
import os
import argparse
import magic
import subprocess
import json
import logging

from hfinger import hreader, tshark_wrappers
from .hfinger_exceptions import (
    NotAPcap,
    BadReportmodeVariable,
    PythonTooOld,
    TsharkNotFound,
    TsharkTooOld,
)


def ensure_environment():
    if sys.version_info < (3, 3):
        raise PythonTooOld
    locate = shutil.which("tshark")
    if locate is None:
        raise TsharkNotFound
    tshark_exec = locate
    tshark_ver = tshark_wrappers.get_tshark_version()
    if not tshark_wrappers.check_tshark_supports_json(tshark_ver):
        raise TsharkTooOld
    return tshark_exec, tshark_ver


def is_pcap_file(file_path):
    f_type = magic.from_file(file_path, mime=True)
    if f_type != "application/vnd.tcpdump.pcap":
        raise NotAPcap


def write_results_to_file(filename, outpath, results_to_write):
    n1 = os.path.basename(filename)
    path_to_file = os.path.join(outpath, n1 + ".json")
    with open(path_to_file, "w") as f_out:
        json.dump(results_to_write, f_out)


def run_tshark(pcap_path, rep_mode, texec, tver):
    with tempfile.TemporaryDirectory() as tmpdirname:
        fname = os.path.join(tmpdirname, "json.out")
        with open(fname, "w") as json_out_file:
            subprocess.call(
                [
                    texec,
                    "-T",
                    "json",
                    "-x",
                    "-Yhttp.request and tcp and not icmp",
                    "-r",
                    pcap_path,
                ],
                stdout=json_out_file,
            )
        tshark_wrappers.repair_json(tver, fname)
        return hreader.reader_wrapper(fname, rep_mode)


def commandline_run():
    my_parser = argparse.ArgumentParser(
        description="Hfinger - fingerprinting malware HTTP requests stored in pcap files",
        allow_abbrev=False,
        prog="hfinger",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    my_group = my_parser.add_mutually_exclusive_group(required=True)
    my_group.add_argument(
        "-f", "--file", action="store", type=str, help="Read a single pcap file"
    )
    my_group.add_argument(
        "-d",
        "--directory",
        metavar="DIR",
        action="store",
        type=str,
        help="Read pcap files from the directory DIR",
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
        default=2,
        choices=[0, 1, 2, 3, 4],
        help="Fingerprint report mode. "
        "\n0 - similar number of collisions and fingerprints as mode 2, but using fewer features, "
        "\n1 - representation of all designed features, but a little more collisions than modes 0, 2, and 4, "
        "\n2 - optimal (the default mode), "
        "\n3 - the lowest number of generated fingerprints, but the highest number of collisions, "
        "\n4 - the highest fingerprint entropy, but slightly more fingerprints than modes 0-2",
    )
    my_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Report information about non-standard values in the request "
        "\n(e.g., non-ASCII characters, no CRLF tags, values not present in the configuration list). "
        "\nWithout --logfile (-l) will print to the standard error.",
    )
    my_parser.add_argument(
        "-l",
        "--logfile",
        action="store",
        type=str,
        help="Output logfile in the verbose mode. Implies -v or --verbose switch.",
    )
    args = my_parser.parse_args()
    tshark_exec = ""
    tshark_ver = ""
    try:
        tshark_exec, tshark_ver = ensure_environment()
    except (PythonTooOld, TsharkNotFound, TsharkTooOld) as err:
        print(err)
        sys.exit(1)
    logger = logging.getLogger("hfinger")
    if args.logfile:
        logger.setLevel(logging.INFO)
        logger.addHandler(logging.FileHandler(args.logfile, encoding="utf-8"))
    elif args.verbose:
        logger.setLevel(logging.INFO)
        logger.addHandler(logging.StreamHandler())
    if args.file:
        try:
            is_pcap_file(args.file)
        except (FileNotFoundError, IsADirectoryError, PermissionError) as err:
            print("Problem with file access. " + str(err))
            sys.exit(1)
        except NotAPcap:
            print("The provided file is not a valid pcap file.")
            sys.exit(1)
        else:
            results = run_tshark(args.file, args.mode, tshark_exec, tshark_ver)
            if args.output_path is not None:
                write_results_to_file(args.file, args.output_path, results)
            else:
                print(json.dumps(results))
    else:
        no_pcaps_found_flag = True
        try:
            filelist = os.listdir(args.directory)
        except NotADirectoryError as err:
            print("The entered path is not a directory. " + str(err))
            sys.exit(1)
        for x in os.listdir(args.directory):
            cur_file = os.path.join(args.directory, x)
            try:
                is_pcap_file(cur_file)
            except IsADirectoryError:
                continue
            except (FileNotFoundError, PermissionError) as err:
                print("Problem with file access. " + str(err))
                sys.exit(1)
            except NotAPcap:
                continue
            else:
                no_pcaps_found_flag = False
                logger.info("Analyzing file: " + str(cur_file))
                results = run_tshark(cur_file, args.mode, tshark_exec, tshark_ver)
                if args.output_path is not None:
                    write_results_to_file(cur_file, args.output_path, results)
                else:
                    print(json.dumps(results))
        if no_pcaps_found_flag:
            print("No valid pcap files found in the directory")


def hfinger_analyze(pcap, reportmode=2):
    """
    Returns the results of fingerprinting for single pcap file.
    Intended to be called from python scripts as the main function of the tool.
    Hfinger logs information about encountering non-standard values in the headers or some minor problems when decoding
    data. The logging is done using 'logging' module and logger name 'hfinger'.
    To receive logs you should configure the 'hfinger' logger (including setting log level to INFO),
    and then configure and add desired log handler. It should be done before calling the `hfinger_analyze` function,
    otherwise no information will be printed.


            Parameters:
                    pcap (str): Path to the pcap file.
                    reportmode (int): Reporting mode of Hfinger in range 0-4. The default value is '2'.

            Returns:
                    results (list): Python list of dicts with fingerprinting results.

            Raises:
                    HfingerReportmodeVariableException: The value of the reportmode is not an int or not in range 0-4

    """

    tshark_exec, tshark_ver = ensure_environment()
    is_pcap_file(pcap)
    if not isinstance(reportmode, int):
        raise BadReportmodeVariable("Wrong type, should be 'int'.")
    if reportmode not in range(0, 5):
        raise BadReportmodeVariable("Wrong value, should be in range 0-4.")

    results = run_tshark(pcap, reportmode, tshark_exec, tshark_ver)
    return results
