import subprocess
from distutils.version import LooseVersion


def get_tshark_version():
    version_raw = subprocess.check_output(["tshark", "-v"]).decode("ascii")
    for lin in version_raw.splitlines():
        if "TShark (Wireshark)" in lin:
            tshark_ver_full = lin.split("(")[1].split(")")[1].strip()
            return tshark_ver_full
        else:
            return "0.0.0"


def check_tshark_supports_json(tshark_ver):
    if LooseVersion(tshark_ver) >= LooseVersion("2.2.0"):
        return True
    else:
        return False


# Tshark before version 2.2.6 does not put "]" at the end of the json
def repair_json(tshark_ver, json_path):
    if LooseVersion(tshark_ver) < LooseVersion("2.2.6"):
        with open(json_path, "a") as repaired_json:
            repaired_json.write("\n ] \n")
