import urllib.parse
import os
from math import log10
from pathlib import Path
from hfinger.configs import METHODS


extensions = set()
with (Path(__file__).parent / "configs/extensions.txt").open() as ext_in:
    for lin in ext_in:
        extensions.add(lin.strip("\n"))


def avg_length_dir(uri_t, numb):
    avg = 0
    for i in uri_t[1:]:
        avg = avg + len(i)
    if float(numb) > 0.0:
        return float(avg) / float(numb)
    else:
        return 0.0


def give_extension(uri_path):
    tmp_ext = os.path.splitext(uri_path)[1].strip(".")
    # naive approach to filter out strings with dot, which are not extensions
    # firstly check if tested string is between 1 and 4 characters
    if 1 <= len(tmp_ext) <= 4:
        if tmp_ext.isalnum() and tmp_ext in extensions:
            return tmp_ext
    return ""


def variables_features(qry):
    query_parsed = urllib.parse.parse_qs(qry)
    var_len = len(qry)
    var_number = len(query_parsed)
    val_len = 0
    for j in query_parsed.values():
        val_len = val_len + len(j[0])
    if var_number > 0:
        avg_len = log10(float(val_len) / float(var_number))
    else:
        avg_len = 0.0
    return "|".join(
        map(
            str,
            ("%.1f" % round(log10(var_len), 1), var_number, "%.1f" % round(avg_len, 1)),
        )
    )


def give_fing(uri):
    uri_parsed = urllib.parse.urlparse(uri)
    path_tokenized = uri_parsed.path.split("/")
    uri_len = len(uri)
    uri_len_log = log10(uri_len)
    var_feat = "||"
    if uri_len > 1:
        dir_number = (
            len(uri_parsed.path.split("/")) - 1
        )  # uri begins with "/", so split gives empty string before "/" as a value
        avg_dir_len = avg_length_dir(path_tokenized, dir_number)
        avg_dir_len_log = 0.0
        if avg_dir_len != 0.0:
            avg_dir_len_log = log10(avg_dir_len)
        if uri_parsed.query != "":
            var_feat = variables_features(uri_parsed.query)
        ext = give_extension(uri_parsed.path)
        return "|".join(
            map(
                str,
                (
                    "%.1f" % round(uri_len_log, 1),
                    dir_number,
                    "%.1f" % round(avg_dir_len_log, 1),
                    ext,
                    var_feat,
                ),
            )
        )
    else:
        return "|".join(
            map(str, ("%.1f" % round(uri_len_log, 1), "", "", "", "", "", ""))
        )


def uri_fingerprint(pkt):
    t = ""
    # Checking if request has protocol version declaration
    if " HTTP/" not in pkt[0]:
        t = pkt[0]
    else:
        t = pkt[0].split(" HTTP/")[0].lstrip(" ")
    # check if method is present in the first seven chars (methods have up to 7 chars)
    t1 = t[:7].upper().strip(" ")
    # find spaces in methods shorter than 7 chars - we will have part of URL in t1
    # we should find whitespace between method and URL and cut the string on it
    it = t1.find(" ")
    meth = t1[:it]
    # workaround for methods with 7 chars
    if it < 0:
        # method has 7 chars, so no need to cut t1
        meth = t1
    if "/" not in t:
        # Simple URI presence check
        return "|||||||"
    if meth in METHODS:
        # searching for URL, which should be separated from method with whitespace
        it1 = t.find(" ")
        # cutting out URL
        uri = t[it1 + 1 :]
        return give_fing(uri)
    else:
        return "|||||||"
