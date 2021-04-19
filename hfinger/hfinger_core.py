from fnvhash import fnv1a_32
from collections import Counter, OrderedDict
import json
import math
from pathlib import Path
from hfinger.configs import AEVAL, CONNVAL, CONTENC, CACHECONT, TE, ACCPTCHAR, METHODS
import sys
import logging


logger = logging.getLogger("hfinger")


def read_config(filename):
    with (Path(__file__).parent / "configs" / filename).open() as fin:
        return json.load(fin, object_pairs_hook=OrderedDict)


HDRL = read_config("headerslow.json")
CONTENTTYPE = read_config("content-type.json")
ACCPT = read_config("accept.json")


def entropy(bstr):
    p, lns = Counter(bstr), float(len(bstr))
    return -sum(count / lns * math.log(count / lns, 2) for count in p.values())


def get_entropy(bstr):
    return str(round(entropy(bstr), 1))


def get_length(bstr):
    return str(round(math.log10(len(bstr)), 1))


def get_hdr_case(hdr):
    if "-" in hdr:
        t = hdr.split("-")
        for i in t:
            if i[0].islower():
                # Is any first letter in compound header name written with lower case?
                return False
        return True
    else:
        return hdr[0].isupper()


# Checking method and proto version
def get_method_version(request_split):
    r_ver = ""
    r_meth = ""
    # Checking if HTTP version is provided, if not assuming it is HTTP 0.9 per www.w3.org/Protocols/HTTP/Request.html
    if " HTTP/" not in request_split[0]:
        r_ver = "9"
        # take first seven characters of the first line of request to look for method (methods have up to 7 chars)
        t2 = request_split[0][:7].upper().strip(" ")
        # if method shorter than 7 chars we will have part of URL in t2
        # we should find space between method and URL and cut the string on it
        it = t2.find(" ")
        meth = t2[:it]
        if it < 0:
            # method has 7 chars, so no need to cut t2
            meth = t2
        if meth in METHODS:
            r_meth = meth[:2]
    else:
        t = request_split[0].split(" HTTP/")
        t1 = t[0].lstrip(" ")
        # check if method is present by taking first 7 characters and searching there for method
        # (methods have up to 7 chars)
        t2 = t1[:7].upper().strip(" ")
        # if method shorter than 7 chars we will have part of URL in t2
        # we should find space between method and URL and cut the string on it
        it = t2.find(" ")
        meth = t2[:it]
        if it < 0:
            # method has 7 chars, so no need to cut t2
            meth = t2
        if meth in METHODS:
            r_meth = meth[:2]
            if "1.1" in t[1]:
                r_ver = "1"
            else:
                r_ver = "0"
    return "|".join((r_meth, r_ver))


# Checking header order - assuming that header field contains ":"
def get_hdr_order(request_split):
    ret = []
    for reqline in request_split[1:]:
        hdr = reqline.split(":")[0]
        hdr_lower = hdr.lower()
        hdr_coded = format(fnv1a_32(hdr.encode()), "x")
        if hdr_lower in HDRL:
            if get_hdr_case(hdr):
                hdr_coded = HDRL[hdr_lower]
            else:
                hdr_coded = "!" + HDRL[hdr_lower]
        ret.append(hdr_coded)
    return ",".join(ret)


def get_ua_value(hdr):
    val = hdr.split(":")[1]
    if val[0] == " ":
        val = val[1:]
    name = HDRL["user-agent"]
    ret = name + ":" + format(fnv1a_32(val.encode()), "x")
    return ret


def get_hdr_value(hdr, hdrname, hdr_value_table):
    val = hdr.split(":")[1]
    if val[0] == " ":
        val = val[1:]
    hdr_coded = HDRL[hdrname] + ":"
    ret = []
    if "," in val:
        # simple splitting of compound values
        if ";q=" in val:
            # we do not tokenize compound values with quality parameters at this moment
            return hdr_coded + format(fnv1a_32(val.encode()), "x")
        t = []
        if ", " in val:
            t = val.split(", ")
        else:
            t = val.split(",")
        for j in t:
            if j == "":
                return hdr_coded + format(fnv1a_32(val.encode()), "x")
            if j not in hdr_value_table:
                logger.info("Unknown header value - " + hdr)
                return hdr_coded + format(fnv1a_32(val.encode()), "x")
            ret.append(hdr_value_table[j])
    else:
        k = ""
        if val in hdr_value_table:
            k = hdr_value_table[val]
        else:
            logger.info("Unknown header value - " + hdr)
            k = format(fnv1a_32(val.encode()), "x")
        ret.append(k)
    return hdr_coded + ",".join(ret)


def get_content_type(hdr):
    val = hdr.split(":")[1]
    if val[0] == " ":
        val = val[1:]
    hdr_coded = HDRL["content-type"] + ":"
    ret = []
    if "," in val:
        vals = []
        if ", " in val:
            vals = val.split(", ")
        else:
            vals = val.split(",")
        for itv in vals:
            if ";" in itv:
                if "boundary=" in itv:
                    bnd_ind = itv.index("boundary=")
                    bnd_offset = len("boundary=")
                    val_bnd = val[: bnd_ind + bnd_offset]
                    return hdr_coded + format(fnv1a_32(val_bnd.encode()), "x")
                else:
                    ret.append(format(fnv1a_32(itv.encode()), "x"))
            else:
                k = format(fnv1a_32(itv.encode()), "x")
                if itv not in CONTENTTYPE:
                    logger.info("Unknown Content-Type value - " + hdr)
                else:
                    k = CONTENTTYPE[itv]
                ret.append(k)
    else:
        if ";" in val:
            if "boundary=" not in val:
                return hdr_coded + format(fnv1a_32(val.encode()), "x")
            bnd_ind = val.index("boundary=")
            bnd_offset = len("boundary=")
            val_bnd = val[: bnd_ind + bnd_offset]
            return hdr_coded + format(fnv1a_32(val_bnd.encode()), "x")
        else:
            k = format(fnv1a_32(val.encode()), "x")
            if val not in CONTENTTYPE:
                logger.info("Unknown Content-Type value - " + hdr)
            else:
                k = CONTENTTYPE[val]
            ret.append(k)
    return hdr_coded + ",".join(ret)


def get_accept_language_value(hdr):
    val = hdr.split(":")[1]
    name = HDRL["accept-language"]
    ret = name + ":" + format(fnv1a_32(val.encode()), "x")
    return ret


def get_pop_hdr_val(request_split):
    r = []
    for reqline in request_split[1:]:
        if ":" in reqline:
            hdr_lower = reqline.split(":")[0].lower()
            if hdr_lower == "connection":
                r.append(get_hdr_value(reqline, "connection", CONNVAL))
            elif hdr_lower == "accept-encoding":
                r.append(get_hdr_value(reqline, "accept-encoding", AEVAL))
            elif hdr_lower == "content-encoding":
                r.append(get_hdr_value(reqline, "content-encoding", CONTENC))
            elif hdr_lower == "cache-control":
                r.append(get_hdr_value(reqline, "cache-control", CACHECONT))
            elif hdr_lower == "te":
                r.append(get_hdr_value(reqline, "te", TE))
            elif hdr_lower == "accept-charset":
                r.append(get_hdr_value(reqline, "accept-charset", ACCPTCHAR))
            elif hdr_lower == "content-type":
                r.append(get_content_type(reqline))
            elif hdr_lower == "accept":
                r.append(get_hdr_value(reqline, "accept", ACCPT))
            elif hdr_lower == "accept-language":
                r.append(get_accept_language_value(reqline))
            elif hdr_lower == "user-agent":
                r.append(get_ua_value(reqline))
        else:
            logger.info("No colon in line: " + reqline)
    ret = "/".join(r)
    return ret
