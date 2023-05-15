from fnvhash import fnv1a_32
from collections import Counter, OrderedDict
import json
import math
from pathlib import Path
from hfinger.configs import AEVAL, CONNVAL, CONTENC, CACHECONT, TE, ACCPTCHAR, METHODS
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
        compound_hdr = hdr.split("-")
        for i in compound_hdr:
            if i[0].islower():
                # Is any first letter in compound header name written with lower case?
                return False
        return True
    else:
        return hdr[0].isupper()


# Checking method and proto version
def get_method_version(request_split):
    req_version = ""
    req_method = ""
    method_line = request_split[0]
    # Checking if HTTP version is provided,
    # if not assuming it is HTTP 0.9 per www.w3.org/Protocols/HTTP/Request.html
    if " HTTP/" not in request_split[0]:
        req_version = "9"
        method_raw = method_line.strip(" ").split()[0]
        # We analyze method's verb only if it is shorter or equal to 7 chars
        # as all registered methods are at most this long.
        method_verb = method_raw.upper()
        if len(method_verb) <= 7 and method_verb in METHODS:
            req_method = method_verb[:2]
    else:
        # split the line on HTTP definition and delete prepended whitespaces
        method_line_split = method_line.split(" HTTP/")
        method_raw = method_line_split[0].lstrip(" ")
        method_verb = method_raw.split()[0].upper()
        if method_verb in METHODS:
            req_method = method_verb[:2]
            if "1.1" in method_line_split[1]:
                req_version = "1"
            else:
                req_version = "0"
    return "|".join((req_method, req_version))


# Checking header order - assuming that header field contains ":"
def get_hdr_order(request_split):
    return_list = []
    for reqline in request_split[1:]:
        hdr = reqline.split(":")[0]
        hdr_lower = hdr.lower()
        hdr_coded = format(fnv1a_32(hdr.encode()), "x")
        if hdr_lower in HDRL:
            if get_hdr_case(hdr):
                hdr_coded = HDRL[hdr_lower]
            else:
                hdr_coded = "!" + HDRL[hdr_lower]
        return_list.append(hdr_coded)
    return ",".join(return_list)


def get_ua_value(hdr):
    header_value = hdr.split(":")[1].lstrip(" ")
    name = HDRL["user-agent"]
    ret = name + ":" + format(fnv1a_32(header_value.encode()), "x")
    return ret


def get_hdr_value(hdr, hdrname, hdr_value_table):
    header_value = hdr.split(":")[1].lstrip(" ")
    hdr_coded = HDRL[hdrname] + ":"
    return_list = []
    if "," in header_value:
        # simple splitting of compound values
        if ";q=" in header_value:
            # we do not tokenize compound values with quality parameters at this moment
            return hdr_coded + format(fnv1a_32(header_value.encode()), "x")
        nested_values = [value.lstrip() for value in header_value.split(",")]
        for nested_value in nested_values:
            if nested_value == "":
                return hdr_coded + format(fnv1a_32(header_value.encode()), "x")
            if nested_value not in hdr_value_table:
                logger.info("Unknown header value - " + hdr)
                return hdr_coded + format(fnv1a_32(header_value.encode()), "x")
            return_list.append(hdr_value_table[nested_value])
    else:
        try:
            value_encoded = hdr_value_table[header_value]
        except KeyError:
            logger.info("Unknown header value - " + hdr)
            value_encoded = format(fnv1a_32(header_value.encode()), "x")
        return_list.append(value_encoded)
    return hdr_coded + ",".join(return_list)


def get_content_type(hdr):
    header_value = hdr.split(":")[1].lstrip(" ")
    hdr_coded = HDRL["content-type"] + ":"
    if "boundary=" in header_value:
        # We cut the header value at the end of "boundary=" keyword.
        # Everything after is discarded.
        value_with_boundary = header_value.split("boundary=")[0] + "boundary="
        return hdr_coded + format(fnv1a_32(value_with_boundary.encode()), "x")
    return_list = []
    if "," in header_value:
        nested_values = [value.lstrip() for value in header_value.split(",")]
        for nested_value in nested_values:
            try:
                value_encoded = CONTENTTYPE[nested_value]
            except KeyError:
                logger.info("Unknown Content-Type value - " + hdr)
                value_encoded = format(fnv1a_32(nested_value.encode()), "x")
            return_list.append(value_encoded)
    else:
        try:
            value_encoded = CONTENTTYPE[header_value]
        except KeyError:
            logger.info("Unknown Content-Type value - " + hdr)
            value_encoded = format(fnv1a_32(header_value.encode()), "x")
        return_list.append(value_encoded)
    return hdr_coded + ",".join(return_list)


def get_cache_control_value(hdr):
    header_value = hdr.split(":")[1].lstrip(" ")
    hdr_coded = HDRL["cache-control"] + ":"
    return_list = []
    if "," in header_value:
        # simple splitting of compound values
        nested_values = [value.lstrip() for value in header_value.split(",")]
        for nested_value in nested_values:
            if nested_value == "":
                return hdr_coded + format(fnv1a_32(header_value.encode()), "x")
            # some values have nested time values,
            # but we drop them as they can vary much
            if "=" in nested_value:
                nested_j = nested_value.split("=")[0]
                if nested_j in ("max-age", "max-stale", "min-fresh"):
                    nested_value = nested_j
            if nested_value not in CACHECONT:
                logger.info("Unknown header value - " + hdr)
                return hdr_coded + format(fnv1a_32(header_value.encode()), "x")
            return_list.append(CACHECONT[nested_value])
    else:
        if "=" in header_value:
            nested_val = header_value.split("=")[0]
            if nested_val in ("max-age", "max-stale", "min-fresh"):
                header_value = nested_val
        try:
            value_encoded = CACHECONT[header_value]
        except KeyError:
            logger.info("Unknown header value - " + hdr)
            value_encoded = format(fnv1a_32(header_value.encode()), "x")
        return_list.append(value_encoded)
    return hdr_coded + ",".join(return_list)


def get_accept_language_value(hdr):
    header_value = hdr.split(":")[1]
    header_name = HDRL["accept-language"]
    ret = header_name + ":" + format(fnv1a_32(header_value.encode()), "x")
    return ret


def get_pop_hdr_val(request_split):
    return_list = []
    for reqline in request_split[1:]:
        if ":" in reqline:
            hdr_lower = reqline.split(":")[0].lower()
            if hdr_lower == "connection":
                return_list.append(get_hdr_value(reqline, "connection", CONNVAL))
            elif hdr_lower == "accept-encoding":
                return_list.append(get_hdr_value(reqline, "accept-encoding", AEVAL))
            elif hdr_lower == "content-encoding":
                return_list.append(get_hdr_value(reqline, "content-encoding", CONTENC))
            elif hdr_lower == "cache-control":
                return_list.append(get_cache_control_value(reqline))
            elif hdr_lower == "te":
                return_list.append(get_hdr_value(reqline, "te", TE))
            elif hdr_lower == "accept-charset":
                return_list.append(get_hdr_value(reqline, "accept-charset", ACCPTCHAR))
            elif hdr_lower == "content-type":
                return_list.append(get_content_type(reqline))
            elif hdr_lower == "accept":
                return_list.append(get_hdr_value(reqline, "accept", ACCPT))
            elif hdr_lower == "accept-language":
                return_list.append(get_accept_language_value(reqline))
            elif hdr_lower == "user-agent":
                return_list.append(get_ua_value(reqline))
        else:
            logger.info("No colon in line: " + reqline)
    ret = "/".join(return_list)
    return ret
