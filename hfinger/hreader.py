import json
import sys
from hfinger.configs import FEATURESET
from hfinger import hfinger_core, uri_reader


def compute_finger_raw(tcp_raw, iscrlf):
    pkt = []
    if iscrlf:
        pkt = bytes.fromhex(tcp_raw).split(b"\r\n\r\n")[0].decode("ascii").split("\r\n")
    else:
        pkt = bytes.fromhex(tcp_raw).split(b"\n\n")[0].decode("ascii").split("\n")
    uri_fing = uri_reader.uri_fingerprint(pkt)
    method = hfinger_core.get_method_version(pkt)
    hdr = hfinger_core.get_hdr_order(pkt)
    val2 = hfinger_core.get_pop_hdr_val(pkt)
    return f"{uri_fing}|{method}|{hdr}|{val2}"


# format the fingerprint according to the reporting mode
def format_output(fing_r, fing_p, repmode):
    mask = FEATURESET[repmode]
    ret = []
    if fing_r == "NULL":
        return "NULL"
    if fing_p == "":
        fing_p = "||"
    fing_tmp = fing_r + "|" + fing_p
    fingtmps = fing_tmp.split("|")
    for i in mask:
        elt = fingtmps[int(i)]
        if mask[i] == "i" and elt != "":
            elt = str(int(round(float(elt), 0)))
        ret.append(elt)
    return "|".join(ret)


def analyze_request_give_fingerprint(tmp, crlftagpresent):
    payload_raw = ""
    finger_pay = ""
    delim = "0d0a0d0a"
    tag_len = 8
    if not crlftagpresent:
        delim = "0a0a"
        tag_len = 4
    finger_raw = compute_finger_raw(tmp, crlftagpresent)
    ind1 = tmp.find(delim)
    if len(tmp[ind1 + tag_len :]) > 0:
        payload_raw = tmp[ind1 + tag_len :]
    if payload_raw != "":
        try:
            payload_ascii = bytes.fromhex(payload_raw).decode("ascii")
        except UnicodeDecodeError:
            finger_pay += "N|"
        except TypeError:
            print(
                "Problem with string length when parsing payload",
                file=sys.stderr,
            )
        else:
            finger_pay += "A|"
        payload_bytes = bytes.fromhex(payload_raw)
        finger_pay += hfinger_core.get_entropy(payload_bytes)
        finger_pay += "|"
        finger_pay += hfinger_core.get_length(payload_bytes)
    return finger_raw, finger_pay


def give_fingerprint(treq):
    finger_raw = ""
    finger_pay = ""
    if "0d0a0d0a" in treq:
        finger_raw, finger_pay = analyze_request_give_fingerprint(treq, True)
    elif "0a0a" in treq:
        print(
            "No CRLFCRLF in request switching to LFLF",
            file=sys.stderr,
        )
        finger_raw, finger_pay = analyze_request_give_fingerprint(treq, False)
    else:
        print(
            "No CRLFCRLF or LFLF in request",
            file=sys.stderr,
        )
        finger_raw = "NULL"
    return finger_raw, finger_pay


def reader(data, report_mode, tsharkold):
    retlist = []
    for p in data:
        finger_raw = ""
        payload_raw = ""
        finger_pay = ""
        json_dict = {}
        # Is http_raw layer present in the json dump?
        if "http_raw" in p["_source"]["layers"]:
            # Is tcp.segments_raw layer present in the json dump?
            if "tcp.segments_raw" in p["_source"]["layers"]:
                tmp = ""
                if tsharkold:
                    tmp = p["_source"]["layers"]["tcp.segments_raw"]
                else:
                    tmp = p["_source"]["layers"]["tcp.segments_raw"][0]
                finger_raw, finger_pay = give_fingerprint(tmp)
            else:
                # No tcp.segments_raw layer, trying request extraction from frame_raw
                tmp = ""
                if tsharkold:
                    tcpr = p["_source"]["layers"]["tcp_raw"]
                    ipr = p["_source"]["layers"]["ip_raw"]
                    ethr = p["_source"]["layers"]["eth_raw"]
                    framer = p["_source"]["layers"]["frame_raw"]
                    delimr = ethr + ipr + tcpr
                    tmp = framer.split(delimr)[1]
                else:
                    tcpr = p["_source"]["layers"]["tcp_raw"][0]
                    ipr = p["_source"]["layers"]["ip_raw"][0]
                    ethr = p["_source"]["layers"]["eth_raw"][0]
                    framer = p["_source"]["layers"]["frame_raw"][0]
                    delimr = ethr + ipr + tcpr
                    tmp = framer.split(delimr)[1]
                finger_raw, finger_pay = give_fingerprint(tmp)
                if "0d0a0d0a" in tmp:
                    finger_raw, finger_pay = analyze_request_give_fingerprint(tmp, True)
                elif "0a0a" in tmp:
                    print(
                        "No CRLFCRLF in request when parsing using frame_raw - switching to LFLF",
                        file=sys.stderr,
                    )
                    finger_raw, finger_pay = analyze_request_give_fingerprint(
                        tmp, False
                    )
                else:
                    # Unusual situation, extracting request from http_raw layer - not always dependable layer
                    print(
                        "Some other problem when parsing new line tags - going back to http_raw",
                        file=sys.stderr,
                    )
                    tmp = p["_source"]["layers"]["http_raw"]
                    finger_raw, finger_pay = give_fingerprint(tmp)
        json_dict["epoch_time"] = p["_source"]["layers"]["frame"]["frame.time_epoch"]
        json_dict["ip_src"] = p["_source"]["layers"]["ip"]["ip.src"]
        json_dict["ip_dst"] = p["_source"]["layers"]["ip"]["ip.dst"]
        json_dict["port_src"] = p["_source"]["layers"]["tcp"]["tcp.srcport"]
        json_dict["port_dst"] = p["_source"]["layers"]["tcp"]["tcp.dstport"]
        json_dict["fingerprint"] = format_output(finger_raw, finger_pay, report_mode)
        retlist.append(json_dict)
    return retlist


# checking format of json to choose proper version of parsing
def reader_wrapper(fjson, rmode):
    with open(fjson, "r") as fin:
        data = json.load(fin)
        if not data:
            return []
        if len(data[0]["_source"]["layers"]["frame_raw"]) > 1:
            return reader(data, rmode, False)
        else:
            return reader(data, rmode, True)
