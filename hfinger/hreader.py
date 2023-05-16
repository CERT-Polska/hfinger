import json
from hfinger.configs import FEATURESET
from hfinger import hfinger_core, uri_reader
import logging

logger = logging.getLogger("hfinger")


def compute_finger_raw(tcp_raw, is_crlf_present):
    request_delimiter = b"\r\n\r\n"
    newline_delimiter = "\r\n"
    if not is_crlf_present:
        request_delimiter = b"\n\n"
        newline_delimiter = "\n"

    # Decoding request's binary form into RFC compliant ASCII text.
    # Non-ASCII characters are escaped with a backslash.
    # If they appear in the request (rarely), their double escaped version
    # will be processed further as an ASCII text.
    # For example, header value of "\x9a\xfa", will be transformed to "\\x9a\\xfa",
    # and FNV hash will be computed on the literal ASCII string of "\\x9a\\xfa",
    # not the original bytes.
    # This approach simplifies the code (such situations are exceptional),
    # but still preserves the original data in some way.
    try:
        pkt = (
            bytes.fromhex(tcp_raw)
            .split(request_delimiter)[0]
            .decode("ascii")
            .split(newline_delimiter)
        )
    except UnicodeDecodeError:
        logger.info("Non-ASCII characters found in the request (non-payload part)")
        pkt = (
            bytes.fromhex(tcp_raw)
            .split(request_delimiter)[0]
            .decode("ascii", errors="backslashreplace")
            .split(newline_delimiter)
        )
    uri_fingerprint = uri_reader.uri_fingerprint(pkt)
    method = hfinger_core.get_method_version(pkt)
    header_order = hfinger_core.get_hdr_order(pkt)
    popular_hdrs_values = hfinger_core.get_pop_hdr_val(pkt)
    return f"{uri_fingerprint}|{method}|{header_order}|{popular_hdrs_values}"


# format the fingerprint according to the reporting mode
def format_output(fingerprint_request, fingerprint_payload, report_mode):
    mask = FEATURESET[report_mode]
    return_list = []
    if fingerprint_request == "NULL":
        return "NULL"
    if fingerprint_payload == "":
        fingerprint_payload = "||"
    fingerprint_full = fingerprint_request + "|" + fingerprint_payload
    fingerprint_full_split = fingerprint_full.split("|")
    for mask_element in mask:
        fingerprint_field = fingerprint_full_split[int(mask_element)]
        if mask[mask_element] == "i" and fingerprint_field != "":
            fingerprint_field = str(int(round(float(fingerprint_field), 0)))
        return_list.append(fingerprint_field)
    return "|".join(return_list)


def analyze_request_give_fingerprint(request_raw, crlftagpresent):
    payload_raw = ""
    fingerprint_payload = ""
    request_delimiter_hex = "0d0a0d0a"
    req_delimiter_len = 8
    if not crlftagpresent:
        request_delimiter_hex = "0a0a"
        req_delimiter_len = 4
    fingerprint_request = compute_finger_raw(request_raw, crlftagpresent)
    req_delimiter_position = request_raw.find(request_delimiter_hex)
    if len(request_raw[req_delimiter_position + req_delimiter_len:]) > 0:
        payload_raw = request_raw[req_delimiter_position + req_delimiter_len:]
    if payload_raw != "":
        try:
            payload_ascii = bytes.fromhex(payload_raw).decode("ascii")
        except UnicodeDecodeError:
            fingerprint_payload += "N|"
        except TypeError:
            logger.info("Problem with string length when parsing payload")
        else:
            fingerprint_payload += "A|"
        payload_bytes = bytes.fromhex(payload_raw)
        fingerprint_payload += hfinger_core.get_entropy(payload_bytes)
        fingerprint_payload += "|"
        fingerprint_payload += hfinger_core.get_length(payload_bytes)
    return fingerprint_request, fingerprint_payload


def give_fingerprint(request_raw):
    fingerprint_request = ""
    fingerprint_payload = ""
    if "0d0a0d0a" in request_raw:
        fingerprint_request, fingerprint_payload = analyze_request_give_fingerprint(
            request_raw, True
        )
    elif "0a0a" in request_raw:
        logger.info("No CRLFCRLF in request switching to LFLF")
        fingerprint_request, fingerprint_payload = analyze_request_give_fingerprint(
            request_raw, False
        )
    else:
        logger.info("No CRLFCRLF or LFLF in request")
        fingerprint_request = "NULL"
    return fingerprint_request, fingerprint_payload


def reader(data, report_mode, is_tshark_old):
    return_list = []
    for packet in data:
        fingerprint_request = ""
        payload_raw = ""
        fingerprint_payload = ""
        output_json_dict = {}
        # Is http_raw layer present in the json dump?
        if "http_raw" in packet["_source"]["layers"]:
            # Is tcp.segments_raw layer present in the json dump?
            if "tcp.segments_raw" in packet["_source"]["layers"]:
                http_request_raw = ""
                if is_tshark_old:
                    http_request_raw = packet["_source"]["layers"]["tcp.segments_raw"]
                else:
                    http_request_raw = packet["_source"]["layers"]["tcp.segments_raw"][
                        0
                    ]
                fingerprint_request, fingerprint_payload = give_fingerprint(
                    http_request_raw
                )
            else:
                # No tcp.segments_raw layer, trying request extraction from frame_raw
                http_request_raw = ""
                if is_tshark_old:
                    tcp_bytes = packet["_source"]["layers"]["tcp_raw"]
                    ip_bytes = packet["_source"]["layers"]["ip_raw"]
                    eth_bytes = packet["_source"]["layers"]["eth_raw"]
                    frame_bytes = packet["_source"]["layers"]["frame_raw"]
                    lower_network_layers = eth_bytes + ip_bytes + tcp_bytes
                    http_request_raw = frame_bytes.split(lower_network_layers)[1]
                else:
                    tcp_bytes = packet["_source"]["layers"]["tcp_raw"][0]
                    ip_bytes = packet["_source"]["layers"]["ip_raw"][0]
                    eth_bytes = packet["_source"]["layers"]["eth_raw"][0]
                    frame_bytes = packet["_source"]["layers"]["frame_raw"][0]
                    lower_network_layers = eth_bytes + ip_bytes + tcp_bytes
                    http_request_raw = frame_bytes.split(lower_network_layers)[1]
                if "0d0a0d0a" in http_request_raw:
                    (
                        fingerprint_request,
                        fingerprint_payload,
                    ) = analyze_request_give_fingerprint(http_request_raw, True)
                elif "0a0a" in http_request_raw:
                    logger.info(
                        "No CRLFCRLF in request when parsing using frame_raw - switching to LFLF"
                    )
                    (
                        fingerprint_request,
                        fingerprint_payload,
                    ) = analyze_request_give_fingerprint(http_request_raw, False)
                else:
                    # Unusual situation, extracting request from http_raw layer
                    # - not always dependable layer
                    logger.info(
                        "Some other problem when parsing new line tags - going back to http_raw"
                    )
                    http_request_raw = packet["_source"]["layers"]["http_raw"]
                    fingerprint_request, fingerprint_payload = give_fingerprint(
                        http_request_raw
                    )
        output_json_dict["epoch_time"] = packet["_source"]["layers"]["frame"][
            "frame.time_epoch"
        ]
        output_json_dict["ip_src"] = packet["_source"]["layers"]["ip"]["ip.src"]
        output_json_dict["ip_dst"] = packet["_source"]["layers"]["ip"]["ip.dst"]
        output_json_dict["port_src"] = packet["_source"]["layers"]["tcp"]["tcp.srcport"]
        output_json_dict["port_dst"] = packet["_source"]["layers"]["tcp"]["tcp.dstport"]
        output_json_dict["fingerprint"] = format_output(
            fingerprint_request, fingerprint_payload, report_mode
        )
        return_list.append(output_json_dict)
    return return_list


# checking format of json to choose proper version of parsing
def reader_wrapper(fjson, rmode):
    with open(fjson, "r", encoding="utf-8", errors="ignore") as tshark_json_file:
        # Ignoring any possible json decoding errors. Some malware families
        # put non-ASCII characters into popular headers.
        # Tshark tries to put such characters directly into json file,
        # what sometimes breaks standard json decoders.
        # In later steps we analyze hex dump info from the json,
        # so errors' ignoring doesn't affect the analyzed data.
        data = json.load(tshark_json_file)
        if not data:
            return []
        if len(data[0]["_source"]["layers"]["frame_raw"]) > 1:
            return reader(data, rmode, False)
        else:
            return reader(data, rmode, True)
