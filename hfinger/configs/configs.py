from collections import OrderedDict

AEVAL = OrderedDict(
    [
        ("gzip", "gz"),
        ("deflate", "de"),
        ("identity", "id"),
        ("none", "no"),
        ("sdch", "sd"),
        ("br", "br"),
        ("compress", "co"),
        ("*", "as"),
        ("chunked", "ch"),
    ]
)
CONNVAL = OrderedDict(
    [
        ("Keep-Alive", "Ke-Al"),
        ("keep-alive", "ke-al"),
        ("close", "cl"),
        ("Close", "Cl"),
        ("Upgrade", "Up"),
    ]
)
CONTENC = OrderedDict(
    [
        ("gzip", "gz"),
        ("deflate", "de"),
        ("identity", "id"),
        ("binary", "bi"),
        ("br", "bt"),
        ("compress", "co"),
        ("UTF8", "UT"),
    ]
)
CACHECONT = OrderedDict(
    [
        ("max-age", "ma"),
        ("no-cache", "nc"),
        ("no-store", "ns"),
        ("no-transform", "nt"),
        ("only-if-cached", "oic"),
    ]
)
TE = OrderedDict(
    [
        ("gzip", "gz"),
        ("deflate", "de"),
        ("compress", "co"),
        ("http", "ht"),
        ("trailers", "tr"),
    ]
)
ACCPTCHAR = OrderedDict(
    [("windows-1251", "w1"), ("utf-8", "ut"), ("*", "as"), ("iso-8859-1", "is")]
)
FEATURESET = {
    0: OrderedDict(
        [(0, "f"), (3, "s"), (5, "s"), (7, "s"), (8, "s"), (10, "s"), (13, "i")]
    ),
    1: OrderedDict(
        [
            (0, "f"),
            (1, "s"),
            (3, "s"),
            (5, "s"),
            (7, "s"),
            (8, "s"),
            (9, "s"),
            (10, "s"),
            (12, "i"),
            (13, "i"),
        ]
    ),
    2: OrderedDict(
        [
            (0, "f"),
            (1, "s"),
            (2, "f"),
            (3, "s"),
            (4, "i"),
            (5, "s"),
            (6, "i"),
            (7, "s"),
            (8, "s"),
            (9, "s"),
            (10, "s"),
            (11, "s"),
            (12, "f"),
            (13, "f"),
        ]
    ),
}
METHODS = {
    "GET",
    "POST",
    "HEAD",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
}