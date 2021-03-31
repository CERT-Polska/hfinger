# Features used by Hfinger

A complete list of request features extracted by Hfinger is presented below.
The list represents all features that Hfinger can analyze, however, each report mode uses their different subset,
including different rounding mode of each feature (if applicable). 
Report modes' feature subset specifications are presented in the README.
## URI features
URI features are used to extract information from the URI part of a request. They consist of: 
* _Length of the URI_, represented as a logarithm with base 10 of the actual URI length 
  (provided as a floating-point number rounded to one decimal place or rounded to an integer),
* _Number of directory levels in the URI_, represented as an integer,
* _Average length of the directory_, represented as a logarithm with base 10 of the actual average length 
  of the directory (provided as a floating-point number rounded to one decimal place or rounded to an integer),
* _Extension of the file requested in the URI_, if applicable. 
  The extension is extracted only if it is present on a defined list of popular extensions 
  to prevent extracting nonsensical values.
* _Length of the variable part of the URI_, where the URI parameters are stored, 
  represented as a logarithm with base 10 of the length 
  (provided as a floating-point number to rounded one decimal place or rounded to an integer),
* _Number of variables in the URI_, represented as an integer,
* _Average value length_, represented as a logarithm with base 10 of the actual average value length 
  (provided as a floating-point number rounded to one decimal place or rounded to an integer),

## Header structure features
Header structure features provide information about headers, their values, extended with information about request 
method and HTTP protocol version. The analyzed features consist of (in the order used in the fingerprint):
* _Request method_, presented as the first two characters of the method name,
* _HTTP protocol version_, expressed as a single number, 
  depending on the first digit after the dot in the protocol definition, 
  for example, "1" for "1.1" version and "9" if no protocol version is defined,
* _Representation of header order in the analyzed request_, 
  where the headers are expressed by the chosen encoding scheme. 
  The scheme provides list of popular headers for which encoding is provided, to shorten the fingerprint length. 
  However, if the header is not on the list, its name is hashed using 32 bit Fowler–Noll–Vo hash function in 
  the version 1a (FNV1a), and the hash is used as the name.
* _Representation of popular header's values_ - the following headers are analyzed to extract their value:
  * _Connection_,
  * _Accept-Encoding_,
  * _Content-Encoding_,
  * _Cache-Control_,
  * _TE_,
  * _Accept-Charset_,
  * _Content-Type_,
  * _Accept_,
  * _Accept-Language_,
  * _User-Agent_.

 If the header value is present on a list of popular values it is encoded with chosen, short encoding representation. 
 If it is not on the list, the values are hashed using FNV1a. 
 The representation is provided as an encoded header name and its encoded value, separated by ":" (colon), 
 and such pairs are separated using "/" (forward slash). If header can have multiple values, their representation is 
 separated by "," (comma). The order of the headers is preserved. Additionally, value of the _User-Agent_ header 
 is always represented as the FNV1a hash.

## Payload features
Payload features are extracted when any data are sent in the request. 
They consist of three features (in the order used in the fingerprint):
* _Presence of non-ASCII characters_, represented as a single letter "N" if non-ASCII characters are present, 
  and "A" otherwise,
* _Shannon entropy of the payload_, represented as a floating-point number rounded to one decimal place 
  or rounded to an integer,
* _Payload length_, represented as a logarithm with base 10 of the actual payload length 
  (provided as a floating-point number rounded to one decimal place or rounded to an integer).
