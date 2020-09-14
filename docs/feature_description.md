# Features used by Hfinger

In this section features analyzed by Hfinger are presented and discussed. Some of the features are represented as either
 floating point number or integers. Features used in particular fingerprinting mode of Hfinger are presented in the README.
## URI features
URI features are used to extract information from URI part of a request. They include:

* Length of the URI, represented as a base 10 logarithm of actual URI length, provided as a floating point number rounded
 to first place after dot or rounded to an integer,
* Number of directory levels in the URI,
* Average length of directory, represented as a base 10 logarithm of actual average length of directory, provided as a 
floating point number rounded to first place after dot or rounded to an integer,
* Extension of the file requested in the URI, if applicable. The extension is extracted only if it is present on a 
defined list of popular extensions, in order to prevent from extracting nonsensical values.
* Length of the variable part of the URI, represented as a base 10 logarithm of the length, provided as a floating 
point number rounded to first place after dot or rounded to an integer,
* Number of variables in the URI, 
* Average value length, represented as base 10 logarithm of the actual average value length, provided as a floating 
point number rounded to first place after dot or rounded to an integer,

## Header structure features
Header structure features provide information about headers, their values, extended with information about request 
method and HTTP protocol version. The analyzed features consist of (in order used in fingerprint):
* Request method, presented as first two characters of the method name,
* HTTP protocol version, presented as single number, depending on first digit after dot in protocol definition, 
for example "1" for "1.1" version and "9" if no protocol version is defined,
* Representation of header order in the analyzed request, where headers are represented by chosen encoding scheme. 
The scheme provides list of popular headers for which encoding is provided, to shorten the fingerprint length. However, 
if the header is not on the list, its name is hashed using 32 bit Fowler–Noll–Vo hash function in version 1a 
(FNV1a), and the hash is used as the name.
* Representation of popular header's values. Following headers are analyzed to extract their value:
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
 
 If the value is present on a list of popular values it is encoded with chosen, short encoding representation. 
 If it is not on the list, the values are hashed using FNV1a. 
 The representation is provided as encoded header name and its encoded value, separated by ":" (colon), 
 and such pairs are separated using "/" (forward slash). If header can have multiple values, their representation is 
 separated by "," (comma). The order of the headers is preserved. Additionally, value of the _User-Agent_ header 
 is always represented as the FNV1a hash.


## Payload features
Payload features are extracted when any data are sent in request. They consist of three features (in order used in fingerprint):

* Presence of non-ASCII characters,
* Payload Shannon entropy,
* payload length, represented as base 10 logarithm of the actual payload length, provided as a floating point number
     rounded to first place after dot or rounded to an integer.
