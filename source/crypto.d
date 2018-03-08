module crypto;
import std.stdio;
import std.algorithm : map, each;
import std.conv : to, parse;
import std.range : chunks, enumerate;
import std.array : array, join;

ubyte[] hexToBytes(string hex) {
    return hex
        .chunks(2)
        .map!(n => n.parse!ubyte(16))
        .array;
}

string toB64(ubyte[] data) {
    import std.base64;
    return Base64.encode(data);
}

ubyte[] xor(string message, string key) {
    return xor(message.hexToBytes, key.hexToBytes);
}

ubyte[] xor(ubyte[] message, ubyte[] key) {
    return message
        .enumerate
        .map!(m => m.value ^ key[m.index % key.length])
        .map!(to!ubyte)
        .array;
}

string toHex(ubyte[] bytes) {
    import std.uni : toLower;
    return bytes
            .map!(n => n.to!string(16))
            .join
            .toLower;
}

unittest {
    string b64Output = 
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        .hexToBytes
        .toB64;
    assert(b64Output == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    ubyte[] xorOutput = "1c0111001f010100061a024b53535009181c"
                        .hexToBytes
                        .xor("686974207468652062756c6c277320657965".hexToBytes);
    assert(xorOutput.toHex == "746865206b696420646f6e277420706c6179");
    assert(xorOutput == "the kid don't play");
}