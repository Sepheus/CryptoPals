module crypto;
import std.stdio;
import std.algorithm : map, each, filter, reduce, sum;
import std.conv : to, parse;
import std.range : chunks, enumerate;
import std.array : array, join;

ubyte[] hexToBytes(const string hex) pure {
    return hex
        .chunks(2)
        .map!(n => n.parse!ubyte(16))
        .array;
}

string toB64(const ubyte[] data) pure {
    import std.base64;
    return Base64.encode(data);
}

ubyte[] xor(const string message, const string key) pure {
    return xor(message.hexToBytes, key.hexToBytes);
}

ubyte[] xorEncrypt(const string message, const string key) pure {
    ubyte[] m = cast(ubyte[])message;
    ubyte[] k = cast(ubyte[])key;
    return xor(m,k);
}

ubyte[] xor(const ubyte[] message, const ubyte[] key) pure {
    return message
        .enumerate
        .map!(m => m.value ^ key[m.index % key.length])
        .map!(to!ubyte)
        .array;
}

string toHex(const ubyte[] bytes) pure {
    import std.uni : toLower;
    import std.string : rightJustify;
    return bytes
            .map!(n => n.to!string(16).rightJustify(2,'0'))
            .join
            .toLower;
}

double score(const ubyte[] message) pure {
    import std.ascii : isAlphaNum, isWhite, toLower;
    int[ubyte] freq;
    message
        .filter!(l => isAlphaNum(l) || isWhite(l))
        .each!(l => freq[l.toLower]++);
    return freq.values?
        freq
            .values
            .map!(n => n / message.length.to!double)
            .sum
            : 0.0;
}

ubyte[] bruteXOR(const string message) pure {
    return message.hexToBytes.bruteXOR;
}

ubyte[] bruteXOR(const ubyte[] message) pure {
    import std.range : iota;
    return 256.iota
        .map!(k => message.xor([k.to!ubyte]))
        .reduce!((a,b) => a.score >= b.score ? a : b);
}

string xorDetect(const string input) pure {
    import std.string : splitLines;
	return cast(string)input
			.splitLines
			.map!(m => m.bruteXOR)
			.reduce!((a,b) => a.score >= b.score ? a : b );
}

uint countBits(const ubyte input) pure {
    uint count;
    ubyte n = input;
    for(count = 0; n > 0; count++) {
        n &= (n - 1);
    }
    return count;
}

uint distance(const string a, const string b) pure {
    return a.xorEncrypt(b)
            .map!(countBits)
            .sum;
}

ubyte[] breakXOR(const ubyte[] message) {
    2.iota(40)
     .map!(size => message[0 .. size].distance(message[size .. size+size] / size))
}

unittest {
    string b64Output = 
        ("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        ).hexToBytes
        .toB64;
    assert(b64Output == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    ubyte[] xorOutput = ("1c0111001f010100061a024b53535009181c").hexToBytes.xor("686974207468652062756c6c277320657965".hexToBytes);
    assert(xorOutput.toHex == "746865206b696420646f6e277420706c6179");
    assert(xorOutput == "the kid don't play");
    assert("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".bruteXOR == "Cooking MC's like a pound of bacon");
    assert("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".xorEncrypt("ICE").toHex == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    assert("this is a test".distance("wokka wokka!!!") == 37);
}