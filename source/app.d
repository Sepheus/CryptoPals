import std.stdio;
import std.base64;
import std.string;
import std.array;
import crypto;

void main() {
	string data = import("data/4.txt");
	string data2 = import("data/6.txt");
	CryptoPacket solution = data.xorDetect;
	"Plain Text: %s".writefln(solution.plainText);
	"Key Bytes: %s".writefln(solution.key);
	CryptoPacket solution2 = Base64.decode(data2.splitLines.join).breakXOR;
	"Plain Text: %s".writefln(solution2.plainText);
	"Key Bytes: %s".writefln(cast(string)solution2.key);
}