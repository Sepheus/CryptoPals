import std.stdio;
import std.base64;
import crypto;

void main() {
	string data = import("data/4.txt");
	string data2 = import("data/6.txt");
	data.xorDetect.write;
}