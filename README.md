# GhidraNESTextDecode
Small decoder tool to translate encoded data in Ghidra to decoded labelled arrays, optionally with comments.

Originally made to help decode non-ASCII text for a <a href="https://github.com/GrasonHumphrey/Earthbound-Zero-Decomp">decompile</a> I'm working on.

## Instructions
Download the latest <a href="https://github.com/GrasonHumphrey/GhidraTextDecode/tree/master/Releases">release</a>.

### Adding your decoding dictionary
1. Unzip the .zip release file.
2. In the unzipped folder, open GhidraTextDecode\data\DecodeDictionary.txt
3. Edit the dictionary as needed.
    - Lines starting with # are ignored
    - General format: ENCODED=DECODED
    - Ghidra will interpret the hex byte value on the left as the text on the right of the =.
4. When you are finished, zip the folder.

### Adding extension to Ghidra
1. In Ghidra, add the .zip extension with File->Install Extensions->(Plus)
2. Restart Ghidra
3. Open CodeBrowser, if prompted configure the extension.  If not, enable it manually with File->Configure->(Plug in top right)->Check GhidraTextDecodePlugin.
4. Highlight data you want decoded, right click, Text Decode, select which decode method you want:
    - Decode: Standard decode, adds decoded labels and stops on unrecognized symbol.
    - Decode w/ comments: Standard decode plus plate comments.
    - Force decode: Standard decode, but doesn't stop on unrecognized symbol.
    - Force decode w/ comments: Force decode plus plate comments.