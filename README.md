# nimfuzz
Simple and compact Nim fuzzing library based on the great 
[fauxfactory](https://github.com/omaciel/fauxfactory). 
The primary purpose of the library is to generate random strings to test the 
security of common utilities to help defend your system.

Most of the module is self-explanatory, and you can look through the 
[Nim-generated docs](https://apense.github.io/nimfuzz) to see the available functions.

The available procedures so far are as follows:
  - [genAlpha](https://apense.github.io/nimfuzz/nimfuzz.html#genAlpha)
  - [genAlphanumeric](https://apense.github.io/nimfuzz/nimfuzz.html#genAlphanumeric)
  - [genChoice](https://apense.github.io/nimfuzz/nimfuzz.html#genChoice)
  - [genBool](https://apense.github.io/nimfuzz/nimfuzz.html#genBool)
  - [genCjk](https://apense.github.io/nimfuzz/nimfuzz.html#genCjk)
  - [genCyrillic](https://apense.github.io/nimfuzz/nimfuzz.html#genCyrillic)
  - [genEmail](https://apense.github.io/nimfuzz/nimfuzz.html#genEmail)
  - [genIpsum](https://apense.github.io/nimfuzz/nimfuzz.html#genIpsum)
  - [genLatin1](https://apense.github.io/nimfuzz/nimfuzz.html#genLatin1)
  - [genIpaddr](https://apense.github.io/nimfuzz/nimfuzz.html#genIpaddr)
  - [genMac](https://apense.github.io/nimfuzz/nimfuzz.html#genMac)
  - [genNetmask](https://apense.github.io/nimfuzz/nimfuzz.html#genNetmask)
  - [genNumericString](https://apense.github.io/nimfuzz/nimfuzz.html#genNumericString)
  - [genTime](https://apense.github.io/nimfuzz/nimfuzz.html#genTime)
  - [genUrl](https://apense.github.io/nimfuzz/nimfuzz.html#genUrl)
  - [genUtf8](https://apense.github.io/nimfuzz/nimfuzz.html#genUtf8)
  - [genHtml](https://apense.github.io/nimfuzz/nimfuzz.html#genHtml)
  - [genUuid](https://apense.github.io/nimfuzz/nimfuzz.html#genUuid)

Most functions return a `string`. See the 
[docs](https://apense.github.io/nimfuzz) for details

Nim implementation copyright 2015 Jonathan Edwards

Fauxfactory Copyright 2014 Og Maciel
