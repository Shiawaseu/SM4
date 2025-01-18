# Overview

This is an implementation of the SM4 Cipher Algorithm written in *nearly* pure [Lua](https://www.lua.org/)

## SM4 Algorithm Background

ShāngMì 4 (SM4, 商密4) formerly SMS4 is a block cipher, standardised for commercial cryptography in China. It is used in the Chinese National Standard for Wireless LAN WAPI (WLAN Authentication and Privacy Infrastructure), and with Transport Layer Security.

The SM4 algorithm was drafted by Data Assurance & Communication Security Center, Chinese Academy of Sciences (CAS), and Commercial Cryptography Testing Center, National Cryptography Administration. It is mainly developed by Lü Shuwang (Chinese: 吕述望). The algorithm was declassified in January, 2006, and it became a national standard (GB/T 32907-2016) in August 2016.

> You can read more about it [here](https://en.wikipedia.org/wiki/SM4_(cipher))

## Usage

```lua
local SM4 = require(SM4)

local enc = SM4.encrypt('My secret text!!',"confidential key")
print('Encrypted Text:', enc.toString())

local dec = SM4.decrypt(enc.value, "confidential key")
print('Decrypted Text:', dec.toString())
```

### Input and Output Types

- **Input Types:**
  - Your Input & Key can be either a string or a byte table.
  - Both inputs must have a value of **16 bytes**
    - To cipher larger data, use a [Block Cipher Mode of Operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) to process data in chunks of 16 bytes. As this implementation focuses on single block encryption/decryption

- **Output Types:**
  - The `encrypt` and `decrypt` functions return a table with:
    - `value`: The encrypted or decrypted byte table.
    - `toString()`: A method to get the string representation of the byte table.

## License

This SM4 implementation is released under the MIT License. See the [LICENSE](/LICENSE) file for more details.

## Acknowledgements

- This implementation is based on the SM4 algorithm specification and is a rewrite of [this project](https://github.com/toruneko/lua-resty-sm4)



