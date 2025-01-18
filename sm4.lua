local bit = bit32
local SM4 = {}


local SBOX = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
}

local FK = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc }
local CK = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
}

local function get32(pc, n)
    return bit.bor(bit.lshift(pc[n], 24), bit.lshift(pc[n + 1], 16), bit.lshift(pc[n + 2], 8), pc[n + 3])
end

local function put32(st, ct, n)
    ct[n] = bit.band(bit.rshift(st, 24), 0xFF)
    ct[n + 1] = bit.band(bit.rshift(st, 16), 0xFF)
    ct[n + 2] = bit.band(bit.rshift(st, 8), 0xFF)
    ct[n + 3] = bit.band(st, 0xFF)
end

local function S(x, n)
    return bit.bor(bit.lshift(x, n), bit.rshift(x, 32 - n))
end

local function P(a)
    return bit.bxor(bit.lshift(SBOX[bit.rshift(a, 24) + 1], 24),
        bit.lshift(SBOX[bit.band(bit.rshift(a, 16), 0xFF) + 1], 16),
        bit.lshift(SBOX[bit.band(bit.rshift(a, 8), 0xFF) + 1], 8),
        SBOX[bit.band(a, 0xFF) + 1])
end

local function L(b)
    return bit.bxor(b, S(b, 2), S(b, 10), S(b, 18), S(b, 24))
end

local function T(a)
    return L(P(a))
end

local function F(x0, x1, x2, x3, rk)
    return bit.bxor(x0, T(bit.bxor(x1, x2, x3, rk)))
end

local function L1(b)
    return bit.bxor(b, S(b, 13), S(b, 23))
end

local function T1(a)
    return L1(P(a))
end

local function F1(x0, x1, x2, x3, rk)
    return bit.bxor(x0, T1(bit.bxor(x1, x2, x3, rk)))
end

local function SMS4_Init(key)
    local K = {}
    K[1] = bit.bxor(get32(key, 1), FK[1])
    K[2] = bit.bxor(get32(key, 5), FK[2])
    K[3] = bit.bxor(get32(key, 9), FK[3])
    K[4] = bit.bxor(get32(key, 13), FK[4])

    local rk = {}
    for i = 0, 7 do
        local j = 4 * i
        K[1] = F1(K[1], K[2], K[3], K[4], CK[j + 1])
        K[2] = F1(K[2], K[3], K[4], K[1], CK[j + 2])
        K[3] = F1(K[3], K[4], K[1], K[2], CK[j + 3])
        K[4] = F1(K[4], K[1], K[2], K[3], CK[j + 4])

        rk[j + 1], rk[j + 2], rk[j + 3], rk[j + 4] = K[1], K[2], K[3], K[4]
    end

    return rk
end

local function SMS4_Update_block(rk, _in, _out, enc)
    local X = {}
    X[1] = get32(_in, 1)
    X[2] = get32(_in, 5)
    X[3] = get32(_in, 9)
    X[4] = get32(_in, 13)

    for i = 0, 7 do
        local j = 4 * i
        X[1] = F(X[1], X[2], X[3], X[4], rk[enc and j + 1 or 32 - j])
        X[2] = F(X[2], X[3], X[4], X[1], rk[enc and j + 2 or 31 - j])
        X[3] = F(X[3], X[4], X[1], X[2], rk[enc and j + 3 or 30 - j])
        X[4] = F(X[4], X[1], X[2], X[3], rk[enc and j + 4 or 29 - j])
    end
    X[1], X[2], X[3], X[4] = X[4], X[3], X[2], X[1]

    put32(X[1], _out, 1)
    put32(X[2], _out, 5)
    put32(X[3], _out, 9)
    put32(X[4], _out, 13)
end

local function sms4_encrypt(_in, _out, key)
    local sms4key = { rk = key }
    SMS4_Update_block(sms4key.rk, _in, _out, true)
end

local function sms4_decrypt(_in, _out, key)
    local sms4key = { rk = key }
    SMS4_Update_block(sms4key.rk, _in, _out, false)
end


local function validate_data(data, key)
    assert((type(data) == "string" or "table"), "Data must be a string or a byte array")
    assert(((type(data) == "table" and #data == 16) or (data:len() == 16)), "Data length must be 16 bytes")

    assert((type(key) == "string" or "table"), "Key must be a string or a byte array")
    assert(((type(key) == "table" and #key == 16) or (key:len() == 16)), "Key length must be 16 bytes")
end


-- Conversion functions
local function string_to_bytes(str)
    local bytes = {}
    for i = 1, #str do
        bytes[i] = str:byte(i)
    end
    return bytes
end

local function bytes_to_string(bytes)
    local chars = {}
    for i = 1, #bytes do
        chars[i] = string.char(bytes[i])
    end
    return table.concat(chars)
end


function SM4.encrypt(input, key)
    validate_data(input, key)
    local input_bytes = (type(input) == "string" and string_to_bytes(input)) or input
    local key_bytes = (type(key) == "string" and string_to_bytes(key)) or key
    local rk = SMS4_Init(key_bytes)
    local ciphertext_bytes = {}
    sms4_encrypt(input_bytes, ciphertext_bytes, rk)
    return {
        toString = function() return bytes_to_string(ciphertext_bytes) end,
        value = ciphertext_bytes
    }
end

function SM4.decrypt(ciphertext, key)
    validate_data(ciphertext, key)
    local ciphertext_bytes = (type(ciphertext) == "string" and string_to_bytes(ciphertext)) or ciphertext
    local key_bytes = (type(key) == "string" and string_to_bytes(key)) or key
    local rk = SMS4_Init(key_bytes)
    local plaintext_bytes = {}
    sms4_decrypt(ciphertext_bytes, plaintext_bytes, rk)
    return {
        toString = function() return bytes_to_string(plaintext_bytes) end,
        value = plaintext_bytes
    }
end

return SM4
