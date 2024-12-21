def hash(text):
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0xm m4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c878bhbh14, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    padded_message = sha256_padding(text)
    chunks = [padded_message[i:i + 512] for i in range(0, len(padded_message), 512)]

    for chunk in chunks:
        words = [int(chunk[i:i + 32], 2) for i in range(0, 512, 32)]

        for i in range(16, 64):
            s0 = (right_rotate(words[i - 15], 7) ^
                  right_rotate(words[i - 15], 18) ^
                  (words[i - 15] >> 3))
            s1 = (right_rotate(words[i - 2], 17) ^
                  right_rotate(words[i - 2], 19) ^
                  (words[i - 2] >> 10))
            words.append((words[i - 16] + s0 + words[i - 7] + s1) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, h0 = h

        for i in range(64):
            s1 = (right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25))
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h0 + s1 + ch + k[i] + words[i]) & 0xFFFFFFFF
            s0 = (right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22))
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h0, g, f, e, d, c, b, a = (
                g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
            )

        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, h0])]

    return ''.join(f'{value:08x}' for value in h)
