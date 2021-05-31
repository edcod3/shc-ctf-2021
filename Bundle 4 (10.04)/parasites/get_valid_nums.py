#!/usr/bin/python3

xor_val = 0x4fb30a91

check_vals = [0x4babd7ac, 0x4c49c202, 0x4abfde42,
              0x4b0333c6, 0x4b113b74, 0x4ab20669]

i = 0
for i in range(len(check_vals)):
    decoded = check_vals[i] ^ xor_val
    print("Solution Authentication " + str(i+1) + ":", str(decoded))
