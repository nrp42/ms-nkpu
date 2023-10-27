
    





dhcp4rsp

dhcp6req

uint16 optcode = 16
uint16 optlen = 15
uint32 enterprise = 311
uint16 datlen = 9
byte vci[9] = "BITLOCKER"

uint16 optcode = 17
uint16 optlen = 288
uint32 enterprise = 311
uint16 thumboptcode = 1
uint16 thumboptlen = 20
byte thumb[20]
uint16 kpoptcode = 2
uint16 kpoptlen = 256
byte kp[256]


v4 req paket:
0000   ff ff ff ff ff ff 00 16 3e 01 11 22 08 00 45 00
0010   02 73 4c 25 40 00 40 11 dd e7 0a 00 04 6e ff ff
0020   ff ff 00 44 00 43 02 5f cc 12 01 01 06 00 aa 67
0030   65 13 00 00 80 00 0a 00 04 6e 0a 00 04 6e 0a 00
0040   04 61 00 00 00 00 00 16 3e 01 11 22 00 00 00 00
0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00d0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00e0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00f0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0100   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0110   00 00 00 00 00 00 63 82 53 63 01 04 ff ff ff e0
0120   03 04 0a 00 04 61 06 04 0a 00 04 61 0f 06 6e 72
0130   70 2e 64 65 1c 04 0a 00 04 7f 2b 98 01 14 4a d0
0140   38 da 81 31 76 ac bd 5c aa ae 0f e3 49 4b 0d 00
0150   81 59 02 80 54 28 51 c2 12 ff 06 99 84 42 40 54
0160   1a ea 67 4b 5d 30 6b 5c b8 d5 8e fe 68 41 4e bb
0170   73 1a ce b4 90 85 c2 af 94 69 d3 ac 55 62 02 53
0180   f1 e0 84 3e 4e 45 cc 6a 08 08 3b b8 6c 47 14 24
0190   46 16 84 9e bb af 4a 2d 24 0e 67 31 c5 63 bf 52
01a0   89 f0 2e 41 e1 5e 77 ae 0b e2 23 c5 a8 5a 22 e8
01b0   b5 8b 98 32 6e f1 08 0f 39 06 4c 9c a2 12 52 20
01c0   b7 b9 23 9c 82 9d 6b 87 71 af 61 f9 a4 46 02 a6
01d0   e6 e4 62 74 33 04 00 00 a8 c0 36 04 0a 00 04 61
01e0   3a 04 00 00 54 60 3b 04 00 00 93 a8 3c 09 42 49
01f0   54 4c 4f 43 4b 45 52 7d 87 00 00 01 37 82 01 80
0200   db 12 79 4b 09 3b 2c 61 26 f4 2a bb 56 0e 8a bb
0210   cb 9c 65 e0 d5 75 f4 ff 74 9d be 0e a9 5e 1c 65
0220   93 46 be 20 e9 ec e4 59 fb 1b 9c 7b 8e 1a 4f 93
0230   5f 50 73 99 f7 54 ad b1 2b 49 82 fc 67 6b 97 8a
0240   0c 0b 1c ad 01 27 01 ae 23 f3 30 18 06 2d 30 a7
0250   19 82 6a 39 4a d0 e8 a1 f4 d8 4c 77 bf 30 1a 6d
0260   55 48 5b e4 9d 93 df 29 08 85 c8 4d a2 22 08 6f
0270   42 e2 93 72 9f 69 f7 ab f8 71 c3 75 f9 c8 64 59
0280   ff

v6 req packet:
0000   33 33 00 01 00 02 00 16 3e 01 11 22 86 dd 60 00
0010   00 00 01 67 11 80 fe 80 00 00 00 00 00 00 02 16
0020   3e ff fe 01 11 22 ff 02 00 00 00 00 00 00 00 00
0030   00 00 00 01 00 02 02 22 02 23 01 67 ca 79 0b 45
0040   d4 95 00 01 00 12 00 04 65 da 2a 2b 80 ba cb 4c
0050   98 2f 3a e3 09 3f 42 e5 00 08 00 02 01 2c 00 06
0060   00 04 00 10 00 11 00 10 00 0f 00 00 01 37 00 09
0070   42 49 54 4c 4f 43 4b 45 52 00 11 01 20 00 00 01
0080   37 00 01 00 14 4a d0 38 da 81 31 76 ac bd 5c aa
0090   ae 0f e3 49 4b 0d 00 81 59 00 02 01 00 b3 ea 27
00a0   5f 59 ae 14 97 5e de 74 3c 5d 68 35 45 63 f8 0d
00b0   a7 df 92 a8 f7 92 d9 fd 07 05 f2 37 69 c4 ac f7
00c0   2d ab 53 c5 28 81 6f 37 03 05 5a 86 fe f0 c0 99
00d0   94 8b e1 fd e3 74 1b 0c a7 5d 76 67 06 81 f6 62
00e0   c8 3f aa 02 aa 3c 57 ec f3 74 4c 5b 1e c7 02 2d
00f0   4a 31 d1 b3 64 8c bb d7 6c 2a 2c aa 22 da 18 90
0100   9a 44 7d 22 aa e8 88 2d ec 49 29 f3 07 85 b3 27
0110   89 d8 8a fe 54 eb 14 ae e1 1f 76 ea a2 5c d1 41
0120   da 25 6b 3a 3c 84 c1 0c 1d 76 7e cf 31 fe a3 36
0130   e9 21 e3 42 5d 28 6c 41 1b ae 56 02 3b 05 0a 9a
0140   8c e6 53 27 15 63 b8 f1 5a 35 aa 11 78 65 a5 4b
0150   b7 45 fe 5b 5e 13 b9 c0 f2 d1 99 9d 63 91 69 64
0160   f0 82 6e 3f cb a0 9c dd 94 10 15 52 d4 65 2d aa
0170   c8 f3 d7 99 0f 56 f8 34 c7 0b 4e b4 48 9d 76 25
0180   13 ff e0 42 8a 5b e1 33 e6 bd 01 c0 19 ed b9 ca
0190   0b 75 4a b5 e1 30 2a a6 a9 0e 97 3a c1


v4-opt43.2-response-full
0000   02 3c 4f 9f fc 3c 3e e6 c5 ae 9c 4a a8 ec 0c 73
0010   2f 2f b2 fb 68 ee 32 d5 44 f1 6e ee fe 23 8c 20
0020   a0 7e 13 38 9e 07 7f fa 50 44 0c a2 2e 8a 2b 38
0030   36 26 a4 c0 68 10 31 81 68 2c 8a b6 28 da



M=RSAES-PKCS1-V1_5-DECRYPT (K, C)
   Input:
      K        recipient's RSA private key
      C        ciphertext to be decrypted, an octet string of length k,
               where k is the length in octets of the RSA modulus n
   Output:
      M        message, an octet string of length at most k - 11

   Steps:

      1.  Length checking: If the length of the ciphertext C is not k
          octets (or if k < 11), output "decryption error" and stop.

      2.  RSA decryption:

          a.  Convert the ciphertext C to an integer ciphertext
              representative c (see Section 4.2):

                 c = OS2IP (C).

          b.  Apply the RSADP decryption primitive (Section 5.1.2) to
              the RSA private key (n, d) and the ciphertext
              representative c to produce an integer message
              representative m:

                 m = RSADP ((n, d), c).

              If RSADP outputs "ciphertext representative out of range"
              (meaning that c >= n), output "decryption error" and stop.

          c.  Convert the message representative m to an encoded message
              EM of length k octets (see Section 4.1):

                 EM = I2OSP (m, k).

      3.  EME-PKCS1-v1_5 decoding: Separate the encoded message EM into
          an octet string PS consisting of nonzero octets and a message
          M as

             EM = 0x00 || 0x02 || PS || 0x00 || M.

          If the first octet of EM does not have hexadecimal value 0x00,
          if the second octet of EM does not have hexadecimal value
          0x02, if there is no octet with hexadecimal value 0x00 to
          separate PS from M, or if the length of PS is less than 8
          octets, output "decryption error" and stop.  (See the note
          below.)

      4.  Output M.


public static int keySizeInOctets(RSAKey key) {
    int keySizeBits = key.getModulus().bitLength();
    int keySizeBytes = (keySizeBits + Byte.SIZE - 1) / Byte.SIZE;
    return keySizeBytes;
}



public static BigInteger os2ip(final byte[] data, final int size) {
    if (data.length != size) {
        throw new IllegalArgumentException("Size of the octet string should be precisely " + size);
    }

    return new BigInteger(1, data); 
}

public static byte[] i2osp(final BigInteger i, final int size) {
    if (size < 1) {
        throw new IllegalArgumentException("Size of the octet string should be at least 1 but is " + size);
    }

    if (i == null || i.signum() == -1 || i.bitLength() > size * Byte.SIZE) {
        throw new IllegalArgumentException("Integer should be a positive number or 0, no larger than the given size");
    }

    final byte[] signed = i.toByteArray();
    if (signed.length == size) {
        // (we are lucky, already the right size)
        return signed;
    }

    final byte[] os = new byte[size];
    if (signed.length < size) {
        // (the dynamically sized array is too small, pad with 00 valued bytes at the left)
        System.arraycopy(signed, 0, os, size - signed.length, signed.length);
        return os;
    }

    // (signed representation too large, remove leading 00 valued byte)
    System.arraycopy(signed, 1, os, 0, size);
    return os;
}


int ccm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Setting IV len to 7. Not strictly necessary as this is the default
     * but shown here for the purposes of this example.
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
        handleErrors();

    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, NULL);

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /* Provide the total plaintext length */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len))
        handleErrors();

    /* Provide any AAD data. This can be called zero or one times as required */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can only be called once for this.
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in CCM mode.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 14, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


