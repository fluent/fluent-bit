set(src
        utils.c
        crypto_utils.c
        mjson.c
        hashmap.c
        ip_utils.c
        ip_encryption.c
        cryptopANT.c
        aes_deterministic.c
        aes_gcm_hmac_deterministic.c
        aes_gcm.c
        hmac.c
        encrypt.c)

FLB_PLUGIN(filter_encrypt "${src}" "")