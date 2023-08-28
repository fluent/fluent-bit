set(src
        utils/utils.c
        utils/crypto_utils.c
        json/mjson.c
        hashmap/hashmap.c
        utils/ip_utils.c
        encryption_libs/ip_encryption.c
        encryption_libs/cryptopANT.c
        encryption_libs/aes_deterministic.c
        encryption_libs/aes_gcm_hmac_deterministic.c
        encryption_libs/aes_gcm.c
        encryption_libs/hmac.c
        encrypt.c)

FLB_PLUGIN(filter_encrypt "${src}" "")