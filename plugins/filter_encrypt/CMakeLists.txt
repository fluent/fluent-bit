# Define the list of source files excluding applink.c
set(src
        utils.c
        crypto_utils.c
        mjson.c
        hashmap.c
        ip_utils.c
        ip_encryption.c
        cryptopANT.c
        aes.c
        cmac.c
        aes_deterministic.c
        aes_gcm_hmac_deterministic.c
        aes_gcm.c
        hmac.c
        encrypt.c)

# Conditionally include applink.c only on Windows
if(WIN32)
    # Adjust the path if applink.c is in a different directory
    list(APPEND src applink.c)
endif()

# Define the Fluent Bit plugin with the configured source files
FLB_PLUGIN(filter_encrypt "${src}" "")
