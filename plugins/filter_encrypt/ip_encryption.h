#ifndef FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_IP_ENCRYPTION_H_
#define FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_IP_ENCRYPTION_H_

void set_encryption_key(const char *encryption_key);
char *encrypt_ip(const char *input);

#ifdef _WIN32
void initialize_winsock();
void cleanup_winsock();
#endif

#endif // FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_IP_ENCRYPTION_H_
