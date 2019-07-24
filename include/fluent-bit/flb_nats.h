#ifndef FLB_NATS_H
#define FLB_NATS_H

#include <nats.h>

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_input.h>
#include <pthread.h>


//static void setProperty(const char **dest, const char *defaultValue);
//static void setByOutputProperty(struct flb_output_instance *ins, char *property, const char **dest, const char *defaultValue);
//static void setByInputProperty(struct flb_input_instance *ins, char *property, const char **dest, const char *defaultValue);
struct flb_common_stan_config {
    struct flb_common_nats_config *nats;

    stanConnection      *connection;
    stanConnOptions     *options;
    bool                closed;

    const char          *cluster;   //Name of the cluster
    const char          *client_id; //Name of the client (optional)
};

struct flb_common_nats_config {
    natsConnection      *connection;
    natsOptions         *options;
    bool                closed;
    natsSubscription    *subscription;
    natsStatus          status;

    pthread_mutex_t     connlock;       // Used to ensure single concurrent connection attempts

    const char          *subject;       // Subject used for regular NATS and NATS Streaming
    const char          *url;           // URL used for authentication, hostname and port in regular NATS and NATS Streaming

    bool                tls_enable;     // use secure (SSL/TLS) connection
    bool                tls_unverified; // Skip TLS server certificate verification
    const char          *tls_ca_path;   // CA trusted certificates file
    const char          *tls_crt_path;  // Client certificate (PEM format only)
    const char          *tls_key_path;  // Client private key file (PEM format only)
    const char          *tls_ciphers;   // TLS ciphers suite
    const char          *tls_hostname;  // TLS server certificate's expected hostname
};

struct flb_out_stan_config {
    //struct flb_output_instance    *ins;
    struct flb_common_stan_config *stan;
};

struct flb_in_stan_config {
    //struct flb_input_instance     *ins;
    struct flb_common_stan_config *stan;

    const char          *queue;
};

struct flb_out_nats_config {
    //struct flb_output_instance    *ins;
    struct flb_common_nats_config *nats;
};

struct flb_in_nats_config {
    //struct flb_input_instance     *ins;
    struct flb_common_nats_config *nats;
};

static const char stan_random_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";        
static const char *nats_setting_error = "[NATS] Error (%d) setting '%s': '%s'";
static const char *stan_setting_error = "[%s] Error (%d) setting '%s': '%s'";

static const char *getRandomStanClientID(size_t length) {
    char *randomString = NULL;
    if (length) {
        randomString = flb_malloc(sizeof(char) * (length +1));

        if (randomString) {            
            for (int n = 0;n < length;n++) {            
                int key = rand() % (int)(sizeof(stan_random_chars) -1);
                randomString[n] = stan_random_chars[key];
            }

            randomString[length] = '\0';
        }
    }
    return randomString;
}

static void setProperty(const char **dest, const char *defaultValue){
    if ((*dest == NULL || strlen(*dest) == 0) && strlen(defaultValue) > 0) {
        *dest = defaultValue; // Default property if it is undefined/empty
    }
    flb_info("[STAN] Set property to '%s'", *dest); // TODO Change to debug
}
static void setByOutputProperty(struct flb_output_instance *ins, char *propertyName, const char **dest, const char *defaultValue){
    *dest = flb_output_get_property(propertyName, ins);
    setProperty(dest, defaultValue);
}
static void setByInputProperty(struct flb_input_instance *ins, char *propertyName, const char **dest, const char *defaultValue){
    *dest = flb_input_get_property(propertyName, ins);
    setProperty(dest, defaultValue);
}


#endif