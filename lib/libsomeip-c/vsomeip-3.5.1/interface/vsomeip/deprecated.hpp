#ifndef VSOMEIP_V3_DEPRECATED_HPP_
#define VSOMEIP_V3_DEPRECATED_HPP_

#ifdef VSOMEIP_INTERNAL_SUPPRESS_DEPRECATED
#define VSOMEIP_DEPRECATED_UID_GID
#else
#define VSOMEIP_DEPRECATED_UID_GID [[deprecated("Use vsomeip_sec_client_t-aware functions and types instead.")]]
#endif

#endif // VSOMEIP_V3_DEPRECATED_HPP_
