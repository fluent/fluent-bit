"""Knowledge about cryptographic mechanisms implemented in Mbed TLS.

This module is entirely based on the PSA API.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
from typing import Dict, Iterable, Optional, Pattern, Tuple

from mbedtls_dev.asymmetric_key_data import ASYMMETRIC_KEY_DATA

class KeyType:
    """Knowledge about a PSA key type."""

    def __init__(self, name: str, params: Optional[Iterable[str]] = None):
        """Analyze a key type.

        The key type must be specified in PSA syntax. In its simplest form,
        `name` is a string 'PSA_KEY_TYPE_xxx' which is the name of a PSA key
        type macro. For key types that take arguments, the arguments can
        be passed either through the optional argument `params` or by
        passing an expression of the form 'PSA_KEY_TYPE_xxx(param1, ...)'
        in `name` as a string.
        """

        self.name = name.strip()
        """The key type macro name (``PSA_KEY_TYPE_xxx``).

        For key types constructed from a macro with arguments, this is the
        name of the macro, and the arguments are in `self.params`.
        """
        if params is None:
            if '(' in self.name:
                m = re.match(r'(\w+)\s*\((.*)\)\Z', self.name)
                assert m is not None
                self.name = m.group(1)
                params = m.group(2).split(',')
        self.params = (None if params is None else
                       [param.strip() for param in params])
        """The parameters of the key type, if there are any.

        None if the key type is a macro without arguments.
        """
        assert re.match(r'PSA_KEY_TYPE_\w+\Z', self.name)

        self.expression = self.name
        """A C expression whose value is the key type encoding."""
        if self.params is not None:
            self.expression += '(' + ', '.join(self.params) + ')'

        self.private_type = re.sub(r'_PUBLIC_KEY\Z', r'_KEY_PAIR', self.name)
        """The key type macro name for the corresponding key pair type.

        For everything other than a public key type, this is the same as
        `self.name`.
        """

    ECC_KEY_SIZES = {
        'PSA_ECC_FAMILY_SECP_K1': (192, 224, 256),
        'PSA_ECC_FAMILY_SECP_R1': (225, 256, 384, 521),
        'PSA_ECC_FAMILY_SECP_R2': (160,),
        'PSA_ECC_FAMILY_SECT_K1': (163, 233, 239, 283, 409, 571),
        'PSA_ECC_FAMILY_SECT_R1': (163, 233, 283, 409, 571),
        'PSA_ECC_FAMILY_SECT_R2': (163,),
        'PSA_ECC_FAMILY_BRAINPOOL_P_R1': (160, 192, 224, 256, 320, 384, 512),
        'PSA_ECC_FAMILY_MONTGOMERY': (255, 448),
        'PSA_ECC_FAMILY_TWISTED_EDWARDS': (255, 448),
    }
    KEY_TYPE_SIZES = {
        'PSA_KEY_TYPE_AES': (128, 192, 256), # exhaustive
        'PSA_KEY_TYPE_ARC4': (8, 128, 2048), # extremes + sensible
        'PSA_KEY_TYPE_ARIA': (128, 192, 256), # exhaustive
        'PSA_KEY_TYPE_CAMELLIA': (128, 192, 256), # exhaustive
        'PSA_KEY_TYPE_CHACHA20': (256,), # exhaustive
        'PSA_KEY_TYPE_DERIVE': (120, 128), # sample
        'PSA_KEY_TYPE_DES': (64, 128, 192), # exhaustive
        'PSA_KEY_TYPE_HMAC': (128, 160, 224, 256, 384, 512), # standard size for each supported hash
        'PSA_KEY_TYPE_RAW_DATA': (8, 40, 128), # sample
        'PSA_KEY_TYPE_RSA_KEY_PAIR': (1024, 1536), # small sample
    }
    def sizes_to_test(self) -> Tuple[int, ...]:
        """Return a tuple of key sizes to test.

        For key types that only allow a single size, or only a small set of
        sizes, these are all the possible sizes. For key types that allow a
        wide range of sizes, these are a representative sample of sizes,
        excluding large sizes for which a typical resource-constrained platform
        may run out of memory.
        """
        if self.private_type == 'PSA_KEY_TYPE_ECC_KEY_PAIR':
            assert self.params is not None
            return self.ECC_KEY_SIZES[self.params[0]]
        return self.KEY_TYPE_SIZES[self.private_type]

    # "48657265006973206b6579a064617461"
    DATA_BLOCK = b'Here\000is key\240data'
    def key_material(self, bits: int) -> bytes:
        """Return a byte string containing suitable key material with the given bit length.

        Use the PSA export representation. The resulting byte string is one that
        can be obtained with the following code:
        ```
        psa_set_key_type(&attributes, `self.expression`);
        psa_set_key_bits(&attributes, `bits`);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
        psa_generate_key(&attributes, &id);
        psa_export_key(id, `material`, ...);
        ```
        """
        if self.expression in ASYMMETRIC_KEY_DATA:
            if bits not in ASYMMETRIC_KEY_DATA[self.expression]:
                raise ValueError('No key data for {}-bit {}'
                                 .format(bits, self.expression))
            return ASYMMETRIC_KEY_DATA[self.expression][bits]
        if bits % 8 != 0:
            raise ValueError('Non-integer number of bytes: {} bits for {}'
                             .format(bits, self.expression))
        length = bits // 8
        if self.name == 'PSA_KEY_TYPE_DES':
            # "644573206b457901644573206b457902644573206b457904"
            des3 = b'dEs kEy\001dEs kEy\002dEs kEy\004'
            return des3[:length]
        return b''.join([self.DATA_BLOCK] * (length // len(self.DATA_BLOCK)) +
                        [self.DATA_BLOCK[:length % len(self.DATA_BLOCK)]])

    KEY_TYPE_FOR_SIGNATURE = {
        'PSA_KEY_USAGE_SIGN_HASH': re.compile('.*KEY_PAIR'),
        'PSA_KEY_USAGE_VERIFY_HASH': re.compile('.*KEY.*')
    } #type: Dict[str, Pattern]
    """Use a regexp to determine key types for which signature is possible
       when using the actual usage flag.
    """
    def is_valid_for_signature(self, usage: str) -> bool:
        """Determine if the key type is compatible with the specified
           signitute type.

        """
        # This is just temporaly solution for the implicit usage flags.
        return re.match(self.KEY_TYPE_FOR_SIGNATURE[usage], self.name) is not None
