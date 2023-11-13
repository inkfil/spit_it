#ifndef HASH_H
#define HASH_H

#include <iostream>
#include <typedefs.h>
#include <hash.h>

extern "C" {
        #include "pkdf2_hash.h"
}

class Hash {
public:
        static ByteArray GetHash(std::string password);
        static bool VerifyHash(ByteArray hash, std::string password);

        // Utility  Functions.
        static ByteArray string_to_bytearray(std::string str);
        static std::string print_hash(ByteArray ba);
};

#endif // HASH_H

