#include "hash.h"

ByteArray Hash::GetHash(std::string password) {
    ByteArray password_ba = string_to_bytearray(password);
    uint8_t *password_cleartext = (uint8_t *)password_ba.data();

    size_t maxmem = 0;
    double maxmemfrac = 0.5;
    double maxtime = 0.1;
    uint8_t outbuf[96]; //Header size for password derivation is fixed

    int passwdSize = password_ba.size();
	int logN = 0;
	uint32_t r = 0;
	uint32_t p = 0;
	uint8_t salt[] = "abcdefghijklmnopqrstuvwxyzabcdef";
	size_t osfreemem = 100;
	pickparams(&logN, &r, &p, maxtime, maxmem, maxmemfrac, osfreemem);

	int result = KDF(password_cleartext, (uint8_t)passwdSize, outbuf, logN, r, p, salt);

	if(result){
        return ByteArray();
    }
    return ByteArray(std::begin(outbuf), std::end(outbuf));
}

bool Hash::VerifyHash(ByteArray hash, std::string password) {
    ByteArray password_ba = string_to_bytearray(password);

	uint8_t *password_cleartext = (uint8_t *)password_ba.data();
    size_t passwdSize = password_ba.size();

	int result = Verify((uint8_t *)hash.data(), password_cleartext, passwdSize);
	return !result;
}

ByteArray Hash::string_to_bytearray(std::string str) {
    if(str.length() < 0){
        return ByteArray();
    }

    ByteArray result;
    for (const auto& c : str) {
        result.push_back(static_cast<uint8_t>(c));
    }
    
    return result;
}

std::string Hash::print_hash(ByteArray ba) {
    std::string result = "\n";
    for(const auto& elem: ba){
        result += elem;
    }
    result += "\n";
    return result;
}
