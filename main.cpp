#include <iostream>
#include <typedefs.h>
#include <hash.h>


int main(const int argc, const char** argv){

	if(argc != 3){
		std::cerr << "Usage: ./spit_it <password_to_hash>" <<std::endl;
	}

	std::string password = argv[1];

	/*
		purpose: encode cleartext -> hash;
		inputs: password -> pixiink, std::string to encode.
		output: hash -> generated 96 length bytearray.
	*/
	ByteArray hash = Hash::GetHash(password);
	std::cout << "\nHash: " << Hash::print_hash(hash) << std::endl;

	/*
		purpose: verify a pre generated hash againt a cleartext;
		input:
			password -> pixiink, std::string to verify against.
			hash -> pregenerated 96 length bytearray.
		output: bool -> true if hash matches, else false.
	*/
	bool isVerifiedHash = Hash::VerifyHash(hash, password);
	std::cout << "\nHash verified: " << isVerifiedHash << std::endl;

	password.append("a");
	isVerifiedHash = Hash::VerifyHash(hash, password);
	std::cout << "\nHash verified: " << isVerifiedHash << std::endl;

	return 0;
}
