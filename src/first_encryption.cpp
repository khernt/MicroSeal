#include "seal/seal.h"
#include "examples.h"


#include <iostream>

using namespace std;
using namespace seal;

int main()
{
    EncryptionParameters parms(scheme_type::BFV);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(1024);

    auto context = SEALContext::Create(parms);

    cout << "The encryption parameters chosen"  << endl;
    print_parameters(context);


    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();

    //to encrypt we need an encryptor instance
    Encryptor encryptor(context, public_key);

    //to decrypt we need an instance of decryptor
    Decryptor decryptor(context, secret_key);

    int x = 21354626;
    Plaintext x_plain(to_string(x));

    cout << "The plain text we have encrypted. " +  x_plain.to_string() << endl;

    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);

    cout << "Encrypted text: " + x_encrypted.to_string() << endl;

    return 0;
}
