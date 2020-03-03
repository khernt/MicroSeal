#include "functions.cpp"



int main()
{
    //create the necessary parameters

    EncryptionParameters parms(scheme_type::BFV);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(2048);

    //context object
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

    int x = 112345;
    Plaintext x_plain(to_string(x));

    cout << "The plain text we have encrypted. " + x_plain.to_string() << endl; // +  x_plain.to_string() << endl;

    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);

    savePrivKey(secret_key, "keys.txt");
    saveCipher(x_encrypted, "output.txt");

    Plaintext decrypted_result;

    decryptor.decrypt(x_encrypted, decrypted_result);
    writeToFile("temp.txt", decrypted_result.to_string());


    





    //Plaintext second(t)
    //encryptor.encrypt(x_encrypted, x_encrypted);

    //inline std::streamoff save(getpt, 24, compr_mode_type compr_mode = Serialization::compr_mode_default);

    //cout << "Encrypted text: " + to_string(x_encrypted) << endl;

    return 0;
}
