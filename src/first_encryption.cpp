#include "functions.cpp"



int main()
{
    //create the necessary parameters

    EncryptionParameters parms(scheme_type::BFV);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(2693);

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

    //evaluator for computation over context
    Evaluator evaluator(context);



//////////////////////////////////////////////////Everything above this line are parameters//////////////////////////////////////////////////
    int x = 10;
    int count = 0;
    Plaintext x_plain(to_string(x));
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    Plaintext x_decrypted;
    decryptor.decrypt(x_encrypted, x_decrypted);

    cout << "Plaintext: " + x_plain.to_string() << endl;
    cout << "Decrypted: " + x_decrypted.to_string()<<endl;

    cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;
    cout << "    + noise budget in freshly encrypted x: "
        << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;

    cout << "Continuing " << endl;

    cout << " x^2 +1: " << endl;
    Ciphertext x_sq_plus1;
    evaluator.square(x_encrypted, x_sq_plus1);
    Plaintext p_one("1");
    evaluator.add_plain_inplace(x_sq_plus1, p_one);

    cout << " Here" << endl;;

    cout << "sdize of x_sq plus one "  << x_sq_plus1.size() << endl;
    cout <<  "noise budget "  << decryptor.invariant_noise_budget(x_sq_plus1) << " bits" << endl;
    decryptor.decrypt(x_sq_plus1, x_decrypted);
    cout << "Decrypted: " + x_decrypted.to_string()<<endl;

   // cout << "Noise budget: " + decryptor.invariant_noise_budget(x_sq_plus1);






    // for(x; x<1024 && count != 5; x++)
    // {      
    //     Plaintext x_plain(to_string(x));
    //     Ciphertext x_encrypted;
    //     encryptor.encrypt(x_plain, x_encrypted);
    //     Plaintext decrypted_result;
    //     decryptor.decrypt(x_encrypted, decrypted_result);
    //     cout << "Plaintext: " + x_plain.to_string() << endl;
    //     cout << "Decrypted: " + decrypted_result.to_string()<<endl; // +  x_plain.to_string() << endl;

    //     if ( x_plain != decrypted_result)
    //         count++;

    // }
        
    // if (count >4)
    // {
    //     for(x; x < 2693; x++)
    //     {
    //         Plaintext x_plain(to_string(x));
    //     Ciphertext x_encrypted;
    //     encryptor.encrypt(x_plain, x_encrypted);
    //     Plaintext decrypted_result;
    //     decryptor.decrypt(x_encrypted, decrypted_result);
    //     cout << "Plaintext: " + x_plain.to_string() << endl;
    //     cout << "Decrypted: " + decrypted_result.to_string()<<endl; // +  x_plain.to_string() << endl;
    //     }
    // }

    //savePrivKey(secret_key, "keys.txt");
    //saveCipher(x_encrypted, "output.txt");

    
    
    //cout << " the decrypted part " << decrypted_result.to_string() ;
    //writeToFile("temp.txt", decrypted_result.to_string());


    return 0;
}
