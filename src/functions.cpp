#include "headers.h"


//function to save ciphertext into separate file
//NB: this file is in binary and unreadable
void saveCipher(Ciphertext encrypted, string filename)
{
        ofstream ct;
        ct.open(filename, ios::binary);
        encrypted.save(ct);
}


//function to save private key into separate file
//NB: this file is in binary and unreadable
void savePrivKey (SecretKey secret, string filename)
{
    ofstream ct;
    ct.open(filename, ios::binary);
    secret.save(ct);
    //ct.write(secret);

}

//function to save parameters needed to create the context for encryption/decryption object
//NB: this file is in binary and unreadable
void saveParams (EncryptionParameters params, string filename)
{
    ofstream printer;
    printer.open(filename, ios::binary);
    params.save(printer);
}

Ciphertext loadCiphertext(string filename, EncryptionParameters parms){

  auto context = SEALContext::Create(parms);

  ifstream printer;
  printer.open(filename, ios::binary);
  Ciphertext result;
  result.load(context, printer);

  return result;
}

void writeToFile(string filename, string data )
{
    ofstream printer;
    printer.open(filename);
    printer << data;
    printer.close();


    //return 0;

}