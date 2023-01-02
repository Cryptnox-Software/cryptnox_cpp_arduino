#if 1
#include <SPI.h>
#include <PN532_SPI.h>
#include "PN532.h"

PN532_SPI pn532spi(SPI, 10);
PN532 nfc(pn532spi);
#elif 0
#include <PN532_HSU.h>
#include <PN532.h>

PN532_HSU pn532hsu(Serial1);
PN532 nfc(pn532hsu);
#else
#include <Wire.h>
#include <PN532_I2C.h>
#include <PN532.h>
#endif

#include <uECC.h>
#include "AESLib.h"
#include <AES.h>

#include <Crypto.h>
#include <SHA512.h>
AES aes;
AESLib aesLib;

AESLib aesLib_without_padding;
SHA512 sha512;

#define INPUT_BUFFER_LIMIT (128 + 1)
#define HASH_SIZE 64

unsigned char cleartext[INPUT_BUFFER_LIMIT] = {0};
unsigned char ciphertext[2 * INPUT_BUFFER_LIMIT] = {0};
uint8_t aesKey[32];
uint8_t macKey[32];
uint8_t ivKey[16];
bool success;
//extern "C"
//{
//  static int RNG(uint8_t *dest, unsigned size);
//}
//extern "C"
//{
//
//  static int RNG(uint8_t *dest, unsigned size)
//  {
//
//    while (size)
//    {
//      uint8_t val = 0;
//      for (unsigned i = 0; i < 8; ++i)
//      {
//        int init = analogRead(0);
//        int count = 0;
//        while (analogRead(0) == init)
//        {
//          ++count;
//        }
//
//        if (count == 0)
//        {
//          val = (val << 1) | (init & 0x01);
//        }
//        else
//        {
//          val = (val << 1) | (count & 0x01);
//        }
//      }
//      *dest = val;
//      ++dest;
//      --size;
//    }
//
//    return 1;
//  }
//}



void setup()
{
  Serial.begin(115200);

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata)
  {
    Serial.print("Didn't find PN53x board");
    while (1)
      ;
  }

  Serial.print("Found chip PN5");
  Serial.println((versiondata >> 24) & 0xFF, HEX);
  Serial.print("Firmware ver. ");
  Serial.print((versiondata >> 16) & 0xFF, DEC);
  Serial.print('.');
  Serial.println((versiondata >> 8) & 0xFF, DEC);

  //   getKeysECC();

  nfc.SAMConfig();
}

void loop()
{

  aesLib.set_paddingmode((paddingMode)1);
  uint8_t response_select_apdu[255];
  uint8_t responseLength = sizeof(response_select_apdu);

  memset(response_select_apdu, 0, sizeof(response_select_apdu));

  Serial.println("Waiting for an ISO14443A card");

  success = nfc.inListPassiveTarget();

  if (success)
  {

    // SELECT --------------------------------------------------




    Serial.println("Found something!");
    uint8_t selectApdu[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12};
    success = nfc.inDataExchange(selectApdu, sizeof(selectApdu), response_select_apdu, &responseLength);

    // CARD CERT AND Manufacture --------------------------------------------------



    if (success)
    {
      // uint8_t apdu[] = {0x80, 0xF7, 0x00, 0x01, 0x00}; // manu Cert
      uint8_t card_cert_apdu[] = {0x80, 0xF8, 0x00, 0x00, 0x08, 0x53, 0x0C, 0x18, 0x4B, 0x89, 0xE1, 0x02, 0x84}; // card Cert
      uint8_t res_card_cert[255];
      uint8_t apduLength = sizeof(res_card_cert);
      //   bool successCardCert = sendApdu(card_cert_apdu, res_card_cert, success);
      success = nfc.inDataExchange(card_cert_apdu, sizeof(card_cert_apdu), res_card_cert, &apduLength);

      if (success)
      {

        // INIT ----------------------------------------------------------------------



        byte secret[32];
        uint8_t public1[64];
        uint8_t cardCert[64];
        getKeysECC(res_card_cert, secret, public1, cardCert);
        Serial.println("Secret output");
        for (int i = 0; i < sizeof(secret); i++) {
          Serial.print(secret[i], HEX);
          Serial.print(" ");
        }
        Serial.println();


        byte  iv[N_BLOCK] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};

        // aesLib.gen_iv(iv);
        aesLib.set_paddingmode((paddingMode)1);

        Serial.println();
        char sampleData[] = {0XE, 0X79, 0X61, 0X6E, 0X6E, 0X61, 0X69, 0X6E, 0X67, 0X77, 0X69, 0X6E, 0X6E, 0X61, 0X69, 0X19, 0X79, 0X61, 0X6E, 0X6E, 0X61, 0X69, 0X6E, 0X67, 0X77, 0X69, 0X6E, 0X32, 0X31, 0X39, 0X34, 0X40, 0X67, 0X6D, 0X61, 0X69, 0X6C, 0X2E, 0X63, 0X6F, 0X6D, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X43, 0X72, 0X79, 0X70, 0X74, 0X6E, 0X6F, 0X78, 0X20, 0X42, 0X61, 0X73, 0X69, 0X63, 0X20, 0X43, 0X6F, 0X6D, 0X6D, 0X6F, 0X6E, 0X50, 0X61, 0X69, 0X72, 0X69, 0X6E, 0X67, 0X44, 0X61, 0X74, 0X61};
        //  char sampleData[] = {0X08, 0X79, 0X61, 0X6E, 0X6E, 0X61, 0X69, 0X6E, 0X67, 0X19, 0X79, 0X61, 0X6E, 0X6E, 0X61, 0X69, 0X6E, 0X67, 0X77, 0X69, 0X6E, 0X32, 0X31, 0X39, 0X34, 0X40, 0X67, 0X6D, 0X61, 0X69, 0X6C, 0X2E, 0X63, 0X6F, 0X6D, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30, 0X43, 0X72, 0X79, 0X70, 0X74, 0X6E, 0X6F, 0X78, 0X20, 0X42, 0X61, 0X73, 0X69, 0X63, 0X20, 0X43, 0X6F, 0X6D, 0X6D, 0X6F, 0X6E, 0X50, 0X61, 0X69, 0X72, 0X69, 0X6E, 0X67, 0X44, 0X61, 0X74, 0X61};
        uint16_t msgLen = sizeof(sampleData);
        int encryptedLength = aesLib.get_cipher_length(sizeof(sampleData));
        Serial.println(encryptedLength);

        unsigned  char ciphertext[2 * INPUT_BUFFER_LIMIT] = {0};


        Serial.println();

        byte aes_key[] = {0X41, 0XA2, 0X1, 0X67, 0X13, 0XDD, 0XB3, 0X67, 0X76, 0XDB, 0X93, 0XD5, 0X78, 0X4F, 0XA4, 0X36, 0X48, 0XDC, 0X56, 0X2, 0X6A, 0X49, 0XDE, 0X9E, 0X49, 0XA3, 0XE6, 0X4, 0X4F, 0X29, 0X86, 0X8A};
        byte iv_key[] = {0XAA, 0X17, 0XFF, 0X52, 0X69, 0X8E, 0X23, 0X80, 0XFE, 0X71, 0XF2, 0X13, 0X72, 0XD1, 0X54, 0XE2};
        uint16_t cipherLength;
        // cipherLength = aes_cbc_encrypt(sampleData, sizeof(sampleData), ciphertext, secret, sizeof(secret), iv_key, true);
        cipherLength = aesLib.encrypt((byte*)sampleData , sizeof(sampleData), ciphertext, secret, sizeof(secret), iv_key);


        byte  enc_iv[N_BLOCK] = {0XAA, 0X17, 0XFF, 0X52, 0X69, 0X8E, 0X23, 0X80, 0XFE, 0X71, 0XF2, 0X13, 0X72, 0XD1, 0X54, 0XE2};
        uint8_t init[] = {0x80, 0xFE, 0x00, 0x00, 82 + cipherLength, 0x41, 0x04};

        int sizeOfInit = sizeof(init) + sizeof(public1) + sizeof(enc_iv) + cipherLength;
        uint8_t initApdu[sizeOfInit];

        char * bufout = initApdu;
        memcpy(bufout, init, sizeof(init));
        bufout += sizeof(init);
        memcpy(bufout, public1, sizeof(public1));
        bufout += sizeof(public1);
        memcpy(bufout, enc_iv, sizeof(enc_iv));
        bufout += sizeof(enc_iv);
        memcpy(bufout, ciphertext , cipherLength);

        uint8_t res_init[255];
        uint8_t initResLength = sizeof(res_init);
        Serial.println(sizeof(initApdu));

        for (int i = 0 ; i < sizeof(initApdu); i++) {
          Serial.print(initApdu[i], HEX);
        }
        Serial.println();

        success = nfc.inDataExchange(initApdu, sizeof(initApdu), res_init, &initResLength);

        if (success)
        {

          // OPen Secure Channel -----------------------------------------------------
          Serial.print("responseLength: ");
          Serial.println(initResLength);
          Serial.println("INIT response");
          nfc.PrintHexChar(res_init, initResLength);
          uECC_set_rng(&RNG);

          const struct uECC_Curve_t *curve = uECC_secp256r1();
          uint8_t private_opc[32];
          uint8_t public_opc[64];
          bool eccSuccess;
          bool eccSharedSuccessOPC;
          eccSuccess = uECC_make_key(public_opc, private_opc, curve);

          Serial.println("public Key");

          for (int i = 0 ; i < sizeof(public_opc); i++) {
            Serial.print(public_opc[i], HEX);
          }
          Serial.println();

          if (eccSuccess) {
            uint8_t opc[] = {0x80, 0x10, 0x00, 0x00, 0x41, 0x04};

            int size_opc = sizeof(opc) + 64;
            uint8_t opcApdu[size_opc];


            char * bufout_opc = opcApdu;
            memcpy(bufout_opc, opc, sizeof(opc));
            bufout_opc += sizeof(opc);
            memcpy(bufout_opc, public_opc, sizeof(public_opc));


            uint8_t res_opc[255];
            uint8_t opcResLength = sizeof(res_opc);



            Serial.println("send APDU");

            for (int i = 0 ; i < sizeof(opcApdu); i++) {
              Serial.print(opcApdu[i], HEX);
            }
            Serial.println();



            success =  nfc.inDataExchange(opcApdu, sizeof(opcApdu), res_opc, &opcResLength);

            if (success) {
              Serial.print("responseLength: ");
              Serial.println(opcResLength);
              Serial.println("Open Secure Channel response");
              nfc.PrintHexChar(res_opc, opcResLength);

              uint8_t salt[32];

              memcpy(salt , res_opc, sizeof(salt));


              uint8_t pairingSecret[] = { 0X43, 0X72, 0X79, 0X70, 0X74, 0X6E, 0X6F, 0X78, 0X20, 0X42, 0X61, 0X73, 0X69, 0X63, 0X20, 0X43, 0X6F, 0X6D, 0X6D, 0X6F, 0X6E, 0X50, 0X61, 0X69, 0X72, 0X69, 0X6E, 0X67, 0X44, 0X61, 0X74, 0X61};
              uint8_t shared_secret_opc[32];
              eccSharedSuccessOPC = uECC_shared_secret(cardCert, private_opc, shared_secret_opc, curve);
              if (eccSharedSuccessOPC)
              {
                Serial.println("shared secret response : ");

                for (int i = 0 ; i < sizeof(shared_secret_opc); i++) {
                  Serial.print(shared_secret_opc[i], HEX);
                }
                Serial.println();

                uint8_t sizeOfSecret = sizeof(shared_secret_opc) + sizeof(pairingSecret) + sizeof(salt);
                uint8_t secret_opc[sizeOfSecret];
                char * bufout_opc = secret_opc;
                memcpy(bufout_opc , shared_secret_opc, sizeof(shared_secret_opc));
                bufout_opc +=  sizeof(shared_secret_opc);
                memcpy(bufout_opc , pairingSecret, sizeof(pairingSecret));
                bufout_opc +=  sizeof(pairingSecret);
                memcpy(bufout_opc , salt, sizeof(salt));

                uint8_t result[64];
                Hash *hash = &sha512;


                hash->reset();
                hash->update(secret_opc, sizeof(secret_opc));
                Serial.println("data input : ");
                for (int i = 0 ; i < sizeof(secret_opc); i++) {
                  Serial.print(secret_opc[i], HEX);
                }
                Serial.println();
                Serial.println("SHA512 response : ");
                hash->finalize(result, sizeof(result));
                for (int i = 0 ; i < sizeof(result); i++) {
                  Serial.print(result[i], HEX);
                  Serial.print(" ");
                }
                Serial.println();




                memcpy(aesKey, result, 32);
                Serial.println("AES KEY");
                for (int i = 0; i < sizeof(aesKey) ; i++) {
                  Serial.print(aesKey[i], HEX);
                  Serial.print(" ");
                }
                Serial.println();
                memcpy(macKey, result + 32, 32);
                Serial.println("MAC KEY");
                for (int i = 0; i < sizeof(macKey) ; i++) {
                  Serial.print(macKey[i], HEX);
                  Serial.print(" ");
                }
                Serial.println();


                Serial.println();
                uint8_t  iv_opc[N_BLOCK] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
                uint8_t  MAC_iv[N_BLOCK] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                uint8_t  RNG_data[] = {0X7, 0X72, 0X30, 0XB, 0XDC, 0X82, 0X58, 0XEC, 0X32, 0X59, 0XCE, 0X38, 0X69, 0X24, 0X1B, 0X59, 0XFB, 0X10, 0X7B, 0X92, 0X10, 0XF2, 0X6E, 0X1F, 0X5E, 0X37, 0X66, 0X6A, 0XC6, 0X55, 0XB5, 0XEF};
                uint8_t AEStest[] = {0X17, 0XAB, 0XF2, 0XAF, 0X5E, 0X19, 0X58, 0X7A, 0X8D, 0X4C, 0X9C, 0XC9, 0X22, 0X6F, 0X80, 0X77, 0X56, 0X2, 0X14, 0X7A, 0X8D, 0X58, 0X6C, 0X46, 0X5F, 0XE4, 0XDB, 0X2F, 0X14, 0XD7, 0X20, 0XBE};
                uint8_t MACtest[] = {0XFE, 0XF7, 0X97, 0X3B, 0XF0, 0X33, 0XAD, 0X12, 0XC1, 0X3E, 0X5B, 0X94, 0X59, 0X82, 0X26, 0X80, 0XC0, 0XD6, 0XCB, 0X2, 0X3C, 0X36, 0X4, 0XD5, 0X2D, 0X3E, 0X5A, 0XF6, 0X7B, 0XFF, 0X1E, 0XDF};
                //  uint8_t opcApduSec[]



                unsigned  char ciphertextOPC[2 * INPUT_BUFFER_LIMIT] = {0};
                uint8_t paddedLength = aesLib.get_cipher_length(sizeof(RNG_data));
                uint16_t cipherLength ;
                //cipherLength = aes_cbc_encrypt(RNG_data, sizeof(RNG_data), ciphertextOPC, aesKey, sizeof(aesKey), iv_opc, true);
                cipherLength = aesLib.encrypt((byte*)RNG_data , sizeof(RNG_data), ciphertextOPC, aesKey, sizeof(aesKey), iv_opc);
                Serial.print("cipherlength = ");
                Serial.println(cipherLength);



                Serial.println(" Encrypted ------------------ ");
                for (int i = 0 ; i < cipherLength; i++) {
                  Serial.print(ciphertextOPC[i], HEX);
                }

                Serial.println();

                uint8_t opcApduHeader[] = {0x80, 0x11, 0x00, 0x00, paddedLength + 16};
                uint8_t MAC_apduHeader[] = {0x80, 0x11, 0x00, 0x00, paddedLength + 16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                uint8_t MAC_data_length = sizeof(MAC_apduHeader) + cipherLength;
                uint8_t MAC_data[MAC_data_length];
                char * buffMAC_data = MAC_data;

                memcpy(buffMAC_data, MAC_apduHeader, sizeof(MAC_apduHeader));
                buffMAC_data += sizeof(MAC_apduHeader);
                memcpy(buffMAC_data, ciphertextOPC, cipherLength);

                Serial.println(" MAC data ------------------ ");
                for (int i = 0 ; i < MAC_data_length; i++) {
                  Serial.print(MAC_data[i], HEX);
                }

                Serial.println();


                unsigned  char ciphertextMACLong[2 * INPUT_BUFFER_LIMIT] = {0};
                //=  aes_cbc_encrypt(MAC_data, MAC_data_length, ciphertextMACLong, macKey, sizeof(macKey), MAC_iv, false);
                uint16_t encryptedLengthMAC = aesLib_without_padding.encrypt((byte*)MAC_data , MAC_data_length, ciphertextMACLong, macKey, sizeof(macKey), MAC_iv);

                uint8_t MACpaddedLength = aesLib_without_padding.get_cipher_length(MAC_data_length);
                Serial.println(MACpaddedLength);

                uint8_t MAC_value[16];

                uint8_t firstSliceLength = encryptedLengthMAC - 16;


                for (int i = firstSliceLength ; i < encryptedLengthMAC; i++) {
                  MAC_value[i - firstSliceLength ] = ciphertextMACLong[i];
                  Serial.print(ciphertextMACLong[i], HEX);
                }

                Serial.println();
                uint8_t apduOpcLength = sizeof(opcApduHeader) + sizeof(MAC_value) + cipherLength;
                uint8_t sendApduOpc[apduOpcLength];
                char * buff_send_apdu = sendApduOpc;

                memcpy(buff_send_apdu, opcApduHeader, sizeof(opcApduHeader));
                buff_send_apdu += sizeof(opcApduHeader);
                memcpy(buff_send_apdu, MAC_value,   sizeof(MAC_value));
                buff_send_apdu += sizeof(MAC_value);
                memcpy(buff_send_apdu, ciphertextOPC,  cipherLength);


                uint8_t res_send_opc[255];
                uint8_t sendOpcResLength = sizeof(res_send_opc);



                Serial.println("send APDU");

                for (int i = 0 ; i < sizeof(sendApduOpc); i++) {
                  Serial.print(sendApduOpc[i], HEX);
                }
                Serial.println();



                success =  nfc.inDataExchange(sendApduOpc, sizeof(sendApduOpc), res_send_opc, &sendOpcResLength);

                if (success) {

                  Serial.print("responseLength: ");
                  Serial.println(sendOpcResLength);
                  Serial.println("Second Open Secure Channel response");
                  nfc.PrintHexChar(res_send_opc, sendOpcResLength);


                  memcpy(ivKey, res_send_opc, 16);
       //           resetCard();
//                  LoadSeed();
     //           changePairingKey();
//                  VerifyPin();
//                  derive();
//                  getCardInfo();
//                  getPubKey();
//                  signWithPin();
//                  resetCard();
changePin();
changePuk();


                }
              }
              else
              {
                Serial.println("shared secret failed");
              }

            }

          }

        }

      }

    }

  }
  else
  {

    Serial.println("Didn't find anything!");
  }

  delay(1000);
}

void LoadSeed() {
  uint8_t data[] = {0X2, 0X47, 0XB4, 0XE8, 0X7F, 0XE8, 0X27, 0X5B, 0XFE, 0X70, 0XD2, 0XA9, 0X81, 0XC4, 0XB1, 0X34, 0XC5, 0X39, 0X79, 0XF, 0XB4, 0X78, 0X58, 0XB0, 0XCC, 0XF9, 0X1, 0XAA, 0X60, 0X94, 0X60, 0XB5, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
  uint8_t apdu[] = {0x80, 0xD0, 0x03, 0x00};
  aes_cbc_encrypt(apdu, sizeof(apdu), data, sizeof(data), "Load Seed ");
}

void VerifyPin() {
  uint8_t data[] = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
  uint8_t apdu[] = {0x80, 0x20, 0x00, 0x00};
  aes_cbc_encrypt(apdu, sizeof(apdu), data, sizeof(data), "Verify Pin ");
}

void derive() {
  uint8_t data[] = {0X80, 0X0, 0X0, 0X2C, 0X80, 0X0, 0X0, 0X3C, 0X80, 0X0, 0X0, 0X0, 0X0, 0X0, 0X0, 0X0, 0X0, 0X0, 0X0, 0X0};
  uint8_t apdu[] = {0x80, 0xD1, 0x08, 0x00};
  aes_cbc_encrypt(apdu, sizeof(apdu), data, sizeof(data), "derive ");
}

void getCardInfo() {
  uint8_t data[] = {0};
  uint8_t apdu[] = {0x80, 0xFA, 0x00, 0x00};
  aes_cbc_encrypt(apdu, sizeof(apdu), data, sizeof(data), "card info ");
}

void getPubKey() {
  uint8_t data[] = {0};
  uint8_t apdu[] = {0x80, 0xC2, 0x00, 0x00};
  aes_cbc_encrypt(apdu, sizeof(apdu), data, sizeof(data), "get pub key ");
}

void signWithPin() {
  uint8_t data[] = {0X2, 0X47, 0XB4, 0XE8, 0X7F, 0XE8, 0X27, 0X5B, 0XFE, 0X70, 0XD2, 0XA9, 0X81, 0XC4, 0XB1, 0X34, 0XC5, 0X39, 0X79, 0XF, 0XB4, 0X78, 0X58, 0XB0, 0XCC, 0XF9, 0X1, 0XAA, 0X60, 0X94, 0X60, 0XB5, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
  uint8_t apdu[] = {0x80, 0xC0, 0x00, 0x00};
  aes_cbc_encrypt(apdu, sizeof(apdu), data, sizeof(data), "Sign with Pin ");
}

void changePairingKey() {
  uint8_t data[] = {0X43, 0X72, 0X79, 0X70, 0X74, 0X6E, 0X6F, 0X78, 0X20, 0X42, 0X61, 0X73, 0X69, 0X63, 0X20, 0X43, 0X6F, 0X6D, 0X6D, 0X6F, 0X6E, 0X50, 0X61, 0X69, 0X72, 0X69, 0X6E, 0X67, 0X44, 0X61, 0X74, 0X61, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
  uint8_t apdu[] = {0x80, 0xDA, 0x00, 0x00};
  aes_cbc_encrypt(apdu, sizeof(apdu), data, sizeof(data), "Change Pairing Key");
}

void resetCard() {
  uint8_t data[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
  uint8_t apdu[] = {0x80, 0xFD, 0x00, 0x00};
  aes_cbc_encrypt(apdu, sizeof(apdu), data, sizeof(data), "Reset Card");
}

void changePin(){
   uint8_t data[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
  uint8_t apdu[] = {0x80, 0x21, 0x00, 0x00};
  aes_cbc_encrypt(apdu, sizeof(apdu), data, sizeof(data), "Change Pin");
}

void changePuk(){
   uint8_t data[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
  uint8_t apdu[] = {0x80, 0x21, 0x01, 0x00};
  aes_cbc_encrypt(apdu, sizeof(apdu), data, sizeof(data), "Change Puk");
}


void setupNFC()
{

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata)
  {
    Serial.print("Didn't find PN53x board");
    while (1)
      ; // halt
  }

  Serial.print("Found chip PN5");
  Serial.println((versiondata >> 24) & 0xFF, HEX);
  Serial.print("Firmware ver. ");
  Serial.print((versiondata >> 16) & 0xFF, DEC);
  Serial.print('.');
  Serial.println((versiondata >> 8) & 0xFF, DEC);

  nfc.SAMConfig();
}

void getKeysECC(uint8_t * cardCertResponse, uint8_t *secret, uint8_t *public1, uint8_t *cardCert)
{
  uECC_set_rng(&RNG);

  const struct uECC_Curve_t *curve = uECC_secp256r1();
  uint8_t private1[32];
  uint8_t cardCertPublicKey[64];
  bool eccSuccess;
  bool eccSharedSuccess;

  eccSuccess = uECC_make_key(public1, private1, curve);

  if (eccSuccess)
  {
    Serial.println("private key --------- ");
    for (uint8_t i = 0; i < 32; i++)
    {
      Serial.print(private1[i], HEX);
    }
    Serial.println();
    Serial.println("public key --------- ");
    for (uint8_t i = 0; i < 64; i++)
    {
      Serial.print(public1[i], HEX);
    }
    Serial.println();

    uint8_t public2[64];


    getSessionPublicKey(cardCertResponse, cardCertPublicKey, cardCert);

    for (int i = 0; i < sizeof(cardCertPublicKey); i++) {
      Serial.print(cardCertPublicKey[i], HEX);
      Serial.print(" ");
    }
    Serial.println();
    eccSharedSuccess = uECC_shared_secret(cardCertPublicKey, private1, secret, curve);
    if (eccSharedSuccess)
    {
      Serial.println("shared secret response : ");

      Serial.println();

    }
    else
    {
      Serial.println("failed");
    }
  }
}

void getSessionPublicKey(uint8_t *cardCertResponse, uint8_t *cardCertPublicKey, uint8_t *cardCert)
{

  String respBuffer;
  for (int i = 10; i < 74; i++)
  {

    if (cardCertResponse[i] < 0x10)
      respBuffer = respBuffer + "0";

    respBuffer = respBuffer + String(cardCertResponse[i], HEX) + " ";

    cardCertPublicKey[i - 10] = cardCertResponse[i], HEX;
    cardCert[i - 10] = cardCertResponse[i], HEX;
  }

  Serial.print("responseCardCert");
  Serial.println(respBuffer);

}


void aes_cbc_encrypt(const uint8_t apdu[], uint16_t apduLength, const uint8_t data[], uint16_t dataLength, String commandName) {

  unsigned char encryptedData[2 * INPUT_BUFFER_LIMIT] = {0};


  uint16_t encryptedLength = aesLib.encrypt((byte*)data , dataLength, encryptedData, aesKey, sizeof(aesKey), ivKey);


  uint8_t macApdu[] = {encryptedLength + 16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint16_t macDataLength = apduLength + sizeof(macApdu) + encryptedLength;
  uint8_t macData[macDataLength];
  char * buffMacData = macData;
  memcpy(buffMacData, apdu, apduLength);
  buffMacData += apduLength;
  memcpy(buffMacData, macApdu, sizeof(macApdu));
  buffMacData += sizeof(macApdu);
  memcpy(buffMacData, encryptedData, encryptedLength);


  unsigned char macEncryptedData[2 * INPUT_BUFFER_LIMIT] = {0};
  uint8_t  macIv[N_BLOCK] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint16_t macEncryptedLength = aesLib_without_padding.encrypt((byte*)macData , macDataLength, macEncryptedData[], macKey, sizeof(macKey), macIv);

  uint8_t firstSliceEncryptedLength = macEncryptedLength - 16;
  uint8_t macValue[16];
  for (int i = firstSliceEncryptedLength; i < macEncryptedLength; i++) {
    macValue[i - firstSliceEncryptedLength] = macEncryptedData[i];
  }

  uint8_t lengthValue[] = {encryptedLength + 16};
  uint16_t sendApduLength = apduLength + sizeof(lengthValue) + sizeof(macValue) + encryptedLength;

  uint8_t sendApdu[sendApduLength];
  char * buffApdu = sendApdu;
  memcpy(buffApdu, apdu, apduLength);
  buffApdu += apduLength;
  memcpy(buffApdu, lengthValue, sizeof(lengthValue));
  buffApdu += sizeof(lengthValue);
  memcpy(buffApdu, macValue, sizeof(macValue));
  buffApdu += sizeof(macValue);
  memcpy(buffApdu, encryptedData, encryptedLength);

  Serial.println(sizeof(sendApdu));
  Serial.println(" Apdu " + commandName);
  for (int i = 0; i < sizeof(sendApdu) ; i++) {
    Serial.print(sendApdu[i], HEX);
    Serial.print(" ");
  }
  Serial.println();


  sendApduCommand(sendApdu, sendApduLength, commandName);

}

void sendApduCommand(const uint8_t sendApdu[], uint16_t sendApduLength, String commandName) {
  uint8_t response[255];
  uint8_t responseLength = sizeof(response);

  success =  nfc.inDataExchange(sendApdu, sendApduLength, response, &responseLength);
  if (success) {
    Serial.print("responseLength: ");
    Serial.println(responseLength);
    Serial.println("sending Apdu response " + commandName);
    nfc.PrintHexChar(response, responseLength);
    memcpy(ivKey, response, 16);
    Serial.println();
  } else {
    Serial.println("sending Apdu Failed");
  }

}
