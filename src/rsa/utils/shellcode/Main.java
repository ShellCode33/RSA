package rsa.utils.shellcode;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by shellcode on 2/10/17.
 */
public class Main {
    public static void main(String [] args) {

        RSA rsa = new RSA(2048);
        rsa.generateKeys();

        String msg = "Bonsoir comment allez-vous ?";
        String cipher_b64 = rsa.encode(msg, rsa.getPublicKey(), rsa.getMod());
        System.out.println("cipher : " + cipher_b64);
        System.out.println("plaintext : " + rsa.decode(cipher_b64, rsa.getPrivateKey(), rsa.getMod()));

        System.out.println("\n\n" + rsa.getFormatedPublicKey());
        System.out.println("\n\n" + rsa.getFormatedPrivateKey());
    }
}
