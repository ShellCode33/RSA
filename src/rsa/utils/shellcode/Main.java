package rsa.utils.shellcode;

/**
 * Created by shellcode on 10/30/17.
 */
public class Main {
    public static void main(String [] args) {

        RSA rsa = new RSA(4096);
        rsa.generateKeys();

        String msg = "RSA (Rivest–Shamir–Adleman) is one of the first practical public-key cryptosystems and is widely used for secure data transmission. In such a cryptosystem, the encryption key is public and it is different from the decryption key which is kept secret (private). In RSA, this asymmetry is based on the practical difficulty of the factorization of the product of two large prime numbers, the \"factoring problem\". The acronym RSA is made of the initial letters of the surnames of Ron Rivest, Adi Shamir, and Leonard Adleman, who first publicly described the algorithm in 1978. Clifford Cocks, an English mathematician working for the British intelligence agency Government Communications Headquarters (GCHQ), had developed an equivalent system in 1973, but this was not declassified until 1997. A user of RSA creates and then publishes a public key based on two large prime numbers, along with an auxiliary value. The prime numbers must be kept secret. Anyone can use the public key to encrypt a message, but with currently published methods, and if the public key is large enough, only someone with knowledge of the prime numbers can decode the message feasibly. Breaking RSA encryption is known as the RSA problem. Whether it is as difficult as the factoring problem remains an open question. RSA is a relatively slow algorithm, and because of this, it is less commonly used to directly encrypt user data. More often, RSA passes encrypted shared keys for symmetric key cryptography which in turn can perform bulk encryption-decryption operations at much higher speed.";

        System.out.println("Encrypting string which is " + msg.length() + " characters long.");

        String cipher_b64 = rsa.encode(msg, rsa.getPublicKey(), rsa.getMod());
        System.out.println("cipher : " + cipher_b64);
        String decrypted_msg = rsa.decodeToString(cipher_b64, rsa.getPrivateKey(), rsa.getMod());
        System.out.println("plaintext : " + decrypted_msg);

        if(msg.equals(decrypted_msg)) {
            System.out.println("RSA is working !!");
        }

        else {
            System.out.println("Oops, something went wrong !");
        }

        System.out.println("\n\n" + rsa.getFormatedPublicKey());
        System.out.println("\n\n" + rsa.getFormatedPrivateKey());

    }
}
