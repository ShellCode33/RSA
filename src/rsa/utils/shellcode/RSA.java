package rsa.utils.shellcode;


import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Created by shellcode on 2/10/17.
 */
public class RSA {

    int mKeySize;
    BigInteger mPublicKey = null;
    BigInteger mPrivateKey = null;
    BigInteger mMod = null;


    public RSA(int key_size) {
        if(key_size != 512 && key_size != 1024 && key_size != 2048 && key_size != 4096)
            throw new IllegalArgumentException("Supported key size : 512, 1024, 2048, 4096");

        mKeySize = key_size;
    }

    public void generateKeys() {

        System.out.println("Generating keys...");

        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(mKeySize / 2, 100, random);
        BigInteger q = new BigInteger(mKeySize / 2, 100, random);
        BigInteger one = new BigInteger("1");
        BigInteger phi_n = p.subtract(one).multiply(q.subtract(one));
        BigInteger e;

        do {
            e = new BigInteger(mKeySize / 2, random);
        }while(e.compareTo(one) <= 0 || !e.gcd(phi_n).equals(one));

        BigInteger d = e.modInverse(phi_n);

        System.out.println("p = " + p.toString() + "\n");
        System.out.println("q = " + q.toString() + "\n");
        System.out.println("phi(n) = " + phi_n.toString() + "\n");
        System.out.println("e = " + e.toString() + "\n");
        System.out.println("d = " + d.toString() + "\n");

        mMod = p.multiply(q);

        mPublicKey = e;
        mPrivateKey = d;

        System.out.println("Generation completed !\n");
    }

    public BigInteger getPrivateKey() {
        return mPrivateKey;
    }

    public String getFormatedPrivateKey() {

        return      "<PrivateKey>\n" +
                        "    <Exponent>" +
                            Base64.getEncoder().encodeToString(mPrivateKey.toByteArray()) +
                        "</Exponent>\n" +

                        "    <Modulus>" +
                            Base64.getEncoder().encodeToString(mMod.toByteArray()) +
                        "</Modulus>\n" +
                    "</PrivateKey>";
    }

    public BigInteger getPublicKey() {
        return mPublicKey;
    }

    public String getFormatedPublicKey() {
        return      "<PublicKey>\n" +
                        "    <Exponent>" +
                            Base64.getEncoder().encodeToString(mPublicKey.toByteArray()) +
                        "</Exponent>\n" +

                        "    <Modulus>" +
                            Base64.getEncoder().encodeToString(mMod.toByteArray()) +
                        "</Modulus>\n" +
                    "</PublicKey>";
    }

    public void savePrivateKeyToFile(String path) {
        saveToFile(path, getFormatedPrivateKey());
    }

    public void savePublicKeyToFile(String path) {
        saveToFile(path, getFormatedPublicKey());
    }

    private void saveToFile(String path, String content) {
        try {
            PrintWriter writer = new PrintWriter(path, "UTF-8");
            writer.print(content);
            writer.close();
        }

        catch (FileNotFoundException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public BigInteger getMod() {
        return mMod;
    }

    //retourne de la base 64
    public String encode(String message, BigInteger public_key, BigInteger mod) {

        if(message == null || public_key == null || mod == null)
            throw new InvalidParameterException("parameters can't be null");

        byte bytes[] = message.getBytes();

        if(bytes.length > mKeySize /8)
            throw new InvalidParameterException("The message can't be longer than " + mKeySize + " bits !"); //TODO : découper en plusieurs messages au lieu de lever une exception

        BigInteger message_integer = new BigInteger(bytes);
        BigInteger cipher = message_integer.modPow(public_key, mod);

        return Base64.getEncoder().encodeToString(cipher.toByteArray());
    }

    public String decode(String b64, BigInteger private_key, BigInteger mod) {

        if(b64 == null || private_key == null || mod == null)
            throw new InvalidParameterException("parameters can't be null");

        byte bytes[] = Base64.getDecoder().decode(b64);
        BigInteger cipher_integer = new BigInteger(bytes);

        return new String(cipher_integer.modPow(private_key, mod).toByteArray());
    }
}
