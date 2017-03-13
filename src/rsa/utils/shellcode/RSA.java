package rsa.utils.shellcode;


import com.sun.org.apache.xml.internal.security.signature.InvalidSignatureValueException;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Arrays;
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
        if (key_size != 512 && key_size != 1024 && key_size != 2048 && key_size != 4096)
            throw new IllegalArgumentException("Supported key size : 512, 1024, 2048, 4096");

        mKeySize = key_size;
    }

    public void generateKeys() {

        System.out.println("Generating keys...");

        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(mKeySize / 2 - 1, 100, random);
        BigInteger q = new BigInteger(mKeySize / 2 - 1, 100, random);
        mMod = p.multiply(q);

        BigInteger phi_n = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger e;

        do {
            e = new BigInteger(mKeySize - 1, random);
        } while (e.compareTo(BigInteger.ONE) != 1 || e.compareTo(phi_n) != -1 || !e.gcd(phi_n).equals(BigInteger.ONE));

        BigInteger d = e.modInverse(phi_n);

//        System.out.println("p = " + p.toString() + "\n");
//        System.out.println("q = " + q.toString() + "\n");
//        System.out.println("phi(n) = " + phi_n.toString() + "\n");
//        System.out.println("e = " + e.toString() + "\n");
//        System.out.println("d = " + d.toString() + "\n");

        System.out.println("private_key size : " + d.bitLength());
        System.out.println("public_key size : " + e.bitLength());
        System.out.println("mod size : " + mMod.bitLength());

        mPublicKey = e;
        mPrivateKey = d;

        System.out.println("Generation completed !\n");

    }

    public BigInteger getPrivateKey() {
        return mPrivateKey;
    }

    public void setPublicKey(String b64PublicKey) {
        mPublicKey = new BigInteger(Base64.getDecoder().decode(b64PublicKey));
    }

    public void setPrivateKey(String b64PrivateKey) {
        mPrivateKey = new BigInteger(Base64.getDecoder().decode(b64PrivateKey));
    }

    public void setKeySize(int size) {
        mKeySize = size;
    }

    public void setModulus(String b64Modulus) {
        mMod = new BigInteger(Base64.getDecoder().decode(b64Modulus));
    }

    public String getFormatedPrivateKey() {

        return "<PrivateKey>\n" +
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
        return "<PublicKey>\n" +
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
        } catch (FileNotFoundException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public BigInteger getMod() {
        return mMod;
    }

    public String encode(String message, BigInteger public_key, BigInteger mod) {
        if (message == null || public_key == null || mod == null)
            throw new InvalidParameterException("parameters can't be null");

        byte msg_bytes[] = null;

        try {
            message = Normalizer.normalize(message, Normalizer.Form.NFD); //fix bugs d'accents
            msg_bytes = message.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return encode(msg_bytes, public_key, mod);
    }

    //retourne de la base 64
    public String encode(byte[] msg_bytes, BigInteger public_key, BigInteger mod) {

        if (msg_bytes == null || public_key == null || mod == null)
            throw new InvalidParameterException("parameters can't be null");

        int block_size = mod.bitLength() / 8 - 2; //On définit la taille d'un block en fonction du modulo car  1 < m < n   (avec m = taille message et n = p * q = modulo)
        int nb_sub_messages = (int) Math.ceil((double) msg_bytes.length / block_size);

        byte[][] blocks = new byte[nb_sub_messages][];

        int copied_bytes = 0;
        int i = 0;
        for (; i < nb_sub_messages - 1; i++) {
            byte[] msg_block = Arrays.copyOfRange(msg_bytes, i * block_size, (i + 1) * block_size);
            copied_bytes += msg_block.length;

            BigInteger message_integer = new BigInteger(msg_block);
            BigInteger cipher = message_integer.modPow(public_key, mod);
            byte[] cipher_bytes = cipher.toByteArray();

            byte[] block = new byte[mKeySize / 8];

            int block_index = mKeySize / 8 - 1;
            for (int j = cipher_bytes.length - 1; j >= 0; j--)
                block[block_index--] = cipher_bytes[j];

            System.out.println("encoded : " + Arrays.toString(block));

            blocks[i] = block;
        }

        if (msg_bytes.length - copied_bytes > 0) {
            byte[] msg_block = Arrays.copyOfRange(msg_bytes, copied_bytes, msg_bytes.length);
//            System.out.println("encode block : " + Arrays.toString(msg_block));
//            System.out.println("Encrypted bytes count : " + msg_block.length);
            BigInteger message_integer = new BigInteger(msg_block);
            BigInteger cipher = message_integer.modPow(public_key, mod);
            byte[] cipher_bytes = cipher.toByteArray();
            byte[] block = new byte[mKeySize / 8];

            int block_index = mKeySize / 8 - 1;
            for (int j = cipher_bytes.length - 1; j >= 0; j--)
                block[block_index--] = cipher_bytes[j];

            blocks[i] = block;
        }

        byte[] inline_blocks = new byte[nb_sub_messages * mKeySize / 8];

        int index = 0;
        for (byte[] block : blocks) {
            for (i = 0; i < block.length; i++)
                inline_blocks[index++] = block[i];
        }

        try {
            return new String(Base64.getEncoder().encode(inline_blocks), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decodeToString(String b64, BigInteger private_key, BigInteger mod) {
        try {
            return new String(decode(b64, private_key, mod), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] decode(String b64, BigInteger private_key, BigInteger mod) {

        if (b64 == null || private_key == null || mod == null)
            throw new InvalidParameterException("parameters can't be null");

        byte cipher[];
        try {
            cipher = Base64.getDecoder().decode(b64.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }

        int nb_blocks = (cipher.length * 8) / mKeySize;

        byte[][] blocks = new byte[nb_blocks][];
        int total_blocks_size = 0;

        int index = 0;
        for (int i = 0; i < nb_blocks; i++) {

            byte[] cipher_bytes = Arrays.copyOfRange(cipher, i * mKeySize / 8, (i + 1) * mKeySize / 8);
            byte[] decrypted_bytes = new BigInteger(cipher_bytes).modPow(private_key, mod).toByteArray();

            System.out.println("decrypted_bytes size : " + decrypted_bytes.length);

            int padding_size = 0;
            while (decrypted_bytes[padding_size] == 0)
                padding_size++;

            if (padding_size > 0) {
                System.out.println("padding detected ! Removing it ;)");

                byte[] removed_padding = new byte[decrypted_bytes.length - padding_size];

                int remove_padding_index = 0;
                for (int j = padding_size; j < decrypted_bytes.length; j++)
                    removed_padding[remove_padding_index++] = decrypted_bytes[j];

                decrypted_bytes = removed_padding;
            }

            blocks[index++] = decrypted_bytes;
            total_blocks_size += decrypted_bytes.length;
        }

        byte[] inline_blocks = new byte[total_blocks_size];

        index = 0;
        for (byte[] block : blocks) {
            for (int i = 0; i < block.length; i++)
                inline_blocks[index++] = block[i];
        }

        return inline_blocks;
    }

    public String sign(String b64Cipher, String hashAlgorithm, BigInteger private_key, BigInteger mod) {

        String cipherHash = Base64.getEncoder().encodeToString(hash(Base64.getDecoder().decode(b64Cipher), hashAlgorithm));
        System.out.println("created hash : " + cipherHash);

        String result = encode(b64Cipher + ":" + cipherHash, private_key, mod);

        return result; //we use the private key as a public key in order to sign the message
    }

    //retourne de la base 64
    public String checkSignatureAndReturnUnsigned(String b64Cipher, String hashAlgorithm, BigInteger public_key, BigInteger mod) throws InvalidSignatureValueException {

        System.out.println("checking signature...");
        String content = decodeToString(b64Cipher, public_key, mod); //we use the public key to unsign
        String[] parts = content.split(":");

        if (parts.length != 2)
            throw new InvalidSignatureValueException("Wrong signature ! cipher had been intercepted/modified ???");

        String cipherB64 = parts[0];
        String hashCipherB64 = parts[1];

        System.out.println("cipher : " + Arrays.toString(Base64.getDecoder().decode(cipherB64)));
        System.out.println("read hashCipher : " + hashCipherB64);
        System.out.println("computed hashCipher : " + Base64.getEncoder().encodeToString(hash(Base64.getDecoder().decode(cipherB64), hashAlgorithm)));

        if (!Arrays.equals(Base64.getDecoder().decode(hashCipherB64), hash(Base64.getDecoder().decode(cipherB64), hashAlgorithm)))
            throw new InvalidSignatureValueException("Wrong signature ! cipher had been intercepted/modified ???");

        return cipherB64;
    }

    public byte[] hash(byte[] bytes, String algo) {
        byte[] hash = null;

        try {
            hash = MessageDigest.getInstance(algo).digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return hash;
    }

    public static String[] getSupportedHashAlgorithms() {
        return new String[]{"MD5", "SHA-1", "SHA-256", "SHA-512"};
    }

    public static Integer[] getSupportedKeySize() {
        return new Integer[]{512, 1024, 2048, 4096};
    }
}