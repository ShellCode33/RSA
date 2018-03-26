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
 * Created by shellcode on 10/30/17.
 */
class RSA {

    private int mKeySize;
    private BigInteger mPublicKey = null;
    private BigInteger mPrivateKey = null;
    private BigInteger mMod = null;


    RSA(int key_size) {
        if (key_size != 512 && key_size != 1024 && key_size != 2048 && key_size != 4096)
            throw new IllegalArgumentException("Supported key size : 512, 1024, 2048, 4096");

        mKeySize = key_size;
    }

    void generateKeys() {

        System.out.println("Generating " + mKeySize + " bits keys...");

        SecureRandom random = new SecureRandom();

        //On divise la taille voulue de la clé par 2 afin d'avoir un n qui sera sur le nb de bits voulu.
        BigInteger p = new BigInteger(mKeySize / 2, 100, random);
        BigInteger q = new BigInteger(mKeySize / 2, 100, random);

        mMod = p.multiply(q);

        BigInteger phi_n = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // phi(n) = (p-1)(q-1)

        BigInteger e;

        do {
            e = new BigInteger(mKeySize - 1, random);   //On génère une exposant aléatoire
        } while (!e.gcd(phi_n).equals(BigInteger.ONE)); //Tant que le nombre n'est pas premier avec phi_n, on en génère un nouveau

        BigInteger d = e.modInverse(phi_n); //Notre clé privée est le coupe (e^-1[phi_n], mMOd)
/*
        System.out.println("p = " + p.toString() + "\n");
        System.out.println("q = " + q.toString() + "\n");
        System.out.println("phi(n) = " + phi_n.toString() + "\n");
        System.out.println("e = " + e.toString() + "\n");
        System.out.println("d = " + d.toString() + "\n");
        System.out.println("private_key size : " + d.bitLength());
        System.out.println("public_key size : " + e.bitLength());
        System.out.println("mod size : " + mMod.bitLength());
*/
        mPublicKey = e;
        mPrivateKey = d;

        System.out.println("Generation completed !\n");

    }

    BigInteger getPrivateKey() {
        return mPrivateKey;
    }

    void setPublicKey(String b64PublicKey) {
        mPublicKey = new BigInteger(Base64.getDecoder().decode(b64PublicKey));
    }

    void setPrivateKey(String b64PrivateKey) {
        mPrivateKey = new BigInteger(Base64.getDecoder().decode(b64PrivateKey));
    }

    void setKeySize(int size) {
        mKeySize = size;
    }

    void setModulus(String b64Modulus) {
        mMod = new BigInteger(Base64.getDecoder().decode(b64Modulus));
    }

    String getFormatedPrivateKey() {

        return "<PrivateKey>\n" +
                "    <Exponent>" +
                Base64.getEncoder().encodeToString(mPrivateKey.toByteArray()) +
                "</Exponent>\n" +

                "    <Modulus>" +
                Base64.getEncoder().encodeToString(mMod.toByteArray()) +
                "</Modulus>\n" +
                "</PrivateKey>";
    }

    BigInteger getPublicKey() {
        return mPublicKey;
    }

    String getFormatedPublicKey() {
        return "<PublicKey>\n" +
                "    <Exponent>" +
                Base64.getEncoder().encodeToString(mPublicKey.toByteArray()) +
                "</Exponent>\n" +

                "    <Modulus>" +
                Base64.getEncoder().encodeToString(mMod.toByteArray()) +
                "</Modulus>\n" +
                "</PublicKey>";
    }

    void savePrivateKeyToFile(String path) {
        saveToFile(path, getFormatedPrivateKey());
    }

    void savePublicKeyToFile(String path) {
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

    BigInteger getMod() {
        return mMod;
    }

    String encode(String message, BigInteger public_key, BigInteger mod) {
        if (message == null || public_key == null || mod == null)
            throw new InvalidParameterException("parameters can't be null");

        byte msg_bytes[] = null;

        try {
            message = Normalizer.normalize(message, Normalizer.Form.NFD); //fix bug d'accents
            msg_bytes = message.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return encode(msg_bytes, public_key, mod);
    }

    //retourne de la base 64
    String encode(byte[] msg_bytes, BigInteger public_key, BigInteger mod) {

        if (msg_bytes == null || public_key == null || mod == null)
            throw new InvalidParameterException("parameters can't be null");

        //On définit la taille d'un block en fonction de la taille de p et de q.
        //Le message M doit être premier avec le modulo N. Pour s'en assurer, on fait en sorte que le message soit plus petit que p et q,
        // de cette manière, on est sûrs que M et N seront premiers entre eux (vu que N = p * q avec p et q premiers)
        int block_size = mKeySize / 2 - 1; //p et q sont sur mKeySize/2 bits, donc on prend la valeur juste en dessous --->  -1

        //Mais il faut que la taille du bloc soit divisible par 8 afin de pouvoir passer de bits à octets (et inversement) sans problème.
        while(block_size % 8 != 0)
            block_size--;

        //System.out.println("Un bloc doit faire " + block_size + " bits");
        //System.out.println("Le message fait " + msg_bytes.length + " octets, donc " + msg_bytes.length*8 + " bits");

        int nb_sub_messages = (int) Math.ceil((float)msg_bytes.length / (block_size / 8));
        //System.out.println("Il y aura " + nb_sub_messages + " blocs");

        byte[][] blocks = new byte[nb_sub_messages][];

        int copied_bytes = 0;
        int i = 0;
        for (; i < nb_sub_messages - 1; i++) { //On chiffre chaque block
            //System.out.println("Bloc n°" + (i+1));

            byte[] msg_block = Arrays.copyOfRange(msg_bytes, i * block_size / 8, (i + 1) * block_size / 8);
            //System.out.println("Encode : " + new String(msg_block));
            //System.out.println("msg_block size : " + msg_block.length);
            copied_bytes += msg_block.length;

            BigInteger message_integer = new BigInteger(msg_block);
            BigInteger cipher = message_integer.modPow(public_key, mod); //On chiffre le bloc
            byte[] cipher_bytes = cipher.toByteArray();

            byte[] block = new byte[mKeySize / 8 + 1]; //Parfois toByteArray() ajoute un bit de signe (et donc un octet) il faut donc faire +1 car l'array peut faire 1 octet de plus que la taille du modulo

            int block_index = block.length - 1;
            for (int j = cipher_bytes.length - 1; j >= 0; j--)
                block[block_index--] = cipher_bytes[j];

            //System.out.println("encoded : " + Arrays.toString(block));

            blocks[i] = block;
        }

        //System.out.println("" + copied_bytes + " octets copiés.");

        //On s'occupe du dernier bloc qui va jusqu'à la fin
        if (msg_bytes.length - copied_bytes > 0) {
            byte[] msg_block = Arrays.copyOfRange(msg_bytes, copied_bytes, msg_bytes.length);
//            System.out.println("encode block : " + Arrays.toString(msg_block));
//            System.out.println("Encrypted bytes count : " + msg_block.length);
            BigInteger message_integer = new BigInteger(msg_block);
            BigInteger cipher = message_integer.modPow(public_key, mod);
            byte[] cipher_bytes = cipher.toByteArray();

            //System.out.println("cipher_bytes : " + Arrays.toString(cipher_bytes));

            //System.out.println("Cipher size : " + cipher_bytes.length + "+1");
            byte[] block = new byte[mKeySize / 8 + 1]; //Parfois toByteArray() ajoute un bit de signe (et donc un octet) il faut donc faire +1 car l'array peut faire 1 octet de plus que la taille du modulo

            int block_index = block.length - 1;
            for (int j = cipher_bytes.length - 1; j >= 0; j--)
                block[block_index--] = cipher_bytes[j];

            blocks[i] = block;
        }

        byte[] inline_blocks = new byte[nb_sub_messages * (mKeySize / 8 + 1)];

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

    String decodeToString(String b64, BigInteger private_key, BigInteger mod) {
        try {
            return new String(decode(b64, private_key, mod), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    byte[] decode(String b64, BigInteger private_key, BigInteger mod) {

        if (b64 == null || private_key == null || mod == null)
            throw new InvalidParameterException("parameters can't be null");

        byte cipher[];
        try {
            cipher = Base64.getDecoder().decode(b64.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }

        int nb_blocks = cipher.length / (mKeySize/8+1); //Le fameux +1 pour résoudre le bug étrange
        //System.out.println("Il y a " + nb_blocks + " blocs");

        byte[][] blocks = new byte[nb_blocks][];
        int total_blocks_size = 0;

        int index = 0;
        for (int i = 0; i < nb_blocks; i++) {

            byte[] cipher_bytes = Arrays.copyOfRange(cipher, i * (mKeySize / 8 + 1), (i + 1) * (mKeySize / 8 + 1));//Le fameux +1 pour le bit de signe

            //System.out.println("[DECRYPT] Block size : " + cipher_bytes.length);

            byte[] decrypted_bytes = new BigInteger(cipher_bytes).modPow(private_key, mod).toByteArray();

            //.out.println("decrypted_bytes size : " + decrypted_bytes.length);
            //System.out.println("decrypted : " + new String(decrypted_bytes));

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

    String sign(String b64Cipher, String hashAlgorithm, BigInteger private_key, BigInteger mod) {

        String cipherHash = Base64.getEncoder().encodeToString(hash(Base64.getDecoder().decode(b64Cipher), hashAlgorithm));
        System.out.println("created hash : " + cipherHash);

        String result = encode(b64Cipher + ":" + cipherHash, private_key, mod);

        return result; //we use the private key as a key in order to sign the message
    }

    //retourne de la base 64
    String checkSignatureAndReturnUnsigned(String b64Cipher, String hashAlgorithm, BigInteger public_key, BigInteger mod) throws InvalidSignatureValueException {

        System.out.println("checking signature...");
        String content = decodeToString(b64Cipher, public_key, mod); //we use the key to unsign
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

    byte[] hash(byte[] bytes, String algo) {
        byte[] hash = null;

        try {
            hash = MessageDigest.getInstance(algo).digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return hash;
    }

    static String[] getSupportedHashAlgorithms() {
        return new String[]{"MD5", "SHA-1", "SHA-256", "SHA-512"};
    }

    static Integer[] getSupportedKeySize() {
        return new Integer[]{512, 1024, 2048, 4096};
    }
}
