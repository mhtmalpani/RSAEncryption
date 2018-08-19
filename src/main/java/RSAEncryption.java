import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAEncryption {

    //Prime 1
    private BigInteger primeNumberOne;

    //Prime 2
    private BigInteger primeNumberTwo;

    //Modulus
    private BigInteger modulus;

    //Totient: Phi(modulus)
    private BigInteger totient;

    //Public Key Exponent
    private BigInteger publicKey;

    //Private Key Exponent
    private BigInteger privateKey;

    //Bit Length
    private int bitLength;

    private SecureRandom secureRandom;


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          Constructors                                               //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Default Constructor with default value settings
     */
    public RSAEncryption() {
        //Default Bit Length
        this(512);
    }

    /**
     * Overload Constructor
     *
     * @param bitLength user specified computation bitlength
     */
    public RSAEncryption(int bitLength) {
        this.bitLength = bitLength;

        secureRandom = new SecureRandom();

        prepareAlgorithmDependencies();
    }

    /**
     * Overload Constructor
     * Pass the Public key
     * <primeNumberOne>
     * Should only use the Encryption when this constructor is used
     *
     * @param modulus   Modulus provided for computation
     * @param publicKey Public Key  for computation
     */
    public RSAEncryption(String modulus, String publicKey) {
        this.modulus = new BigInteger(modulus);
        this.publicKey = new BigInteger(publicKey);
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       Algorithm Helper                                              //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////


    /**
     * Prepares the steps related to generation of Keys to set up
     * the Encryption and Decryption environment
     */
    private void prepareAlgorithmDependencies() {
        generatePrimes();
        generateModulus();
        generateTotient();
        generateInitialPublicKey();
        generatePublicKey();
        generatePrivateKey();
    }

    /**
     * Generates the primes
     * primeNumberOne and primeNumberTwo
     */
    private void generatePrimes() {
        primeNumberOne = new BigInteger(bitLength / 2, 100, secureRandom);
        primeNumberTwo = new BigInteger(bitLength / 2, 100, secureRandom);
    }

    /**
     * Generates the modulus N:
     * modulus = primeNumberOne * primeNumberTwo
     */
    private void generateModulus() {
        modulus = primeNumberOne.multiply(primeNumberTwo);
    }

    /**
     * Generates the Totient totient
     * totient = (primeNumberOne - 1) * (primeNumberTwo - 1)
     */
    private void generateTotient() {
        totient = (primeNumberOne.subtract(BigInteger.ONE)).multiply(primeNumberTwo.subtract(BigInteger.ONE));
    }

    /**
     * Generates the initial public key
     */
    private void generateInitialPublicKey() {
        this.publicKey = new BigInteger(bitLength, 100, secureRandom);
    }


    /**
     * Generates the Public Key
     * 1 < publicKey < totient, such that
     * publicKey and totient are co-prime
     * publicKey is an odd number
     */
    private void generatePublicKey() {
        while (totient.gcd(publicKey).intValue() > 1) {
            publicKey = publicKey.add(new BigInteger("2"));
        }
    }

    /**
     * Generates the Private Key
     * de ~ 1 ( mod totient )
     * de = 1 + k*totient
     * where k is any integer
     */
    private void generatePrivateKey() {
        privateKey = publicKey.modInverse(totient);
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              Encryption                                             //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////


    /**
     * Encrypts the given plaintext message
     *
     * @param message the data to be encrypted as String
     * @return CipherText as String
     */
    public synchronized String encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(publicKey, modulus).toString();
    }

    /**
     * Encrypts the given plaintext message
     *
     * @param message the data to be encrypted as BigInteger (message in bytes)
     * @return CipherText as bytes
     */
    public synchronized BigInteger encrypt(BigInteger message) {
        return message.modPow(publicKey, modulus);
    }


    /**
     * Encrypts the given CipherText message
     *
     * @param message   the encrypted CipherText to be decrypted as String
     * @param modulus   modulus
     * @param publicKey Public Key (publicKey)
     * @return CipherText as String
     */
    public synchronized String encrypt(String message, String modulus, String publicKey) {
        this.publicKey = new BigInteger(publicKey);
        this.modulus = new BigInteger(modulus);
        return (new BigInteger(message.getBytes())).modPow(this.publicKey, this.modulus).toString();
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              Decryption                                             //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////


    /**
     * Decrypts the given CipherText message
     *
     * @param cipherText the encrypted CipherText to be decrypted as String
     * @return Actual Message contained in the CipherText as String
     */
    public synchronized String decrypt(String cipherText) {
        return new String((new BigInteger(cipherText)).modPow(privateKey, modulus).toByteArray());
    }

    /**
     * Decrypts the given CipherText message
     *
     * @param cipherText the encrypted CipherText to be decrypted as BigInteger (cipherText in bytes)
     * @return Actual Message contained in the CipherText as bytes
     */
    public synchronized BigInteger decrypt(BigInteger cipherText) {
        return cipherText.modPow(privateKey, modulus);
    }


    /**
     * Decrypts the given CipherText message
     *
     * @param cipherText the encrypted CipherText to be decrypted as String
     * @param modulus    modulus
     * @param privateKey Private Key (privateKey)
     * @return Decrypted Message as String
     */
    public synchronized String decrypt(String cipherText, String modulus, String privateKey) {
        this.privateKey = new BigInteger(privateKey);
        this.modulus = new BigInteger(modulus);
        return new String((new BigInteger(cipherText)).modPow(this.privateKey, this.modulus).toByteArray());
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              Getters                                                //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    public BigInteger getPrimeNumberOne() {
        return primeNumberOne;
    }

    public BigInteger getPrimeNumberTwo() {
        return primeNumberTwo;
    }

    public String getModulus() {
        return String.valueOf(modulus);
    }

    public BigInteger getTotient() {
        return totient;
    }

    public String getPublicKey() {
        return String.valueOf(publicKey);
    }

    public String getPrivateKey() {
        return String.valueOf(privateKey);
    }

    public int getBitLength() {
        return bitLength;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              Setters                                                //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////


    public void setPrimeNumberOne(BigInteger primeNumberOne) {
        this.primeNumberOne = primeNumberOne;
    }

    public void setPrimeNumberTwo(BigInteger primeNumberTwo) {
        this.primeNumberTwo = primeNumberTwo;
    }

    public void setModulus(String n) {
        this.modulus = new BigInteger(n);
    }

    public void setPublicKey(String e) {
        this.publicKey = new BigInteger(e);
    }

    public void setPrivateKey(String d) {
        this.privateKey = new BigInteger(d);
    }

    public void setBitLength(int bitLength) {
        this.bitLength = bitLength;
    }
}
