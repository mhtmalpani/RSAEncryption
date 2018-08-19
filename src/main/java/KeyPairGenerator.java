import java.math.BigInteger;
import java.security.SecureRandom;

public class KeyPairGenerator {

    //Prime 1
    private BigInteger p;

    //Prime 2
    private BigInteger q;

    //Modulus
    private BigInteger n;

    //Totient: Phi(n)
    private BigInteger m;

    //Public Key Exponent
    private BigInteger e;

    //Private Key Exponent
    private BigInteger d;

    //Bit Length
    private int bitLength;

    private SecureRandom secureRandom;


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          Constructors                                               //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Default Constructor with default value settings
     */
    public KeyPairGenerator() {
        //Default Bit Length
        this(512);
    }

    /**
     * Overload Constructor
     *
     * @param bitLength user specified computation bitlength
     */
    public KeyPairGenerator(int bitLength) {
        this.bitLength = bitLength;

        secureRandom = new SecureRandom();

        prepareAlgorithmDependencies();
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       Algorithm Helper                                              //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////


    /**
     * Prepares the steps related to generation of Keys to set up
     * the Encryption and Decryption environment
     */
    private void prepareAlgorithmDependencies() {
        generateE();
        generatePrimes();
        generateModulus();
        generateTotient();
        generatePublicKey();
        generatePrivateKey();
    }

    /**
     * Generates the E (Public key exponent)
     */
    private void generateE() {
        this.e = new BigInteger(bitLength, 100, secureRandom);
    }

    /**
     * Generates the primes
     * p and q
     */
    private void generatePrimes() {
        p = new BigInteger(bitLength / 2, 100, secureRandom);
        q = new BigInteger(bitLength / 2, 100, secureRandom);
    }

    /**
     * Generates the modulus N:
     * n = p * q
     */
    private void generateModulus() {
        n = p.multiply(q);
    }

    /**
     * Generates the Totient m
     * m = (p - 1) * (q - 1)
     */
    private void generateTotient() {
        m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
    }

    /**
     * Generates the Public Key
     * 1 < e < m, such that
     * e and m are co-prime
     * e is an odd number
     */
    private void generatePublicKey() {
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
    }

    /**
     * Generates the Private Key
     * de ~ 1 ( mod m )
     * de = 1 + k*m
     * where k is any integer
     */
    private void generatePrivateKey() {
        d = e.modInverse(m);
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              Getters                                                //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    public String getModulus() {
        return String.valueOf(n);
    }

    public String getPublicKey() {
        return String.valueOf(e);
    }

    public String getPrivateKey() {
        return String.valueOf(d);
    }
}
