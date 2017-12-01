import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Main
{
    public static void main (String [] args)
    {
        Signature d = new Signature();
        System.out.println(d.genPrivKey().toString());
    }

    /*El Gamal key pair
    //generate x
    x 1 < x < p-1
    //generate y
    y = g^x(mod p)
    */


    /* Signing message
    ** choose random k 0 < k < p-1 and gcd(k,p-1) = 1
    *  r = g^k(mod p)
    *
    *  compute s = (H-sha-256(m)-xr)k^-1(mod p-1)
    *  if s = 0 start again
     */

    /*
     *  gcd algo
     */
}

class Signature
{
    private String hexPrimeMod = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
    private String hexGenerator = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
    private BigInteger primeMod = new BigInteger(hexPrimeMod, 16);
    private BigInteger generator = new BigInteger(hexGenerator, 16);
    private Random RANDOM = new SecureRandom();

    private BigInteger privKey = genPrivKey();
    private BigInteger pubKey = genPubKey();

    // 1 < x < p-1
    public BigInteger genPrivKey()
    {
        BigInteger randomX = new BigInteger(primeMod.bitLength(), RANDOM);
        while (randomX.compareTo(primeMod) == 1 || (randomX.compareTo(BigInteger.ONE)) < 1)
        {
            randomX = new BigInteger(primeMod.bitLength(), RANDOM);
        }
        return randomX;
    }

    //y = g^x(mod p)
    public BigInteger genPubKey()
    {
        return generator.modPow(privKey, primeMod);
    }



}