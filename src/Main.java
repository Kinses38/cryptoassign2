import java.math.BigInteger;

public class Main
{
    public static void main (String [] args)
    {
        String hexPrimeMod;
        String hexGenerator;

        BigInteger primeMod;
        BigInteger generator;

        byte [] zip;

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

    // sign checker

}
