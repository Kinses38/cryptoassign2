import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

public class Main
{
    public static void main (String [] args)
    {
        String p = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
        String g = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";

        Signature sign = new Signature(p, g);


    }
}

class Signature
{
    private BigInteger primeMod;
    private BigInteger pMinusOne;
    private BigInteger generator;


    private Random RANDOM = new SecureRandom();

    private BigInteger privKey;
    private BigInteger pubKey;
    private BigInteger randK;
    private BigInteger randR;
    private BigInteger randS;

    private final File ZIPTOSIGN = new File("src.zip");

    Signature(String p, String g)
    {
        primeMod = new BigInteger(p, 16);
        pMinusOne = primeMod.subtract(BigInteger.ONE);
        generator = new BigInteger(g, 16);

        privKey = genPrivKey();
        pubKey = genPubKey();

        do
        {
           randK = genK();
           randR = genR();
           randS = genS();
        }while(randS.equals(BigInteger.ZERO));

        System.out.println("privKey: " + privKey.toString(16));
        System.out.println("pubKey: " + pubKey.toString(16));

        System.out.println("K: " + randK.toString(16));
        System.out.println("R: " + randR.toString(16));
        System.out.println("S: " + randS.toString(16));

        testSig();
    }


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

    public BigInteger getGCD(BigInteger a, BigInteger b)
    {
        if(b.equals(BigInteger.ZERO))
            return a;
        else
            return getGCD(b, a.mod(b));
    }

    //generate k, check if prime && < primeMod
    public BigInteger genK()
    {
        BigInteger randomK = new BigInteger(primeMod.bitLength(), 1, RANDOM);
        boolean goodK = false;
        while(!goodK)
        {
            randomK = new BigInteger(primeMod.bitLength(), 1, RANDOM);
            if(getGCD(randomK, pMinusOne).equals(BigInteger.ONE))
                if(randomK.compareTo(pMinusOne) == 1)
                    goodK = true;
        }
        return randomK;
    }

    public BigInteger genR()
    {
        return generator.modPow(randK, primeMod);
    }

    public byte [] hashFile()
    {
        try
        {
            int size = (int)ZIPTOSIGN.length();
            FileInputStream inputStream = new FileInputStream(ZIPTOSIGN);
            byte [] message = new byte[size];
            inputStream.read(message);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            message = digest.digest(message);

            inputStream.close();
            return message;
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }

    private BigInteger [] extGCD(BigInteger a, BigInteger b)
    {
        BigInteger[] results = new BigInteger[3];
        if(b.equals(BigInteger.ZERO))
        {
            results[0] = a;
            results[1] = BigInteger.ONE;
            results[2] = BigInteger.ZERO;
            return results;
        }

        results = extGCD(b, a.mod(b));
        BigInteger x = results[1];
        BigInteger y = results[2];
        results[1] = y;
        results[2] = x.subtract((a.divide(b)).multiply(y));

        return results;
    }

    private BigInteger genS()
    {
        //(hOfM-xr)k^-1 (mod p-1)
        BigInteger xr = privKey.multiply(randR);
        BigInteger hOfM = new BigInteger(hashFile());
        BigInteger inverse = extGCD(randK, pMinusOne)[1].mod(pMinusOne);

        BigInteger s = (hOfM.subtract(xr)).multiply(inverse).mod(pMinusOne);
        
        return s;
    }

    private void testSig()
    {
        if(randR.compareTo(BigInteger.ZERO) == 1 && randR.compareTo(primeMod) == -1)
            System.out.println("\n0 < R < P");
        if(randS.compareTo(BigInteger.ZERO) == 1 && randS.compareTo(pMinusOne) == -1)
            System.out.println("0 < S < P-1");

        //Lets just input the sha256 checksum here to check...oh wait..
        BigInteger hOfM = new BigInteger (hashFile());

        //g^h(m)(mod p) = ((y^r)(r^s))(mod p)
        BigInteger LHS = generator.modPow(hOfM, primeMod);
        BigInteger RHS = (pubKey.modPow(randR, primeMod)).multiply(randR.modPow(randS, primeMod)).mod(primeMod);
        if(LHS.equals(RHS))
            System.out.println("LHS == RHS");
    }

}