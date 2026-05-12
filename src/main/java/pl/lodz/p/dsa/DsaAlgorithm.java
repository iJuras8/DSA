package pl.lodz.p.dsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class DsaAlgorithm {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.TWO;
    private static final int PRIME_CERTAINTY = 80;

    private final SecureRandom random = new SecureRandom();

    public DsaParameters generateParameters(int pBits, int qBits) {
        if (pBits <= qBits || qBits < 128) {
            throw new IllegalArgumentException("Nieprawidlowe rozmiary parametrow DSA.");
        }

        while (true) {
            BigInteger q = BigInteger.probablePrime(qBits, random);
            BigInteger p = generateP(pBits, q);
            if (p != null) {
                BigInteger g = generateG(p, q);
                return new DsaParameters(p, q, g);
            }
        }
    }

    public DsaKeyPair generateKeyPair(DsaParameters parameters) {
        BigInteger x = randomBetween(ONE, parameters.q().subtract(ONE));
        BigInteger y = parameters.g().modPow(x, parameters.p());
        DsaPublicKey publicKey = new DsaPublicKey(parameters.p(), parameters.q(), parameters.g(), y);
        return new DsaKeyPair(publicKey, new DsaPrivateKey(x));
    }

    public DsaSignature sign(byte[] data, DsaParameters parameters, DsaPrivateKey privateKey) {
        BigInteger hash = hashToInteger(data).mod(parameters.q());

        while (true) {
            BigInteger k = randomBetween(ONE, parameters.q().subtract(ONE));
            BigInteger r = parameters.g().modPow(k, parameters.p()).mod(parameters.q());
            if (r.equals(ZERO)) {
                continue;
            }

            BigInteger s = k.modInverse(parameters.q())
                    .multiply(hash.add(privateKey.x().multiply(r)))
                    .mod(parameters.q());
            if (!s.equals(ZERO)) {
                return new DsaSignature(r, s);
            }
        }
    }

    public boolean verify(byte[] data, DsaPublicKey publicKey, DsaSignature signature) {
        BigInteger q = publicKey.q();
        if (!isInRange(signature.r(), ONE, q.subtract(ONE)) || !isInRange(signature.s(), ONE, q.subtract(ONE))) {
            return false;
        }

        BigInteger hash = hashToInteger(data).mod(q);
        BigInteger w = signature.s().modInverse(q);
        BigInteger u1 = hash.multiply(w).mod(q);
        BigInteger u2 = signature.r().multiply(w).mod(q);
        BigInteger v = publicKey.g().modPow(u1, publicKey.p())
                .multiply(publicKey.y().modPow(u2, publicKey.p()))
                .mod(publicKey.p())
                .mod(q);

        return v.equals(signature.r());
    }

    private BigInteger generateP(int pBits, BigInteger q) {
        BigInteger min = ONE.shiftLeft(pBits - 1);
        BigInteger max = ONE.shiftLeft(pBits).subtract(ONE);
        BigInteger minK = min.subtract(ONE).divide(q).add(ONE);
        BigInteger maxK = max.subtract(ONE).divide(q);

        for (int attempt = 0; attempt < 100_000; attempt++) {
            BigInteger k = randomBetween(minK, maxK);
            if (k.testBit(0)) {
                k = k.add(ONE);
            }
            if (k.compareTo(maxK) > 0) {
                k = k.subtract(TWO);
            }

            BigInteger p = k.multiply(q).add(ONE);
            if (p.bitLength() == pBits && p.isProbablePrime(PRIME_CERTAINTY)) {
                return p;
            }
        }
        return null;
    }

    private BigInteger generateG(BigInteger p, BigInteger q) {
        BigInteger exponent = p.subtract(ONE).divide(q);
        BigInteger h = TWO;
        while (h.compareTo(p.subtract(TWO)) <= 0) {
            BigInteger g = h.modPow(exponent, p);
            if (g.compareTo(ONE) > 0) {
                return g;
            }
            h = h.add(ONE);
        }
        throw new IllegalStateException("Nie udalo sie wyznaczyc generatora g.");
    }

    private BigInteger hashToInteger(byte[] data) {
        return new BigInteger(1, Sha256.digest(data));
    }

    private BigInteger randomBetween(BigInteger minInclusive, BigInteger maxInclusive) {
        BigInteger range = maxInclusive.subtract(minInclusive).add(ONE);
        BigInteger value;
        do {
            value = new BigInteger(range.bitLength(), random);
        } while (value.compareTo(range) >= 0);
        return minInclusive.add(value);
    }

    private boolean isInRange(BigInteger value, BigInteger minInclusive, BigInteger maxInclusive) {
        return value.compareTo(minInclusive) >= 0 && value.compareTo(maxInclusive) <= 0;
    }
}
