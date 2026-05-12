package pl.lodz.p.dsa;

import java.math.BigInteger;

public record DsaPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
}
