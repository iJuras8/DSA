package pl.lodz.p.dsa;

import java.nio.charset.StandardCharsets;

public class DsaSmokeTest {
    public static void main(String[] args) {
        String abcHash = toHex(Sha256.digest("abc".getBytes(StandardCharsets.UTF_8)));
        if (!"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".equals(abcHash)) {
            throw new IllegalStateException("Nieprawidlowy SHA-256.");
        }

        DsaAlgorithm dsa = new DsaAlgorithm();
        DsaParameters parameters = dsa.generateParameters(512, 128);
        DsaKeyPair keyPair = dsa.generateKeyPair(parameters);
        byte[] data = "test podpisu".getBytes(StandardCharsets.UTF_8);
        DsaSignature signature = dsa.sign(data, parameters, keyPair.privateKey());

        if (!dsa.verify(data, keyPair.publicKey(), signature)) {
            throw new IllegalStateException("Prawidlowy podpis nie przeszedl weryfikacji.");
        }
        if (dsa.verify("zmienione".getBytes(StandardCharsets.UTF_8), keyPair.publicKey(), signature)) {
            throw new IllegalStateException("Zmienione dane przeszly weryfikacje.");
        }

        System.out.println("OK");
    }

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }
}
