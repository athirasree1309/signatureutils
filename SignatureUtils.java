// SignatureUtils.java
package paymentfiles;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SignatureUtils {

	public static String generateSignature(String payload, String secret) throws Exception {
        String algorithm = "HmacSHA256";
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(keySpec);
        byte[] hash = mac.doFinal(payload.getBytes());
        return toHex(hash);
    }

    // Method to convert bytes to hex
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}