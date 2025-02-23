package org.prvn.labs.security.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class PKCEGenerator {

    // Generate a random code verifier
    public static String generateCodeVerifier() {
        byte[] code = new byte[32];
        new SecureRandom().nextBytes(code);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(code);
    }

    // Generate a code challenge using SHA-256
    public static String generateCodeChallenge(String codeVerifier) throws Exception {
        byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public static void main(String[] args) throws Exception {
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        System.out.println("Code Verifier: " + codeVerifier);
        System.out.println("Code Challenge: " + codeChallenge);

        // Generate the OAuth2 URL
        String authUrl = String.format(
                "http://localhost:9090/oauth2/authorize?" +
                        "response_type=code&client_id=client&" +
                        "redirect_uri=https://springone.io/authorized&" +
                        "scope=read&code_challenge=%s&code_challenge_method=S256",
                codeChallenge
        );

        System.out.println("\nAuthorization URL:\n" + authUrl);
    }
}
