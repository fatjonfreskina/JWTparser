/*
Further Improvements:
1) public class JWT with: a constructor that takes the token itself and an optional hashing algorithm
Two different methods on the object to 1) Simply deconde and 2) Validate the token
2) Even better, reduce the number of parameters took by the constructor by removing the hashing algorithm.
This for now is hardcoded, however it could be extracted by the token! "alg" field of the header
3) Write unit tests for testing the algorithm with some hard-coded examples.

Useful doc:
About the code: https://www.baeldung.com/java-jwt-token-decode
About the validation process: https://www.freecodecamp.org/news/how-to-sign-and-validate-json-web-tokens/#:~:text=Crypto%2FSignature%20Segment%20of%20a%20JWT&text=JWTs%20are%20signed%20so%20they,the%20key%20used%20could%20differ.

*/ 

package com.mycompany.app;

import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.DefaultJwtSignatureValidator;
import static io.jsonwebtoken.SignatureAlgorithm.HS256;

public class App {
    public static void main(String[] args) throws Exception {
        
        // Go to https://jwt.io/#encoded-jwt and insert a key
        
        String keyExample = "test";
        String JWTexample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkJhZWxkdW5nIFVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.cBeAV24jl6povEuEFWnSgaAcHNZwwjsj6uAn6Ps0ifE";
        
        // Test

        decodeJWTToken(JWTexample);
        decodeAndValidateJWTToken(JWTexample, keyExample);
    }
    
    /**
     * 
     * @param token The token issued by the Authorization Server
     * @param secretKey The key used to sign the token
     * @return a String concatenation of decoded Header and Payload
     * @throws Exception if the validation process fails
     */
    public static String decodeAndValidateJWTToken(String token, String secretKey) throws Exception {
        Base64.Decoder decoder = Base64.getUrlDecoder();

        String[] chunks = token.split("\\.");

        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));
        String tokenWithoutSignature = chunks[0] + "." + chunks[1];

        String signature = chunks[2];

        SignatureAlgorithm sa = HS256;
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), sa.getJcaName());

        DefaultJwtSignatureValidator validator = new DefaultJwtSignatureValidator(sa, secretKeySpec);

        if (!validator.isValid(tokenWithoutSignature, signature)) {
            throw new Exception("Could not verify JWT token integrity!");
        } else {
            System.out.println("Token is valid");
        }

        return header + " " + payload;
    }

    /**
     * 
     * @param token The token issued by the Authorization Server
     * @return a String concatenation of decoded Header and Payload 
     */
    public static String decodeJWTToken(String token) {
        Base64.Decoder decoder = Base64.getUrlDecoder();

        String[] chunks = token.split("\\.");

        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));

        return header + " " + payload;
    }
}
