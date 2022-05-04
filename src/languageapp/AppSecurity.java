/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package languageapp;

import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import javax.crypto.SecretKeyFactory;
import java.util.Base64;


/**
 *
 * @author kristi
 */
public class AppSecurity {
    
    private static final Random RAND = new SecureRandom();
    private static final int LNGTH_OF_THE_KEY = 64;
    private static final int REPEAT_ITER = 25;    
    private static final String CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz@#!£&*^";
    
    public static String generateSlt(int d){
        
        StringBuilder getReasult = new StringBuilder(d);
        
        for(int l = 0; l < d; l++){     
            getReasult.append(CHARSET.charAt(RAND.nextInt(CHARSET.length())));
        }
        
        return new String(getReasult);
    }
    
    public static byte[] encde(char[] pass, byte[] slt){
        
        PBEKeySpec keySPBE = new PBEKeySpec(pass, slt, REPEAT_ITER, LNGTH_OF_THE_KEY);
        Arrays.fill(pass, Character.MIN_VALUE);
        
        try{
            SecretKeyFactory sectetKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");            
            return sectetKeyFactory.generateSecret(keySPBE).getEncoded();            
        }
        
        catch(NoSuchAlgorithmException | InvalidKeySpecException e){
            throw new AssertionError("Error: " + e.getMessage(), e);
        }
        
        finally{
            keySPBE.clearPassword();
            System.gc();
        }
    }
    
    public static String createPasswordSecuredAndProtected(String pass, String slt){
        String getReasult;
        byte[] passSecured = encde(pass.toCharArray(), slt.getBytes());        
        System.out.println("Secured password " + Arrays.toString(passSecured));
        getReasult = Base64.getEncoder().encodeToString(passSecured);
        System.out.println("Encoded password: " + getReasult);
        return getReasult;          
    }    
}
