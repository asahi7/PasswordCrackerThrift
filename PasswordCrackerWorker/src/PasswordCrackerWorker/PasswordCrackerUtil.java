package PasswordCrackerWorker;

import org.apache.thrift.TException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static PasswordCrackerWorker.PasswordCrackerConts.PASSWORD_CHARS;
import static PasswordCrackerWorker.PasswordCrackerConts.PASSWORD_LEN;

public class PasswordCrackerUtil {

    private static MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Cannot use MD5 Library:" + e.getMessage());
        }
    }

    private static String encrypt(String password, MessageDigest messageDigest) {
        messageDigest.update(password.getBytes());
        byte[] hashedValue = messageDigest.digest();
        return byteToHexString(hashedValue);
    }

    private static String byteToHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                builder.append('0');
            }
            builder.append(hex);
        }
        return builder.toString();
    }

    /*
     * The findPasswordInRange method finds the password.
     * if it finds the password, it set the termination for transferring signal to master and returns password to caller.
     */
    public static String findPasswordInRange(long rangeBegin, long rangeEnd, String encryptedPassword, TerminationChecker terminationChecker) throws TException, InterruptedException {
        /** COMPLETE **/
        MessageDigest msg = getMessageDigest();
        int[] numArrayInBase36 = new int[PASSWORD_LEN];
        transformDecToBase36(rangeBegin, numArrayInBase36);      
        for(long i = rangeBegin; i < rangeEnd; i++){
        	if(terminationChecker.isTerminated()) {
        		return null;
        	}
            String str = transformIntoStr(numArrayInBase36);             
            String md = encrypt(str, msg);
            if(md.equals(encryptedPassword)) {
                return str;
            }
            getNextCandidate(numArrayInBase36);
        }   
        return null;
    }

    /* ###  transformDecToBase36  ###
     * The transformDecToBase36 transforms decimal into numArray that is base 36 number system
     * If you don't understand, refer to the homework01 overview
    */
    private static void transformDecToBase36(long numInDec, int[] numArrayInBase36) {
        /** COMPLETE **/
        List<Integer> list = new ArrayList<>();
        do {
            list.add((int)(numInDec % 36));
            numInDec /= 36;
        } while (numInDec != 0); 
        Collections.reverse(list);
        for(int i = 0; i < list.size(); i++){
            numArrayInBase36[i] = list.get(i);
        }
    }

    //  ### getNextCandidate ###
    private static void getNextCandidate(int[] candidateChars) {
        /** OPTIONAL **/
        candidateChars[candidateChars.length - 1]++;
        for(int i = candidateChars.length - 1; i > 0; i--){
            if(candidateChars[i] > 35) {
                candidateChars[i] = 0;
                candidateChars[i - 1] ++;
            }
            else break;
        } 
    }

    private static String transformIntoStr(int[] chars) {
        char[] password = new char[chars.length];
        for (int i = 0; i < password.length; i++) {
            password[i] = PASSWORD_CHARS.charAt(chars[i]);
        }
        return new String(password);
    }
}
