/**
 * @classname: PasswordHash.Java
 * @author: Rofin A
 */
/*----------------------------------------------------------------------------- 
*  Purpose: This is a utility class, can be used for generating the hash values 
   for installers Password. Also this class implements an authentication method 
   which will take raw password as input and compare it with the hashed salt and
   password combination to validate the credentials of the user
-------------------------------------------------------------------------------*/
package PublicKeyCertificates;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;


public class PasswordHash {
    
    public static void main (String[] args){
//-----------Read the user inputs--------------
    Scanner s = new Scanner(System.in);   
    // read the user id
    System.out.println("Please enter User ID");
    String userid = s.nextLine();
    // read the password
    System.out.println("Please enter password");
    String pass = s.nextLine();
    
// --------------------------Generate Hash-----------------------------   
//    Generate Salt and hash the password along with the determined salt
    PasswordHash ph = new PasswordHash();
    ph.computeHash(userid, pass);
    }

    private  void computeHash(String user,String pass) {
        byte[] salt = new byte[16];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(salt);
        String salt_val  = javax.xml.bind.DatatypeConverter.printBase64Binary(salt);
       
        //Combine password and the determine salt
        String pwd = salt_val+pass;
        String hash_pwd;
        MessageDigest algorithm;
        try {
            algorithm = MessageDigest.getInstance("SHA-256");
            algorithm.update(pwd.getBytes());
            byte[] hashed = algorithm.digest();
//            Convert the encrypted methods to base64 and hexadecimal notations
            hash_pwd = javax.xml.bind.DatatypeConverter.printBase64Binary(hashed);     
            System.out.println("The following could be stored in the file");
            System.out.println("User ID = "+ user);
            System.out.println("Salt = "+salt_val);
            System.out.println("Hash of Salt+password =  "+hash_pwd);
            
//--------------------Read user Inputs for authentication-----------------------            
           Scanner s = new Scanner(System.in);           
           System.out.println("Please enter User ID");
           String usr = s.nextLine();
           // read the password
           System.out.println("Please enter password");
           String passwd = s.nextLine();
//----------------------------Check authorization------------------------------            

            if(auth_check(passwd,salt_val,hash_pwd)){
                System.out.println("User is good");
            } 
            else{
                System.out.println("User is bad");
            }
        } catch (NoSuchAlgorithmException ex) {
          System.out.println("Could not hash the password");
        }
//       
    }

    public boolean auth_check(String passwd,String salt, String hashed) {
//--------------------------------Calculate Hash-------------------------------    
        String saltd_pass = salt+passwd;
           MessageDigest algorithm;
        try {
            algorithm = MessageDigest.getInstance("SHA-256");
            algorithm.update(saltd_pass.getBytes());
            byte[] hash = algorithm.digest();
            //Convert the encrypted methods to base64 and hexadecimal notations
            String check_val = javax.xml.bind.DatatypeConverter.printBase64Binary(hash);
           
//----------Check if the hashed password is same as the stored password---------           
            if(check_val.equals(hashed)){
                return true;
            }else{
                   return false;
            }
           } catch (NoSuchAlgorithmException ex) {
            System.out.println("Digest error");
        }
    return true;
}
}