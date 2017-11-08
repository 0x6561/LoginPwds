/**

   © Copyright 2017 Edgar Aguiniga ©
   This file is part of LoginPwds.

   LoginPwds is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   LoginPwds is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with LoginPwds.  If not, see <http://www.gnu.org/licenses/>.

 **/
package net.ea.loginpwds;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.util.*;

/*
 * This class is a wrapper class for constructing a 
 * AES Cipher
 */
public class CryptAES
{

  private static final boolean DBG = false;
  private static String KEY_FILE = "aesKey256.dat";
  private static Cipher aesCipher;
  private static Key aesKey;
  private static SecretKeySpec skeySpec;

  /**
   * Class Contructor
   * This version to be used with a 
   * pre-shared key as a file on disk 
   *
   */
  public CryptAES()
  {
    try
    {
      FileInputStream in = new FileInputStream(KEY_FILE);
      int keySize = in.available();
      byte[] keyAsBytes = new byte[keySize];
      in.read(keyAsBytes);
      in.close();

      aesCipher = Cipher.getInstance("AES");
      skeySpec = new SecretKeySpec(keyAsBytes, "AES");
    }//close try
    catch(NoSuchAlgorithmException nsaex)
    {
      nsaex.printStackTrace();
    }
    catch(NoSuchPaddingException nspex)
    {
      nspex.printStackTrace();
    }
    catch(FileNotFoundException fnfex)
    {
      fnfex.printStackTrace();
    }
    catch(IOException ioex)
    {
      ioex.printStackTrace();
    }

  }//close Crypt

  /**
   * Class Contructor
   * This version requires a key as parameter, 
   * Uses output of Diffie-helman
   * @param byte[], Diffie Helman shared secret
   */
  public CryptAES(byte[] k)
  {
    try
    {
      aesCipher = Cipher.getInstance("AES");
      //SecretKeySpec(byte[] key, int offset, int len, String algorithm)
      //Constructs a secret key from the given 
      //byte array, using the first len bytes of key, 
      //starting at offset inclusive. + 
      skeySpec = new SecretKeySpec(k,0,16,"AES");
      byte[] skstr = skeySpec.getEncoded();
      String keySpecStr = Base64.getEncoder().encodeToString(skstr);
    }//close try
    catch(NoSuchAlgorithmException nsaex)
    {
      nsaex.printStackTrace();
    }
    catch(NoSuchPaddingException nspex)
    {
      nspex.printStackTrace();
    }
  }//close Crypt

  /**
   * Class Contructor
   * This version requires a password as parameter, 
   * Uses PBE Password Based Encryption 
   * @param String, password
   * @param String, salt 
   */
  public CryptAES(String password, String salt)
  {
    try
    {
      aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
      // this is more secure but need to store IV for each ciphertext 
      //aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      // cannot use a bigger key size unless unlimited jurisdiction file installed
      //PBEKeySpec spec = new PBEKeySpec(plaintext, saltBytes, iterations, keySize);
      PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
      SecretKey secretKey = skf.generateSecret(spec);
      skeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
    }
    catch(NoSuchAlgorithmException nsaex)
    {
      nsaex.printStackTrace();
    }
    catch(NoSuchPaddingException nspex)
    {
      nspex.printStackTrace();
    }
    catch(InvalidKeySpecException e)
    {
      e.printStackTrace();
    }
  }//close Crypt

  /*
   *Method to encrypt a String using AES
   @param plainText, String to be encrypted
   @return String, ciphertext 
  */
  public static String crypt(String plainText)
  {
    String cipherTextAsStr = ""; 
    try
    {
      //setup for ENCRYPTION
      aesCipher.init(Cipher.ENCRYPT_MODE, skeySpec);
      byte[] plainTxtAsBytes = plainText.getBytes();
      byte[] cipherTxtAsBytes = aesCipher.doFinal(plainTxtAsBytes);
      // encode byte[] as Base64...

      cipherTextAsStr = Base64.getEncoder().encodeToString(cipherTxtAsBytes);
    }//close try
    catch(IllegalBlockSizeException ibsex)
    {
      ibsex.printStackTrace();
    }
    finally
    {
      return cipherTextAsStr;
    }//close finally
  }//close crypt

  /*
   *Method to encrypt a String using AES
   @param plainTxtAsBytes, byte[] to be encrypted
   @return String, ciphertext 
  */
  public static String crypt(byte[] plainTxtAsBytes)
  {
    String cipherTextAsStr = ""; 
    try
    {
      //setup for ENCRYPTION
      aesCipher.init(Cipher.ENCRYPT_MODE, skeySpec);
      byte[] cipherTxtAsBytes = aesCipher.doFinal(plainTxtAsBytes);
      // encode byte[] as Base64...

      cipherTextAsStr = Base64.getEncoder().encodeToString(cipherTxtAsBytes);
    }//close try
    catch(IllegalBlockSizeException ibsex)
    {
      ibsex.printStackTrace();
    }
    finally
    {
      return cipherTextAsStr;
    }//close finally
  }//close crypt


  /*
   *Method to encrypt a String using AES
   @param plainText, String to be encrypted
   @return CipherTxtIV, ciphertext and iv 
  */
  public static CipherTxtIV crypt_iv(String plainText)
  {
    CipherTxtIV cipherTxtIV = null; 
    try
    {
      //setup for ENCRYPTION
      aesCipher.init(Cipher.ENCRYPT_MODE, skeySpec);
      AlgorithmParameters params = aesCipher.getParameters();
      byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();

      byte[] plainTxtAsBytes = plainText.getBytes();
      byte[] cipherTxtAsBytes = aesCipher.doFinal(plainTxtAsBytes);
      // encode byte[] as Base64...

      String cipherTextAsStr = Base64.getEncoder().encodeToString(cipherTxtAsBytes);
      String ivStr = Base64.getEncoder().encodeToString(ivBytes);
      cipherTxtIV = new CipherTxtIV(cipherTextAsStr, ivStr);
    }//close try
    catch(IllegalBlockSizeException ibsex)
    {
      ibsex.printStackTrace();
    }
    finally
    {
      return cipherTxtIV;
    }//close finally
  }//close crypt

  
  /*
   *Method to decrypt a CipherTxtIV encrypted object using AES
   @param cipherTxtIV, CipherTxtIV to be decrypted
   @return String, plaintext 
  */
  public static String decrypt_iv(CipherTxtIV cipherTxtIV)
  {
    String decryptedTxtStr = "";
    try
     {

      //setup for DECRYPTION
       byte[] ivBytes = Base64.getDecoder().decode(cipherTxtIV.getIV());
      aesCipher.init(Cipher.DECRYPT_MODE, skeySpec,new IvParameterSpec(ivBytes));
      byte[] cipherTxtAsBytes = Base64.getDecoder().decode(cipherTxtIV.getCipherTxt());
      byte[] decipheredTxtBytes = aesCipher.doFinal(cipherTxtAsBytes);
      decryptedTxtStr = new String(decipheredTxtBytes, "UTF8");
    }//close try
    catch(InvalidKeyException ikex)
    {
      ikex.printStackTrace();
    }
    catch(IllegalBlockSizeException ibsex)
    {
      ibsex.printStackTrace();
    }
    catch(UnsupportedEncodingException ueex)
    {
      ueex.printStackTrace();
    }
    finally
    {
      return decryptedTxtStr;
    }//close finally
  }//close decrypt

  /*
   *Method to decrypt a String encrypted using AES
   @param cipherText, String to be encrypted
   @return String, plaintext 
  */
  public static String decrypt(String cipherText)
  {
    String decryptedTxtStr = "";
    try
    {
      //setup for DECRYPTION
      aesCipher.init(Cipher.DECRYPT_MODE, skeySpec);
      byte[] cipherTxtAsBytes = Base64.getDecoder().decode(cipherText);
      byte[] decipheredTxtBytes = aesCipher.doFinal(cipherTxtAsBytes);
      decryptedTxtStr = new String(decipheredTxtBytes, "UTF8");
    }//close try
    catch(InvalidKeyException ikex)
    {
      ikex.printStackTrace();
    }
    catch(IllegalBlockSizeException ibsex)
    {
      ibsex.printStackTrace();
    }
    catch(UnsupportedEncodingException ueex)
    {
      ueex.printStackTrace();
    }
    finally
    {
      return decryptedTxtStr;
    }//close finally
  }//close decrypt


  /*
   *Method to decrypt a String encrypted using AES
   @param cipherTxtAsBytes, byte[] to be encrypted
   @return String, plaintext 
  */
  public static String decrypt(byte[] cipherTxtAsBytes)
  {
    String decryptedTxtStr = "";
    try
    {

      if(DBG){System.out.println("DECRYPTING = " + cipherTxtAsBytes.toString());}

      //setup for DECRYPTION
      aesCipher.init(Cipher.DECRYPT_MODE, skeySpec);
      byte[] decipheredTxtBytes = aesCipher.doFinal(cipherTxtAsBytes);
      decryptedTxtStr = new String(decipheredTxtBytes, "UTF8");

      if(DBG){System.out.println("DECRYPTION DONE : decryptedTxtStr = "+ decryptedTxtStr);}

    }//close try
    catch(InvalidKeyException ikex)
    {
      ikex.printStackTrace();
    }
    catch(IllegalBlockSizeException ibsex)
    {
      ibsex.printStackTrace();
    }
    catch(UnsupportedEncodingException ueex)
    {
      ueex.printStackTrace();
    }
    finally
    {
      return decryptedTxtStr;
    }//close finally
  }//close decrypt

  public static void printInfo()
  {
    // Security.addProvider( new BouncyCastleProvider() );
    for (Provider provider : Security.getProviders()) 
    {
      System.out.println( provider );
      for (Provider.Service service : provider.getServices())
      {
        if("SecretKeyFactory".equals(service.getType()))
        {
          System.out.println( service );
        }
      }
  }
  }

  //Returns the algorithm name of this Cipher object.
  public static String getAlgorithm()
  {
    return aesCipher.getAlgorithm();
  }

}//close CryptAES class
