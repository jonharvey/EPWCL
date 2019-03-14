package com.ecapitaladvisors.oraclecloud;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;

public class EPWCL {
	
	private static String _mode = null;
	private static String _filePath = null;
	private static String _key = null;
	private static String _pwd = null;
	private static String _proxyPwd = null;

	public static void main(String[] args) {
		if(validateArgs(args)){
			if(_mode=="ENCRYPT")
				try {
					writeEPWFile(_pwd,_key,_filePath,_proxyPwd);
				} 
				catch (Exception e) {
					e.printStackTrace();
				}
			else
				try {
					readEPWFile(_filePath);
				} 
				catch (Exception e) {
					e.printStackTrace();
				}
		}
		else{
			printUsage();
		}
	}
		
    public static void writeEPWFile(String pwd, String encKey, String filePath, String proxyPwd) throws IOException, Exception
    {
        FileOutputStream fos;
        String encPwd = null;
        String comb = null;
        fos = null;
        String encoded = null;
        File parentFile = null;

        try{
            encPwd = encrypt(pwd, encKey);
            if(proxyPwd != null)
            {
                if(null != proxyPwd && proxyPwd.toLowerCase().startsWith("ProxyServerPassword=".toLowerCase()))
                    proxyPwd = (new StringBuilder()).append("ProxyPassword=").append(proxyPwd.split("=")[1]).toString();
                comb = (new StringBuilder()).append(encPwd).append(".epw2015.").append(encKey).append(".epw2015.").append(proxyPwd).toString();
            } 
            else
            {
                comb = (new StringBuilder()).append(encPwd).append(".epw2015.").append(encKey).toString();
            }
            if(!filePath.endsWith(".epw"))
                filePath = (new StringBuilder()).append(filePath).append(".epw").toString();
            encoded = new String(Base64.encodeBase64(comb.getBytes("UTF-8")));
            parentFile = (new File(filePath)).getParentFile();
            if(parentFile != null && !parentFile.exists())
                parentFile.mkdirs();
            fos = new FileOutputStream(new File(filePath));
            fos.write(encoded.getBytes("UTF-8"));
        }
        catch(IOException ioe){
            throw new Exception(ioe.getMessage());
        }
        catch(Exception e){
            throw new Exception(e.getMessage());
        }
        finally{
            if(fos != null)
            {
                fos.flush();
                fos.close();
            }
        }
        System.out.println("EPW file created: "+filePath);
        return;
    }
	
    public static String readEPWFile(String filePath) throws IOException, Exception
    {
        FileInputStream fis;
        String decryptedString;
        StringBuffer encodedBuffer;
        fis = null;
        String comb = null;
        String pwd = null;
        String encKey = null;
        String temp[] = null;
        decryptedString = null;
        encodedBuffer = new StringBuffer();
        try
        {
            fis = new FileInputStream(new File(filePath.endsWith(".epw") ? filePath : (new StringBuilder()).append(filePath).append(".epw").toString()));
            int ch;
            while((ch = fis.read()) != -1) 
                encodedBuffer.append((char)ch);
            if(encodedBuffer.length() == 0)
            {
                throw new Exception("buffer length is zero");
            }
            comb = new String(Base64.decodeBase64(encodedBuffer.toString().getBytes("UTF-8")));
            temp = comb.split(".epw2015.");
            if(temp != null && temp.length >= 2)
            {
                pwd = temp[0];
                encKey = temp[1];
                decryptedString = decrypt(pwd, encKey);
            }
            System.out.println("EPW FILE : "+filePath);
            System.out.println("DECRYPTED: "+decryptedString);
        }
        catch(Exception e)
        {
        	System.out.println(e.getMessage());
        }
        finally{
		   if(fis != null)
	            fis.close();
        }
        return decryptedString;
    }

    public static String encrypt(String strToEncrypt, String key) throws Exception
    {
        SecretKeySpec secretKey = null;
        byte userKey[] = null;
        String encryptedString = null;
        try
        {
            MessageDigest sha = null;
            userKey = key.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            userKey = sha.digest(userKey);
            userKey = Arrays.copyOf(userKey, 16);
            secretKey = new SecretKeySpec(userKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(1, secretKey);
            encryptedString = (new StringBuilder()).append("{EPMAT}").append(new String(Base64.encodeBase64(cipher.doFinal(strToEncrypt.getBytes("UTF-8"))))).toString();
        }
        catch(Exception e)
        {
            throw new Exception(e.getMessage());
        }
        return encryptedString;
    }
    
    public static String decrypt(String strToDecrypt, String key) throws Exception
    {
        SecretKeySpec secretKey = null;
        byte userKey[] = null;
        String decryptedString = null;
        try
        {
            MessageDigest sha = null;
            userKey = key.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            userKey = sha.digest(userKey);
            userKey = Arrays.copyOf(userKey, 16);
            secretKey = new SecretKeySpec(userKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            decryptedString = strToDecrypt;
            if(isEncrypted(strToDecrypt))
            {
                strToDecrypt = strToDecrypt.substring(7, strToDecrypt.length());
                cipher.init(2, secretKey);
                decryptedString = new String(cipher.doFinal(Base64.decodeBase64(strToDecrypt.getBytes("UTF-8"))));
            }
        }
        catch(Exception e)
        {
            throw new Exception(e.getMessage());
        }
        return decryptedString;
    }

    public static boolean isEncrypted(String param)
    {
        if(param != null && param.length() > 7)
        {
            String prefix = param.substring(0, 7);
            if(prefix.equals("{EPMAT}"))
                return true;
        }
        return false;
    }

    private static boolean validateArgs(String[] args){
        try{
            if(args.length % 2 != 0)
                throw new Exception("\nERROR: Invalid number of arguments exception...");
            for(int i=0;i<args.length-1;i=i+2){
                if(args[i].charAt(0) == '-'){
                    switch(args[i].charAt(1)){
                        case 'm':
                            switch(args[i+1].charAt(0)){
	                            case 'E':
	                            	_mode="ENCRYPT";
	                            	break;
	                            case 'D':
	                            	_mode="DECRYPT";
	                            	break;
	                        	default:
	                        		throw new Exception("\nERROR: Bad mode flag passed. Valid values are \"E\" or \"D\"");
                            }
                            break;
                        case 'f':
                            _filePath = args[i+1];
                            break;
                        case 'p':
                            _pwd = args[i+1];
                            break;
                        case 'k':
                            _key = args[i+1];
                            break;
                        case 'x':
                            _proxyPwd = args[i+1];
                            break;
                        default:
                            throw new Exception("\nERROR: Bad flag/argument exception...");
                    }
                }
                else
                    throw new Exception("\nERROR: Bad argument format exception...");
            }
            if((_mode == null) || (_filePath == null) || ((_mode == "ENCRYPT") && ((_pwd == null) || (_key == null))))
                throw new Exception("\nERROR: Mandatory argument not passed...");           
        }
        catch(Exception e){
            System.out.println(e.getMessage());
            return false;
        }

        return true;
    }

    private static void printUsage(){
        System.out.println(System.getProperty("line.separator"));
        System.out.println("*************************************************");
        System.out.println("*           EPW Command Line Utility            *");
        System.out.println("*                                               *");
        System.out.println("*    Author: Jon Harvey                         *");
        System.out.println("*            eCapital Advisors, LLC.            *");
        System.out.println("*            jharvey@ecapitaladvisors.com       *");
        System.out.println("*                                               *");
        System.out.println("*     Built: 07/24/2018                         *");
        System.out.println("*************************************************");
        System.out.println("\nUSAGE: java -jar EPWCL.jar [options]\n");
        System.out.println("Flag                             Option");      
        System.out.println("================================================================================");
        System.out.println("-m       (required)              Mode: \"E\" for Encrypt, \"D\" for Decrypt");
        System.out.println("-f       (required)              File path to EPW file");
        System.out.println("-p       (encrypt mode required) Password to enrypt");
        System.out.println("-k       (encrypt mode required) Key to enrypt the password with");
        System.out.println("-x       (encrypt mode optional) Proxy server password" + System.getProperty("line.separator"));
        System.out.println("Arguments must be passed in a \"-flag argument\" paired format");
        System.out.println("(not \"EPWCL.jar -mfpkx arg1 arg2 argX...\")" + System.getProperty("line.separator") + System.getProperty("line.separator"));
    }
 
}
