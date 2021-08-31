package de.exware.crypt2cloud;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.DateFormat;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.Stack;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class to sync files encrypted. This makes it possible to sync local unencrypted folders to
 * an encrypted cloud folder. 
 * @author martin
 */
public class Crypt2Cloud
{
    private static final String version = "1";
    Set<File> filesInUse = new HashSet<>();
    
    public static void main(String[] args) throws Exception
    {
        boolean backup = getArgumentIndex(args, "--backup") >= 0;
        boolean restore = getArgumentIndex(args, "--restore") >= 0;
        boolean list = getArgumentIndex(args, "--list") >= 0;
        if(oneTrue(backup, restore, list) == false)
        {
            printSyntax();
            System.exit(-1);
        }
        Crypt2Cloud cs = new Crypt2Cloud();
        File plainDir = null;
        File cryptDir = null;
        String path = null;
        char[] pass = null;
        try
        {
            plainDir = new File(getArgumentValue(args, "--plaindir", null));
            cryptDir = new File(getArgumentValue(args, "--cryptdir", null));
            String p = getArgumentValue(args, "--password", null);            
            path = getArgumentValue(args, "--path", null); 
            if(path == null)
            {
            	path = "";
            }
            else
            {
            	path.replace('\\', '/');
            	if(path.charAt(0) != '/')
            	{
            		path = "/" + path;
            	}
            }
            pass = p.toCharArray();
            p = null;
        }
        catch(Exception ex)
        {
            printSyntax();
        }
        if(pass == null || plainDir == null || cryptDir == null)
        {
            printSyntax();
        }
        else
        {
            if(backup)
            {
                cs.backup(pass, plainDir, cryptDir, path);
            }
            else if(restore)
            {
                cs.restore(pass, cryptDir, plainDir, path);
            }
            else if(list)
            {
                cs.list(pass, cryptDir, path);
            }
        }
    }

    /**
     * Check if only one of the Arguments is true.
     * @param values
     * @return
     */
    private static boolean oneTrue(boolean ... values)
    {
    	boolean oneTrue = false;
    	for(int i=0;i<values.length;i++)
    	{
    		if(oneTrue && values[i])
    		{
    			oneTrue = false;
    			break;
    		}
    		if(values[i])
    		{
    			oneTrue = true;
    		}
    	}
    	return oneTrue;
    }
    
    /**
     * Print usage syntax
     */
    private static void printSyntax()
    {
        System.err.println("Usage:");
        System.err.println("crypt2cloud [--backup | --restore | --list] --password PASSWORD --plaindir DIRECTORY --cryptdir DIRECTORY [--path SUBPATH]");
        System.err.println("--backup will store plain files into the crypted directory.");
        System.err.println("--restore will restore plain files from the crypted directory.");
        System.err.println("--list will list the files stored in the crypted directory.");
        System.err.println("--path will limit the operation to only the given path. Useful to limit restore to single files or directories, or if you know, that backup only needs to be performed on some directories.");
        System.err.println("Version 1.0");
    }
    
    public static String getArgumentValue(String[] args, String arg,String defaultValue)
    {
        for(int i=0;i<args.length;i++)
        {
            if(args[i].equals(arg) && i+1 < args.length)
            {
                return args[i+1];
            }
        }
        return defaultValue;
    }

    /**
     * Gibt den Index der angegebenen Option zurück.
     * 
     * @param args String Array mit der Kommandozeile
     * @param arg Die zurückzuliefernde Option
     * @return index der Option "arg"
     */
    public static int getArgumentIndex(String[] args, String arg)
    {
        if (args == null) 
        {
            return -1;
        }
        for (int i = 0; i < args.length; i++)
        {
            if (args[i].equals(arg))
            {
                return i;
            }
        }
        return -1;
    }

    private void backup(char[] pass, File source, File cryptDir, String pathLimit) throws Exception
    {
        long totalSize = 0;
        filesInUse.clear();
        SecretKey key = getKey(pass, cryptDir);
        Stack<File> files = new Stack<>();
        files.push(source);
        while(files.isEmpty() == false)
        {
            File f = files.pop();
            String path = getPath(source, f);
            File file = getCryptPath(path, cryptDir);
            filesInUse.add(file);
            File filex = getCryptPath(path + "_X_meta", cryptDir); 
            filesInUse.add(filex);
            file.getParentFile().mkdirs();
            Properties props = new Properties();
            props.put("version", version);
            if(f.isDirectory())
            {
                File[] ch = f.listFiles();
                files.addAll(Arrays.asList(ch));
                for(int i=0;i<ch.length;i++)
                {
                    String name = ch[i].getName();
                    name.replace('\\', '/');
                    props.put("file_" + i, name);
                    props.put("file_" + i + "_isDirectory", "" + ch[i].isDirectory());
                    props.put("file_" + i + "_lastModified", "" + ch[i].lastModified());
                }
            }
            if(path.startsWith(pathLimit))
            {
            	if(f.isDirectory() == false)
                {
                    String oldMd5 = null;
                    try
                    {
                        Properties oldProps = loadProperties(key, path, cryptDir);
                        oldMd5 = oldProps.getProperty("md5sum");
                    }
                    catch(Exception ex)
                    {
                        System.out.println("Error loading old Properties. Will backup completely: " + f);
                    }
                    String md5 = md5(f);
                    if(md5.equals(oldMd5))
                    {
                        System.out.println(f + " not modified");
                        continue;
                    }
                    else
                    {
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                        byte[] iv = new SecureRandom().generateSeed(16);
                        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                        Md5InputStream in = new Md5InputStream(new BufferedInputStream(new FileInputStream(f)));
                        BufferedOutputStream bout = new BufferedOutputStream(new FileOutputStream(file));
                        bout.write(iv);
                        CipherOutputStream out = new CipherOutputStream(bout, cipher);
                        copy(in, out);
                        in.close();
                        out.close();
                        props.put("md5sum", in.getMd5());
                        props.put("lastModified", "" + f.lastModified());
                        totalSize += f.length();
                        if(f.equals(source) == false)
                        {
                            System.out.println(f + " stored to " + file);
                        }
                    }
                }
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                byte[] iv = new SecureRandom().generateSeed(16);
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                filex.getParentFile().mkdirs();
                OutputStream out = new BufferedOutputStream(new FileOutputStream(filex));
                out.write(iv);
                out.flush();
                out = new CipherOutputStream(out, cipher);
                props.store(out, null);
                out.close();
                System.out.println(f + " stored meta to " + filex);
                System.out.println("Total Size: " + totalSize);
            }
        }
        deleteOldFiles(cryptDir, filesInUse);
        filesInUse.clear();
    }

    /**
     * Deletes files that do no longer exist in plain directory.
     * @param cryptDir
     * @param filesInUse
     * @throws IOException
     */
    private void deleteOldFiles(File cryptDir, Set<File> filesInUse) throws IOException
    {
        System.out.println("Deleting unused files");
        Stack<File> files = new Stack<>();
        files.push(cryptDir);
        while(files.isEmpty() == false)
        {
            File f = files.pop();
            if(f.isDirectory())
            {
                File[] ch = f.listFiles();
                files.addAll(Arrays.asList(ch));
            }
            else if (filesInUse.contains(f) == false)
            {
                delete(f, true);
                System.out.println(f + " deleted");
            }
        }
    }

    private String getPath(File plainDir, File file)
    {
        String path = file.getAbsolutePath();
        int cutPoint = plainDir.getAbsolutePath().length();
        path = path.substring(cutPoint);
        path.replace('\\', '/');
        return path;
    }
    
    class CryptFile
    {
        boolean isDirectory;
        String path;
        String name;
        public String md5;
        public long lastModified;
    }
    
    private File getCryptPath(String filename, File cryptDir) throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        MessageDigest digest = MessageDigest.getInstance("md5");
        digest.update(filename.getBytes("UTF-8"));
        byte[] encdata = digest.digest();
        String hex = toHex(encdata);
        File file = new File(cryptDir, hex.charAt(0) + "/"
            + hex.charAt(1) + "/"
            + hex.charAt(2) + "/"
            + hex.charAt(3) + "/"
            + hex.charAt(4) + "/"
            + hex.charAt(5) + "/"
            + hex);
        return file;
    }
    
    public static void copy(InputStream in, OutputStream out) throws IOException
    {
        byte[] buf = new byte[65536];
        int count = in.read(buf);
        while (count >= 0)
        {
            out.write(buf, 0, count);
            count = in.read(buf);
        }
    }

    private SecretKey getKey(char[] pass, File cryptDir) throws Exception
    {
        String p = new String(pass);
        File saltfile = getCryptPath(p, cryptDir);
        File keyfile = getCryptPath(p+"_X_key", cryptDir);
        File ivfile = getCryptPath(p+"_X_iv", cryptDir);
        filesInUse.add(saltfile);
        filesInUse.add(keyfile);
        filesInUse.add(ivfile);
        p = null;
        byte[] salt;
        byte[] bkey;
        byte[] iv;
        if(saltfile.exists())
        {
            salt = Files.readAllBytes(saltfile.toPath());
        }
        else
        {
            salt = new SecureRandom().generateSeed(256);
            saltfile.getParentFile().mkdirs();
            FileOutputStream out = new FileOutputStream(saltfile);
            out.write(salt);
            out.close();
        }
        if(ivfile.exists())
        {
            iv = Files.readAllBytes(ivfile.toPath());
        }
        else
        {
            iv = new SecureRandom().generateSeed(16);
            ivfile.getParentFile().mkdirs();
            FileOutputStream out = new FileOutputStream(ivfile);
            out.write(iv);
            out.close();
        }
        SecretKey key = getKeyFromPassword(pass, salt);
        if(keyfile.exists())
        {
            bkey = Files.readAllBytes(keyfile.toPath());
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            bkey = cipher.doFinal(bkey);
        }
        else
        {
            bkey = new byte[32];
            new SecureRandom().nextBytes(bkey);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] savekey = cipher.doFinal(bkey);
            keyfile.getParentFile().mkdirs();
            FileOutputStream out = new FileOutputStream(keyfile);
            out.write(savekey);
            out.close();
        }
        SecretKey secretKey = new SecretKeySpec(bkey, "AES");
        return secretKey;
    }
    
    private Properties loadProperties(SecretKey key,String path, File cryptDir) throws Exception
    {
        Properties props = new Properties();
        File file = getCryptPath(path + "_X_meta", cryptDir);
        if(file.exists())
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            InputStream in = new BufferedInputStream(new FileInputStream(file));
            byte[] iv = readIV(in);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            in = new CipherInputStream(in, cipher);
            props.load(in);
            in.close();
        }
        return props;
    }
    
    /**
     * Liefert die Dateien für einen bestimmten Pfad im verschlüsselten Ordner.
     * @param key
     * @param path
     * @param cryptDir
     * @return
     * @throws Exception
     */
    private List<CryptFile> getFilesFromMeta(SecretKey key,String path, File cryptDir) throws Exception
    {
        List<CryptFile> pathes = new ArrayList<>();
        Properties props = loadProperties(key, path, cryptDir);
        int i=0;
        while(true)
        {
            String filename = props.getProperty("file_" + i);
            if(filename == null)
            {
                break;
            }
            else
            {
                CryptFile cf = new CryptFile();
                cf.path = path + "/" + filename;
                cf.name = filename;
                cf.isDirectory = Boolean.parseBoolean(props.getProperty("file_" + i + "_isDirectory"));
                String tmp = props.getProperty("file_" + i + "_lastModified");
                if(tmp != null)
                {
                    cf.lastModified = Long.parseLong(tmp);
                }
                pathes.add(cf);
            }
            i++;
        }
        return pathes;
    }
    
    private byte[] readIV(InputStream in) throws Exception
    {
        byte[] iv = new byte[16];
        int count = 0;
        while(count < iv.length)
        {
            count += in.read(iv, count, iv.length-count);
        }
        return iv;
    }
    
    private void list(char[] pass, File cryptDir, String pathLimit) throws Exception
    {
        SecretKey key = getKey(pass, cryptDir);
        List<CryptFile> list = getFilesFromMeta(key, "", cryptDir);
        Stack<CryptFile> files = new Stack<>();
        files.addAll(list);
        while(files.isEmpty() == false)
        {
            CryptFile f = files.pop();
            if(f.isDirectory)
            {
                list = getFilesFromMeta(key, f.path, cryptDir);
                files.addAll(list);
            }
            if(f.path.startsWith(pathLimit))
            {
	            DateFormat format = DateFormat.getDateTimeInstance();
	            System.out.print(format.format(new Date(f.lastModified)));
	            System.out.println(" " + f.path);
            }
        }
    }
    
    private void restore(char[] pass, File cryptDir, File restored, String pathLimit) throws Exception
    {
        SecretKey key = getKey(pass, cryptDir);
        List<CryptFile> list = getFilesFromMeta(key, "", cryptDir);
        Stack<CryptFile> files = new Stack<>();
        files.addAll(list);
        while(files.isEmpty() == false)
        {
            CryptFile f = files.pop();
            File cryptedFile = getCryptPath(f.path, cryptDir);
            File file = new File(restored, f.path);
            if(f.isDirectory)
            {
            	if(f.path.startsWith(pathLimit))
        		{
        			file.mkdirs();
        		}
                list = getFilesFromMeta(key, f.path, cryptDir);
                files.addAll(list);
            }
            else if(f.path.startsWith(pathLimit))
            {
                InputStream in = new BufferedInputStream(new FileInputStream(cryptedFile));
                byte[] iv = readIV(in);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                in = new CipherInputStream(in, cipher);
                file.getParentFile().mkdirs();
                OutputStream out = new BufferedOutputStream(new FileOutputStream(file));
                copy(in, out);
                in.close();
                out.close();
                file.setLastModified(f.lastModified);
                System.out.println(file + " restored from " + cryptedFile);
            }
        }
    }

    public static SecretKey getKeyFromPassword(char[] password, byte[] salt)
        throws NoSuchAlgorithmException, InvalidKeySpecException 
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, 80000, 128);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    private static char[] hexa = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    
    public static String md5(File file) throws IOException
    {
        FileInputStream in = new FileInputStream(file);
        String md5 = md5(in);
        in.close();
        return md5;
    }

    public static String md5(InputStream in) throws IOException
    {
        Md5InputStream min = new Md5InputStream(new BufferedInputStream(in));
        byte[] buf = new byte[65536];
        int ret = min.read(buf);
        while (ret >= 0)
        {
            ret = min.read(buf);
        }
        return min.getMd5();
    }

    public static String toHex(byte[] data)
    {
        StringBuilder buf = new StringBuilder();
        for(int i=0;i<data.length;i++)
        {
            byte b = data[i];
            int hi = (b & 0xF0) >>> 4;
            int low = b & 0xF;
            buf.append(hexa[hi]);
            buf.append(hexa[low]);
        }
        return buf.toString();
    }
    
    public static byte[] fromHex(String hex)
    {
        byte[] data = new byte[hex.length()/2];
        for(int i=0;i<data.length;i++)
        {
            char hi = hex.charAt(i*2);
            char low = hex.charAt(i*2+1);
            byte b1 = convertHexDigit(hi);
            byte b2 = convertHexDigit(low);
            b1 = (byte)(b1 << 4);
            data[i] = (byte)(b1 + b2);
        }
        return data;
    }
    
    private static byte convertHexDigit(char c)
    {
        byte b = 0;
        switch(c)
        {
            case '0':
                b = 0;
            break;
            case '1':
                b = 1;
            break;
            case '2':
                b = 2;
            break;
            case '3':
                b = 3;
            break;
            case '4':
                b = 4;
            break;
            case '5':
                b = 5;
            break;
            case '6':
                b = 6;
            break;
            case '7':
                b = 7;
            break;
            case '8':
                b = 8;
            break;
            case '9':
                b = 9;
            break;
            case 'a':
                b = 10;
            break;
            case 'b':
                b = 11;
            break;
            case 'c':
                b = 12;
            break;
            case 'd':
                b = 13;
            break;
            case 'e':
                b = 14;
            break;
            case 'f':
                b = 15;
            break;
        }
        return b;
    }
    
    /**
     * Löschen einer Datei.
     * 
     * @param file
     *            Diese Datei wird gelöscht.
     * @param rekursiv
     *            Wenn true, dann werden Verzeichnisse Rekursiv gelöscht
     */
    public static void delete(File file, boolean rekursiv) throws IOException
    {
        if (file.exists() == false)
        {
            return;
        }
        if (file.isDirectory() && rekursiv)
        {
            String[] files = file.list();
            for (int i = 0; i < files.length; i++)
            {
                File f = new File(file, files[i]);
                delete(f, rekursiv);
            }
        }
        file.delete();
    }

}
