package de.exware.crypt2cloud;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Md5InputStream extends FilterInputStream
{
    private MessageDigest digest;
    
    public Md5InputStream(InputStream in)
    {
        super(in);
        try
        {
            digest = MessageDigest.getInstance("MD5");
        }
        catch (NoSuchAlgorithmException ex)
        {
            ex.printStackTrace();
        }
    }
    
    @Override
    public int read() throws IOException
    {
        int ret = super.read();
        if(ret >= 0)
        {
            digest.update((byte) (ret - 128));
        }
        return ret;
    }
    
    @Override
    public int read(byte[] b) throws IOException
    {
        return read(b,0,b.length);
    }
    
    @Override
    public int read(byte[] b, int off, int len) throws IOException
    {
        int ret = super.read(b, off, len);
        if(ret >= 0)
        {
            digest.update(b, off, ret);
        }
        return ret;
    }

    public String getMd5()
    {
        return Crypt2Cloud.toHex(digest.digest());
    }
}
