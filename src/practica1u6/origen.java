package practica1u6;

import java.io.File;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Eric
 */
public class origen {
    
    private byte[] missatgeXifrat;

    public KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS"); // JCEKS ó JKS
        File f = new File(ksFile);
        if (f.isFile()) {            
            FileInputStream in = new FileInputStream(f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }
    
    /**
     * Metode que li arriba una cadena de String i una clau publica. Un cop li
     * arriba el String el passa a bytes i el xifra en forma asimetrica
     *
     * @param missatge_text
     * @param pub
     */
    public void xifraDadesEmissor(String missatge_text, PublicKey pub) {
        
        try {
            byte[] buffer = missatge_text.getBytes("UTF-8");
            Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            ci.init(Cipher.ENCRYPT_MODE, pub);
            missatgeXifrat = ci.doFinal(buffer);
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(origen.class.getName()).log(Level.SEVERE, null, ex);
        }
         
    }

}
