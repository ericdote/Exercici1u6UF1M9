package practica1u6;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Eric
 */
public class Desti {
    
    private byte[] missatgeXifrat;
    private Key kPrivada;
    
    public KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS"); // JCEKS ó JKS
        File f = new File(ksFile);
        if (f.isFile()) {            
            FileInputStream in = new FileInputStream(f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }
    
    public Key obtindreClauPrivada(String alias, String password){
        try {
            kPrivada = loadKeyStore(alias, password).getKey(alias, password.toCharArray());
        } catch (Exception ex) {
            Logger.getLogger(Desti.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kPrivada;
    }
    
   
}
