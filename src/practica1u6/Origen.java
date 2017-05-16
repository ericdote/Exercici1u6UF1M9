package practica1u6;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Eric
 */
public class Origen {
    
    private PrivateKey kPrivada;
    private X509Certificate certPriv, certPub;
    private PublicKey kPublica;
    
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
            kPrivada = (PrivateKey) loadKeyStore(alias, password).getKey(alias, password.toCharArray());
        } catch (Exception ex) {
            Logger.getLogger(Desti.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kPrivada;
    }
     
     public void obtindreCertificat(String alias){
          
     }
     
     public void obtenidreClauPublica(){
         kPublica = certPub.getPublicKey();
     }
    
}
