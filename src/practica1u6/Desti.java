package practica1u6;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * No comento aqui ya que es igual que el Origen, con la diferencia de que aqui
 * validamos y desciframos.
 *
 * @author Eric
 */
public class Desti {

    private PrivateKey kPrivada;
    private X509Certificate cert;
    private KeyStore kStore;

    public KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        kStore = KeyStore.getInstance("JCEKS"); // JCEKS ó JKS
        File f = new File(ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            kStore.load(in, ksPwd.toCharArray());
        }
        return kStore;
    }

    public Key obtindreClauPrivada(String alias, String password) {
        try {
            kPrivada = (PrivateKey) kStore.getKey(alias, password.toCharArray());
        } catch (Exception ex) {
            Logger.getLogger(Desti.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kPrivada;
    }

    public void obtindreCertificat(String alias) {
        try {
            cert = (X509Certificate) kStore.getCertificate(alias);
        } catch (KeyStoreException ex) {
            Logger.getLogger(Desti.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public boolean validarSignatura(byte[] missatgeXifrat, byte[] signature) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initVerify(cert.getPublicKey());
            signer.update(missatgeXifrat);
            isValid = signer.verify(signature);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException ex) {
            Logger.getLogger(Desti.class.getName()).log(Level.SEVERE, null, ex);
        }
        return isValid;
    }

    public byte[] desxifraDadesReceptor(byte[] missatgeXifrat) {
        byte[] missatge = null;
        try {
            Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            ci.init(Cipher.DECRYPT_MODE, kPrivada);
            missatge = ci.doFinal(missatgeXifrat);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            Logger.getLogger(Desti.class.getName()).log(Level.SEVERE, null, ex);
        }
        return missatge;
    }
}
