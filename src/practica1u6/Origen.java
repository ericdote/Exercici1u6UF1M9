package practica1u6;

import java.io.File;
import java.io.FileInputStream;
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
 *
 * @author Eric
 */
public class Origen {

    private PrivateKey kPrivada;
    private X509Certificate cert;
    private KeyStore kStore;

    /**
     * Metode que carrega la KeyStore
     *
     * @param ksFile
     * @param ksPwd
     * @return
     * @throws Exception
     */
    public KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        kStore = KeyStore.getInstance("JCEKS"); // JCEKS ó JKS
        File f = new File(ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            kStore.load(in, ksPwd.toCharArray());
        }
        return kStore;
    }

    /**
     * Metode que obte la clau privada.
     *
     * @param alias
     * @param password
     * @return
     */
    public Key obtindreClauPrivada(String alias, String password) {
        try {
            kPrivada = (PrivateKey) loadKeyStore(alias, password).getKey(alias, password.toCharArray());
        } catch (Exception ex) {
            Logger.getLogger(Origen.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kPrivada;
    }

    /**
     * Metode que obte el certificat del desti
     *
     * @param alias
     */
    public void obtindreCertificat(String alias) {
        try {
            cert = (X509Certificate) kStore.getCertificate(alias);
        } catch (KeyStoreException ex) {
            Logger.getLogger(Origen.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Metode que xifra el missatge
     *
     * @param missatge
     * @return
     */
    public byte[] xifrar(String missatge) {
        byte[] buffer = new byte[1024];
        try {
            Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            ci.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
            buffer = ci.doFinal(missatge.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            Logger.getLogger(Origen.class.getName()).log(Level.SEVERE, null, ex);
        }
        return buffer;
    }
    /**
     * Metode que signa el missatge xifrat
     * @param missatgeXifrat
     * @return 
     */
    public byte[] signar(byte[] missatgeXifrat) {
        byte[] sign = null;
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(kPrivada);
            signer.update(missatgeXifrat);
            sign = signer.sign();

            return sign;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Origen.class.getName()).log(Level.SEVERE, null, ex);
        }
        return sign;
    }

}
