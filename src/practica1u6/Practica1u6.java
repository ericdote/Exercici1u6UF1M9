package practica1u6;

/**
 *
 * @author Eric
 */
public class Practica1u6 {

    public static void main(String[] args) throws Exception {
        String rutaKeyStoreDesti = "src\\SSL\\desti.jks";
        String rutaKeyStoreOrigen = "src\\SSL\\origen.jks";
        Origen o = new Origen();
        Desti d = new Desti();
        String password = "123456", missatge = "Probando";

        //Carregem la KeyStore
        o.loadKeyStore(rutaKeyStoreOrigen, password);
        //Obtenim la clau privada
        o.obtindreClauPrivada("origen", password);
        //Obtenim el certificat del Desti
        o.obtindreCertificat("desticert");
        //Xifrem i signem el missatge
        byte[] missatgeXifrat = o.xifrar(missatge);
        byte[] sign = o.signar(missatgeXifrat);

        //Lo mateix que abans pero amb desti
        d.loadKeyStore(rutaKeyStoreDesti, password);
        d.obtindreClauPrivada("desti", password);
        d.obtindreCertificat("origencert");
        //Validem la signatura
        if (d.validarSignatura(missatgeXifrat, sign)) {
            //Desxifrem si es valida
            byte[] missatgeDesxifrat = d.desxifraDadesReceptor(missatgeXifrat);
            System.out.println("Devolviendo bien: " + new String(missatgeDesxifrat));
        } else {
            System.out.println("No es pot verificar");
        }

    }

}
