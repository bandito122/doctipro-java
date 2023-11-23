/*
 * SSL.java
 * Date de cr�ation: 15 juin 2015
 * Auteur: u156gm
 *
 * Copyright (c) 2015 by CISS
 *
 * Modifications:
 * --------------
 *
 * Notes:
 * ------
 *
 */

package lu.ciss.mysecu.demo.inttest;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import lu.ciss.mysecu.demo.wsse.HTTPClient;

/**
 * D�monstration du test d'int�gration SSL de mySecu
 *
 * Il s'agit de tester l'int�gration de l'authentification SSL cliente.
 * URL du service /ws/soap/inttest/ssl
 *
 * ATTENTION:
 * IL S'AGIT D'UN PROJET DE DEMONSTRATION. IL EST DECONSEILE DE L'UTILISER EN PRODUCTION.
 *
 * Les arguments suivants sont � fournir en argument:
 * <ol>
 * <li> args[0]: l'URL compl�te du serveur </li>
 * <li> args[1]: le chemin vers le keystore contenant la clef priv�e du client </li>
 * <li> args[2]: le type du keystore (JKS || PKCS12) </li>
 * <li> args[3]: le mot de passe pour ouvrir le keystore </li>
 * <li> args[4]: le chemin vers le truststore contenant le certificat du serveur mySecu </li>
 * <li> args[5]: le type du truststore (JKS || PKCS12) </li>
 * <li> args[6]: le mot de passe pour ouvrir le truststore </li>
 * </ol>
 *
 * Le test s'ex�cut� avec succ�s lorsque le code de retour du serveur correspond � 200.
 *
 * Les configurations SSL sont faites par {@link HTTPClient}
 *
 * @author u156gm
 * @version $Id: SSL.java 16672 2015-06-30 14:26:21Z u156gm $
 * @since REL_1-0-0
 *
 * @see HTTPClient
 */
public class SSL {

    /**
     * Affiche l'ent�te du programme
     */
    public static void printHeader() {
        System.out.println("*********************************************");
        System.out.println("mySecu D�monstration: Tests d'int�gration");
        System.out.println("/ws/soap/inttest/ssl");
        System.out.println("*********************************************");
    }

    /**
     * {@inheritDoc}
     */
    public static void main(String args[]) throws IOException {
        printHeader();
        // 1.) cr�ation de l'URL de connexion
        URL url = new URL(args[0]);
        System.out.println("URL sp�cifi�e:" + url);

        HttpURLConnection connection = HTTPClient.getHTTPConnection(url, args[1], args[2],
                                                                    args[3], args[4], args[5], args[6]);
        String resultat = HTTPClient.doGET(connection);
        if (resultat != null) {
            System.out.println("R�ponse du serveur:");
            System.out.println(resultat);
        }
        else {
            System.exit(1);
        }
        System.exit(0);
    }
}