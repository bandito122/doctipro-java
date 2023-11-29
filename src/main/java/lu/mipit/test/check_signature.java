package lu.mipit.test;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import lu.mipit.utils.FichierConfig;
import org.apache.commons.codec.binary.Base64;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

public class check_signature {

    public static void main(String args[]) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        String serverUrl = FichierConfig.getProperty("serverUrl");
        String keyStorePath = FichierConfig.getProperty("keyStorePath");
        String keyStoreType = FichierConfig.getProperty("keyStoreType");
        String keyStorePassword = FichierConfig.getProperty("keyStorePassword");
        String trustStorePath = FichierConfig.getProperty("trustStorePath");
        String trustStoreType = FichierConfig.getProperty("trustStoreType");
        String trustStorePassword = FichierConfig.getProperty("trustStorePassword");
        String xml = FichierConfig.getProperty("xml");
        String xml_check_sign = FichierConfig.getProperty("xml_check_sign");
        String xml2_create_sign = FichierConfig.getProperty("xml2_create_sign");
        String privateKey_alias = FichierConfig.getProperty("privateKeyAlias");

        // Print the values to verify
        System.out.println("url=" + serverUrl);
        System.out.println("keyStorePath=" + keyStorePath);
        System.out.println("keyStoreType=" + keyStoreType);
        System.out.println("keyStorePassword=" + keyStorePassword);
        System.out.println("trustStorePath=" + trustStorePath);
        System.out.println("trustStoreType=" + trustStoreType);
        System.out.println("trustStorePassword=" + trustStorePassword);
        System.out.println("xml=" + xml);
        System.out.println("xml_check_sign=" + xml_check_sign);
        System.out.println("xml2_create_sign=" + xml2_create_sign);

        KeyStore ks = KeyStore.getInstance(keyStoreType);
        FileInputStream fis = new FileInputStream(keyStorePath);
        ks.load(fis, keyStorePassword.toCharArray());
        PrivateKey privateKey = (PrivateKey) ks.getKey(privateKey_alias, keyStorePassword.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(privateKey_alias);
        PublicKey publicKey = certificate.getPublicKey();
        System.out.println("public key = "  + publicKey.toString() );

        File file = new File(xml_check_sign);
        byte[] fileContent = new byte[(int) file.length()];

        try (FileInputStream fis2 = new FileInputStream(file)) {
            fis2.read(fileContent);
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] signature = Base64.decodeBase64("YAwQUxyxdXDYcWstp4S3H0YD+BubBIDMtlB87TfwGFgc7jUHgdlMtNpbAvoHa6y4FYs80rmAVsHjv2oOcmfu9yZB6juFCGkfgUrJ5w1OcKUv1bqvMEDVlJj6gPPQXicl14GlVDvu62XBZrmFXVq6yklVAyzkJevZZHTiCT2DZUo5ZynagPYpy97yand1nKtZ+yP0K9JASaRAvX1rQrEKdmJx2WANqtQ7fppaxjMYIeBWsUxjIwNaHFIayFRzimr5D1F3rWfaBncmU9OWkjBhNfwnUfg6jyG8BOKMvE4F/8b5x065ZiS7uivYrD4alrSXbbw8L30YiY9r90Z9ml1KoYD/ifwduroeEl+BbQKaRVeRKkT3GBqAZ6HSO4tm3ypJJ59Kzhfig0GebVBHBvxrdxmDwjNuouVuxSZOih3hGqwJcnN9dSz2QcVtNaviUTcnLJY5FP5tdQHMOgGig7iUmGd5kL11+DIi5tX/Xey6F7amtW0MmN5ImmBbiAxdY9H5HiJmsnKaJc+E2MNq+bPY1ovH0ID+BKE7ofARb+IApsr46fRVpwMCMCyX2hiVn/UIgQgL50Ld5JRzkP7iXFfCmepM/6QaRdvUREal2f1Sn8v/GcoR4J0NguIpbnoTzvY7Zw5aiaqA+dHYSv3fYzDV9VqMZZUc7RrKi4VQUwDJ1v0=");

        try {
            System.out.println(verify(fileContent, signature, publicKey));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

    }

    private static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws GeneralSecurityException{
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(data);
        return sig.verify(signature);
    }
}