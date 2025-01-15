package com.silkimen.cordovahttp;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.ArrayList;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.silkimen.http.TLSConfiguration;

import org.apache.cordova.CallbackContext;

import android.app.Activity;
import android.util.Log;
import android.content.res.AssetManager;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import android.os.Process;

import android.app.AlertDialog;
import android.os.Handler;
import android.os.Looper;
class CordovaServerTrust implements Runnable {
  private static final String publicKeyContent = "";
  private static final String TAG = "Cordova-Plugin-HTTP";

  private final TrustManager[] noOpTrustManagers;
  private final HostnameVerifier noOpVerifier;

  private String mode;
  private Activity activity;
  private TLSConfiguration tlsConfiguration;
  private CallbackContext callbackContext;

  public CordovaServerTrust(final String mode, final Activity activity, final TLSConfiguration configContainer,
      final CallbackContext callbackContext) {

    this.mode = mode;
    this.activity = activity;
    this.tlsConfiguration = configContainer;
    this.callbackContext = callbackContext;

    this.noOpTrustManagers = new TrustManager[] { new X509TrustManager() {
      public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
      }

      public void checkClientTrusted(X509Certificate[] chain, String authType) {
        // intentionally left blank
      }

      public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // intentionally left blank
      }
    } };

    this.noOpVerifier = new HostnameVerifier() {
      public boolean verify(String hostname, SSLSession session) {
        return true;
      }
    };
  }

  @Override
  public void run() {
    try {
      /*if ("legacy".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(null);
        this.tlsConfiguration.setTrustManagers(null);
      } else if ("nocheck".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(this.noOpVerifier);
        this.tlsConfiguration.setTrustManagers(this.noOpTrustManagers);
      } else if ("pinned".equals(this.mode)) {*/
        this.tlsConfiguration.setHostnameVerifier(null);
        this.tlsConfiguration.setTrustManagers(this.getTrustManagers(this.getCertsFromBundle("www/certificates")));
      /*} else {
        this.tlsConfiguration.setHostnameVerifier(null);
        this.tlsConfiguration.setTrustManagers(this.getTrustManagers(this.getCertsFromKeyStore("AndroidCAStore")));
      }*/

      callbackContext.success();
    } catch (Exception e) {
      Log.e(TAG, "An error occured while configuring SSL cert mode", e);
      callbackContext.error("An error occured while configuring SSL cert mode");
      // Show alert on the main (UI) thread
      new Handler(Looper.getMainLooper()).post(() -> {
            new AlertDialog.Builder(this.activity)
                    .setTitle("")
                    .setMessage("An error occured while configuring SSL cert mode")
                    .setPositiveButton("OK",  (dialog, which) -> { 
                    })
                    .setCancelable(false) // Prevent dismiss by tapping outside or back button
                    .create()
                    .show();
        });
      try {
            // Sleep for 5 seconds (5000 milliseconds)
            Thread.sleep(5000);  // This may throw an InterruptedException
        } catch (InterruptedException ex) {
            // Handle the interruption here
            ex.printStackTrace();
        }
      closeApp();
    }
  }
  
    private void closeApp() {
        this.activity.runOnUiThread(() -> {
            this.activity.finish();
            Process.killProcess(Process.myPid());
        });
    }

  private TrustManager[] getTrustManagers(KeyStore store) throws GeneralSecurityException {
    String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
    tmf.init(store);

    return tmf.getTrustManagers();
  }

  private KeyStore getCertsFromBundle(String path) throws GeneralSecurityException, IOException, Exception {
    AssetManager assetManager = this.activity.getAssets();
    String[] files = assetManager.list(path);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    String keyStoreType = KeyStore.getDefaultType();
    KeyStore keyStore = KeyStore.getInstance(keyStoreType);

    keyStore.load(null, null);

    for (int i = 0; i < files.length; i++) {
      int index = files[i].lastIndexOf('.');

      if (index == -1 || !files[i].substring(index).equals(".cer")) {
        continue;
      }
      /*String publicKeyContent = "-----BEGIN PUBLIC KEY-----"
				+"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzWw6ESqeJ86TIJngPddz"
				+"CpD7r6Q2GNnQFtxMbQRkjH3W+NnHxG8onJ3eeEGcn2dsiu3zVKWzLPNd54veqfTb"
				+"fGhqXRoxFZaRj3tQWl+rCQC12S68TZe+sT7E/RE5YxoIsZn+Qgm6LjLJS/1yLZKz"
				+"086i1qooSx/+nYq2stBXgWy/6FGu5RbMj2hIBLGagcMVMwuhgeuXcsDcTRc/qaLa"
				+"xjG4YVwkA0+Bo4DO+GLhVEd1EdYA20/BKFfpb6MTvehDwY5kb14Ny4O2Pp3ocSaw"
				+"KixLMtu+cSOrCDGbS75uO2SrSvnkmwA5XWo7+5Zc7h28rMC87qIuGR7vjfHn7VGD"
				+"aQIDAQAB"
				+"-----END PUBLIC KEY-----";
        // Remove the first and last lines (the PEM header and footer)
        publicKeyContent = publicKeyContent
                .replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");*/

        Log.d("CordovaServerTrust","publicKeyContent: "+publicKeyContent);
        // Decode the base64 public key
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyContent);

        // Create the public key
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        // Decrypt the signature (Base64 encoded) to verify
        Log.d("CordovaServerTrust","try get the certificate data from path "+path + "/" + files[i]);
		String encryptedData = readFile(path + "/" + files[i],assetManager);
      Log.d("CordovaServerTrust","certificate data : "+encryptedData);
      ArrayList<String> chunks = new ArrayList<>();
      // Remove brackets and split by commas, handling each chunk
            String[] rawChunks = encryptedData.toString()
                    .replace("[", "")     // Remove starting bracket
                    .replace("]", "")     // Remove ending bracket
                    .replace("\"", "")    // Remove double quotes
                    .split(",");          // Split by commas
 
            // Add each chunk to the ArrayList
            for (String chunk : rawChunks) {
                chunks.add(chunk.trim());
              Log.d("CordovaServerTrust","chunk "+chunk);
            }
      
		/*String[] encryptedDataArray = encryptedData.split("_");
		// AES IV and encrypted AES key and data (replace with actual values)
        String encryptedDataBase64 = encryptedDataArray[0];
        String encryptedAesKeyBase64 = encryptedDataArray[1];
        String aesIvBase64 = encryptedDataArray[2];
		// Step 1: Decrypt the AES key using the public key
        byte[] encryptedAesKey = Base64.getDecoder().decode(encryptedAesKeyBase64);
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] aesKey = rsaCipher.doFinal(encryptedAesKey);

        // Step 2: Decrypt the data using the AES key
        byte[] aesIv = Base64.getDecoder().decode(aesIvBase64);
        byte[] encryptedDataBytes = Base64.getDecoder().decode(encryptedDataBase64);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(aesIv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec, ivSpec);
        byte[] decryptedBytes = aesCipher.doFinal(encryptedDataBytes);*/
        //byte[] encryptedDataBase64 = Base64.getDecoder().decode(encryptedData);
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, publicKey);
        //byte[] decryptedBytes = rsaCipher.doFinal(encryptedDataBase64);
        StringBuilder decryptedData = new StringBuilder(); 
        // Decrypt each chunk and append the result
        byte[] fullDecryptedChunk=new byte[0];
        for (String encryptedChunkBase64 :chunks) {
            byte[] encryptedChunkBytes = Base64.getDecoder().decode(encryptedChunkBase64);
            byte[] decryptedChunk = rsaCipher.doFinal(encryptedChunkBytes);
            decryptedData.append(new String(decryptedChunk, StandardCharsets.UTF_8));
            fullDecryptedChunk=concatenateByteArrays(fullDecryptedChunk, decryptedChunk);
        }
 
        //String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
        byte[] decryptedBytes = decryptedData.toString().getBytes(StandardCharsets.UTF_8);
        Log.d("CordovaServerTrust","Decrypted certificate: " + decryptedData);

        keyStore.setCertificateEntry("CA" + i, cf.generateCertificate(new ByteArrayInputStream(fullDecryptedChunk)));
    }

    return keyStore;
  }
  private byte[] concatenateByteArrays(byte[] array1, byte[] array2) {
    byte[] result = new byte[array1.length + array2.length];
    System.arraycopy(array1, 0, result, 0, array1.length);
    System.arraycopy(array2, 0, result, array1.length, array2.length);
    return result;
}
 private String readFile(String path,AssetManager assetManager)
  throws IOException
{
  InputStream encryptedInputStream =assetManager.open(path);// Files.readAllBytes(Paths.get(path));
  byte[] encoded = new byte[encryptedInputStream.available()];
    encryptedInputStream.read(encoded);
    encryptedInputStream.close();
  return new String(encoded, StandardCharsets.UTF_8);
}
  private KeyStore getCertsFromKeyStore(String storeType) throws GeneralSecurityException, IOException {
    KeyStore store = KeyStore.getInstance(storeType);
    store.load(null);

    return store;
  }
}
