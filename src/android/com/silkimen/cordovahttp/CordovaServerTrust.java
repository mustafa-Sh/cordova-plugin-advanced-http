package com.silkimen.cordovahttp;

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

class CordovaServerTrust implements Runnable {
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
      if ("legacy".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(null);
        this.tlsConfiguration.setTrustManagers(null);
      } else if ("nocheck".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(this.noOpVerifier);
        this.tlsConfiguration.setTrustManagers(this.noOpTrustManagers);
      } else if ("pinned".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(null);
        Log.e(TAG, "call getCertsFromBundle()");
        callbackContext.error("call getCertsFromBundle()");
        this.tlsConfiguration
            .setTrustManagers(this.getTrustManagers(this.getCertsFromBundle("www/assets/certificates")));
      } else {
        this.tlsConfiguration.setHostnameVerifier(null);
        this.tlsConfiguration.setTrustManagers(this.getTrustManagers(this.getCertsFromKeyStore("AndroidCAStore")));
      }

      callbackContext.success();
    } catch (Exception e) {
      Log.e(TAG, "An error occured while configuring SSL cert mode", e);
      callbackContext.error("An error occured while configuring SSL cert mode");
    }
  }

  private TrustManager[] getTrustManagers(KeyStore store) throws GeneralSecurityException {
    String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
    tmf.init(store);

    return tmf.getTrustManagers();
  }

  private KeyStore getCertsFromBundle(String path) throws GeneralSecurityException, IOException {
    Log.e(TAG, "getCertsFromBundle() called");
    callbackContext.error("getCertsFromBundle() called");
    AssetManager assetManager = this.activity.getAssets();
    Log.e(TAG, "assetManager: " + assetManager);
    callbackContext.error("assetManager: " + assetManager);
    String[] files = assetManager.list(path);
    Log.e(TAG, "files: " + files);
    callbackContext.error("files: " + files);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    Log.e(TAG, "cf: " + cf);
    callbackContext.error("cf: " + cf);
    String keyStoreType = KeyStore.getDefaultType();
    Log.e(TAG, "keyStoreType: " + keyStoreType);
    callbackContext.error("keyStoreType: " + keyStoreType);
    KeyStore keyStore = KeyStore.getInstance(keyStoreType);
    Log.e(TAG, "keyStore1: " + keyStore);
    callbackContext.error("keyStore1: " + keyStore);

    keyStore.load(null, null);

    for (int i = 0; i < files.length; i++) {
      int index = files[i].lastIndexOf('.');
      Log.e(TAG, "index: " + index);
      callbackContext.error("index: " + index);
      Log.e(TAG, "files[i]: " + files[i]);
      callbackContext.error("files[i]: " + files[i]);

      if (index == -1 || !files[i].substring(index).equals(".cer")) {
        continue;
      }

      keyStore.setCertificateEntry("CA" + i, cf.generateCertificate(assetManager.open(path + "/" + files[i])));
    }

    Log.e(TAG, "keyStore2: " + keyStore);
    callbackContext.error("keyStore2: " + keyStore);
    return keyStore;
  }

  private KeyStore getCertsFromKeyStore(String storeType) throws GeneralSecurityException, IOException {
    KeyStore store = KeyStore.getInstance(storeType);
    store.load(null);
    Log.e(TAG, "store: " + store);
    callbackContext.error("store: " + store);

    return store;
  }
}
