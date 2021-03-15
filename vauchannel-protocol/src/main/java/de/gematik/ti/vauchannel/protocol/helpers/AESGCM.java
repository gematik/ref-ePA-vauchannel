/*
Copyright (c) 2020 gematik GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package de.gematik.ti.vauchannel.protocol.helpers;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** @author matthias.unverzagt */
public class AESGCM {

  //  96-Bit Nonce (IV) mit Ciphertext und 128 Bit Authentication-Tag
  public static final int AES_KEY_SIZE = 32; // in  bytes
  public static final int GCM_IV_LENGTH = 12; // in bytes
  public static final int GCM_TAG_LENGTH = 16; // in  bytes
  private static final Logger logger = LoggerFactory.getLogger(AESGCM.class);

  private static GCMParameterSpec getGCMParameterSpec(byte[] iv) {
    return new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
  }

  public static byte[] encrypt(byte[] input, byte[] key, long counter) throws Exception {
    return encrypt(input, key, null, counter);
  }

  public static byte[] encrypt(byte[] input, byte[] key) throws Exception {
    return encrypt(input, key, null);
  }

  public static byte[] encrypt(byte[] input, byte[] key, byte[] associatedData) throws Exception {
    byte[] iv = generateIV();
    return encrypt(input, key, associatedData, iv);
  }

  public static byte[] encrypt(byte[] input, byte[] key, byte[] associatedData, long counter)
      throws Exception {
    byte[] iv = generateIV(counter);
    return encrypt(input, key, associatedData, iv);
  }

  private static byte[] encrypt(byte[] input, byte[] key, byte[] associatedData, byte[] iv)
      throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
          BadPaddingException {
    SecretKey secretKey = new SecretKeySpec(key, "AES");
    byte[] encMessage;

    Cipher cipher = getCipher();

    byte[] cipherTextPlusTag;

    cipher.init(Cipher.ENCRYPT_MODE, secretKey, getGCMParameterSpec(iv));

    if (associatedData != null) {
      cipher.updateAAD(associatedData);
    }

    cipherTextPlusTag = cipher.doFinal(input);

    encMessage = Arrays.copyOf(iv, GCM_IV_LENGTH + cipherTextPlusTag.length);
    System.arraycopy(cipherTextPlusTag, 0, encMessage, GCM_IV_LENGTH, cipherTextPlusTag.length);

    return encMessage;
  }

  public static byte[] decrypt(byte[] encMessage, byte[] key) throws Exception {
    return decrypt(encMessage, key, null);
  }

  public static byte[] decrypt(byte[] encMessage, byte[] key, byte[] associatedData)
      throws Exception {
    SecretKey secretKey = new SecretKeySpec(key, "AES");
    byte[] plainText;
    byte[] iv = Arrays.copyOfRange(encMessage, 0, GCM_IV_LENGTH);
    byte[] cipherText = Arrays.copyOfRange(encMessage, GCM_IV_LENGTH, encMessage.length);
    Cipher cipher = getCipher();

    cipher.init(Cipher.DECRYPT_MODE, secretKey, getGCMParameterSpec(iv));

    if (associatedData != null) {
      cipher.updateAAD(associatedData);
    }

    plainText = cipher.doFinal(cipherText);

    return plainText;
  }

  private static Cipher getCipher() {
    try {
      return Cipher.getInstance("AES/GCM/NoPadding", "BC");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] generateIV() {
    byte[] iv = new byte[GCM_IV_LENGTH];
    ThreadLocalRandom.current().nextBytes(iv);
    return iv;
  }

  public static byte[] generateIV(long counter) {
    byte[] iv = new byte[GCM_IV_LENGTH];
    ThreadLocalRandom.current().nextBytes(iv);
    byte[] counterBytes = longToBytes(counter);
    System.arraycopy(counterBytes, 0, iv, GCM_IV_LENGTH - 8, counterBytes.length);
    return iv;
  }

  public static byte[] longToBytes(long x) {
    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.putLong(0, x);
    return buffer.array();
  }

  public static SecretKey keyFromBytes(byte[] encodedKey) {
    return new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
  }

  public static SecretKey generateSymmetricKey() {
    SecretKey key = null;
    try {
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(AES_KEY_SIZE * 8);
      key = keyGen.generateKey();
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
    }
    return key;
  }

  public static CipherOutputStream encrypt(OutputStream os, byte[] key) {

    byte[] iv = generateIV();
    CipherOutputStream cos = null;
    try {
      os.write(iv);

      SecretKey secretKey = new SecretKeySpec(key, "AES");
      Cipher cipher = getCipher();
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, getGCMParameterSpec(iv));

      cos = new CipherOutputStream(os, (StreamCipher) cipher);
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
    }
    return cos;
  }
}
