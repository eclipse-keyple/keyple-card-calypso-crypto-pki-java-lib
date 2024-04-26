/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.card.calypso.crypto.pki;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2PSSSigner;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;

/**
 * Provides utility methods for field format and cryptographic operations.
 *
 * @since 0.1.0
 */
class CertificateUtils {

  private static final int RSA_SIGNATURE_SIZE = 256;

  /** Private constructor */
  private CertificateUtils() {}

  /**
   * Ensures that the provided key is a valid RSA 2048 bits public key with a modulus of 65537,
   * throwing appropriate exceptions if not.
   *
   * @param rsaPublicKey The key to check.
   * @throws IllegalArgumentException if the provided key is not a 2048-bit RSA key, or has a
   *     modulus different from 65537.
   * @since 0.1.0
   */
  static void checkRSA2048PublicKey(RSAPublicKey rsaPublicKey) {
    // Check for 2048 bits length
    if (rsaPublicKey.getModulus().bitLength() != 2048) {
      throw new IllegalArgumentException("Public key must be 2048 bits");
    }
    // Check for public exponent 65537
    if (!rsaPublicKey.getPublicExponent().equals(BigInteger.valueOf(65537))) {
      throw new IllegalArgumentException("Public key's exponent must be 65537");
    }
  }

  /**
   * Creates a 2048 bits {@link RSAPublicKey} with a public exponent equal to 65537 from the
   * provided modulus value.
   *
   * @param modulus A 256-byte byte array representing the modulus value.
   * @return A non-null {@link RSAPublicKey} instance.
   * @throws AsymmetricCryptoException if the provided modulus is invalid or if an error occurred
   *     during the cryptographic operations.
   * @since 0.1.0
   */
  static RSAPublicKey generateRSAPublicKeyFromModulus(byte[] modulus)
      throws AsymmetricCryptoException {
    // Convert modulus to BigInteger
    BigInteger modulusBigInt = new BigInteger(1, modulus);

    // Define public exponent
    BigInteger publicExponent = BigInteger.valueOf(65537);

    try {
      // Create RSAPublicKey using KeyFactory (assuming Bouncy Castle is available)
      KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
      return (RSAPublicKey)
          keyFactory.generatePublic(new RSAPublicKeySpec(modulusBigInt, publicExponent));
    } catch (NoSuchAlgorithmException e) {
      throw new AsymmetricCryptoException(e.getMessage(), e);
    } catch (NoSuchProviderException e) {
      throw new AsymmetricCryptoException(e.getMessage(), e);
    } catch (InvalidKeySpecException e) {
      throw new AsymmetricCryptoException(e.getMessage(), e);
    }
  }

  /**
   * Validates the signature of the provided certificate using the public key from the issuer's
   * certificate content and recovers the message data embedded within the signature according to
   * the ISO 9796-2 scheme.
   *
   * <p>The method uses RSA public key parameters extracted from the issuer's certificate and
   * applies the ISO9796d2 PSS (Probabilistic Signature Scheme) Signer mechanism for signature
   * verification and message recovery. The signature to be verified is expected to be occupying the
   * last 256 bytes of the certificate array.
   *
   * <p>If the signature is successfully verified, the method returns the recovered message data; if
   * the signature verification fails, it throws a {@link CertificateValidationException}.
   *
   * <p>Note: This method assumes the use of SHA-256 for message digest during the signature
   * process.
   *
   * @param certificate The byte array containing the certificate data along with the signature.
   * @param issuerPublicKey The issuer public key.
   * @return a byte array containing the recovered message data if the signature is valid.
   * @throws AsymmetricCryptoException If there is an issue with the cryptographic operations.
   * @throws CertificateValidationException If the signature verification fails.
   * @since 0.1.0
   */
  static byte[] checkCertificateSignatureAndRecoverData(
      byte[] certificate, RSAPublicKey issuerPublicKey)
      throws AsymmetricCryptoException, CertificateValidationException {
    RSAKeyParameters pubParams =
        new RSAKeyParameters(
            false, issuerPublicKey.getModulus(), issuerPublicKey.getPublicExponent());

    ISO9796d2PSSSigner pssSign =
        new ISO9796d2PSSSigner(new RSAEngine(), new SHA256Digest(), 0, true);

    pssSign.init(false, pubParams);

    try {
      pssSign.updateWithRecoveredMessage(
          Arrays.copyOfRange(
              certificate, certificate.length - RSA_SIGNATURE_SIZE, certificate.length));
    } catch (InvalidCipherTextException e) {
      throw new AsymmetricCryptoException(e.getMessage(), e);
    }

    pssSign.update(certificate, 0, certificate.length - 256);

    byte[] signature =
        Arrays.copyOfRange(certificate, certificate.length - 256, certificate.length);
    if (!pssSign.verifySignature(signature)) {
      throw new CertificateValidationException("Challenge PSS certificate verification failed");
    }

    return pssSign.getRecoveredMessage();
  }

  /**
   * Retrieves the current date and converts it into a BCD (Binary-Coded Decimal) format.
   *
   * <p>This method uses the system's current date, as provided by the Calendar class, and formats
   * it into a long value in BCD format, where the year occupies the highest 16 bits, the month the
   * next 8 bits, and the day the lowest 8 bits. The resulting BCD format is 0xYYYYMMDD, where YYYY
   * represents the four-digit year, MM the two-digit month, and DD the two-digit day.
   *
   * @return The current date in long format as BCD representing 0xYYYYMMDD.
   * @since 0.1.0
   */
  static long getCurrentDateAsBcdLong() {
    Calendar calendar = Calendar.getInstance();
    return convertDateToBcdLong(
        calendar.get(Calendar.YEAR),
        calendar.get(Calendar.MONTH) + 1,
        calendar.get(Calendar.DAY_OF_MONTH));
  }

  /**
   * Converts the provided date into a long. It is in BCD format 0xYYYYMMDD, where YYYY represents
   * the four-digit year, MM the two-digit month, and DD the two-digit day.
   *
   * @param year The year (0-9999).
   * @param month The month (1-99).
   * @param day The day (1-99).
   * @return A long in BCD format.
   * @since 0.1.0
   */
  static long convertDateToBcdLong(int year, int month, int day) {
    long bcdYear =
        ((long) (year / 1000) << 12)
            | ((year / 100 % 10) << 8)
            | ((year % 100 / 10) << 4)
            | (year % 10);
    long bcdMonth = ((long) (month / 10) << 4) | (month % 10);
    long bcdDay = ((long) (day / 10) << 4) | (day % 10);
    return (bcdYear << 16) | (bcdMonth << 8) | bcdDay;
  }

  static boolean isAidValidForIssuer(byte[] aid, CaCertificateContentSpi issuerCertificateContent) {
    if (!issuerCertificateContent.isAidCheckRequested()) {
      return true;
    }

    byte[] issuerAid = issuerCertificateContent.getAid();

    boolean isAidValid = true;

    if (issuerCertificateContent.isAidTruncated()) {
      if (aid.length < issuerAid.length
          || !Arrays.equals(Arrays.copyOf(aid, issuerAid.length), issuerAid)) {
        isAidValid = false;
      }
    } else {
      if (!Arrays.equals(aid, issuerAid)) {
        isAidValid = false;
      }
    }
    return isAidValid;
  }
}
