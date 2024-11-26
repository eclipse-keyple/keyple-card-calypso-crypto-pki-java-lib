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
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import org.bouncycastle.asn1.*;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.transaction.spi.CardTransactionCryptoExtension;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardPublicKeySpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.transaction.spi.AsymmetricCryptoCardTransactionManagerSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link AsymmetricCryptoCardTransactionManagerSpi} & {@link
 * CardTransactionCryptoExtension}.
 *
 * @since 0.1.0
 */
final class AsymmetricCryptoCardTransactionManagerAdapter
    implements AsymmetricCryptoCardTransactionManagerSpi, CardTransactionCryptoExtension {

  private static final Logger logger =
      LoggerFactory.getLogger(AsymmetricCryptoCardTransactionManagerAdapter.class);

  private static final String CARD_SESSION_SIGNATURE_SCHEME = "SHA256withECDSA";
  private static final String BOUNCY_CASTLE = "BC";
  private static final String ELLIPTIC_CURVE = "EC";
  private static final String EC_DOMAIN_PARAMETERS_NAME = "secp256r1";
  private final Signature signature;
  private final KeyFactory keyFactory;
  private final ECParameterSpec ecParameterSpec;
  private boolean isRequest = true;

  /**
   * Constructor
   *
   * <p>Initializes the necessary cryptographic components used for card transaction management.
   *
   * @throws IllegalStateException If an error occurs during the initialization process.
   * @since 0.1.0
   */
  AsymmetricCryptoCardTransactionManagerAdapter() {
    try {
      signature = Signature.getInstance(CARD_SESSION_SIGNATURE_SCHEME, BOUNCY_CASTLE);
      AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(ELLIPTIC_CURVE);
      algorithmParameters.init(new ECGenParameterSpec(EC_DOMAIN_PARAMETERS_NAME));
      ecParameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);
      keyFactory = KeyFactory.getInstance(ELLIPTIC_CURVE);
    } catch (NoSuchAlgorithmException | InvalidParameterSpecException | NoSuchProviderException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public void initTerminalPkiSession(CardPublicKeySpi cardPublicKey)
      throws AsymmetricCryptoException {
    if (logger.isTraceEnabled()) {
      String cardPublicKeyHex = HexUtil.toHex(cardPublicKey.getRawValue());
      logger.trace("Card public key: {}", cardPublicKeyHex);
    }
    try {
      byte[] cardPub = cardPublicKey.getRawValue();
      ECPoint ecPoint =
          new ECPoint(
              new BigInteger(1, Arrays.copyOfRange(cardPub, 0, 32)),
              new BigInteger(1, Arrays.copyOfRange(cardPub, 32, 64)));
      ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
      PublicKey publicKey = keyFactory.generatePublic(ecPublicKeySpec);
      signature.initVerify(publicKey);
      signature.update((byte) 0x10); // see requirement R203
    } catch (Exception e) {
      throw new AsymmetricCryptoException(e.getMessage(), e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public void updateTerminalPkiSession(byte[] cardApdu) throws AsymmetricCryptoException {
    try {
      byte[] dataToHash;
      if (isRequest && cardApdu[4] == cardApdu.length - 6) {
        // case 4 command, we ignore Le
        dataToHash = Arrays.copyOf(cardApdu, cardApdu.length - 1);
      } else {
        dataToHash = cardApdu;
      }
      if (logger.isTraceEnabled()) {
        String dataToHashHex = HexUtil.toHex(dataToHash);
        logger.trace("Update hash with: {}", dataToHashHex);
      }
      signature.update((byte) dataToHash.length);
      signature.update(dataToHash);
      isRequest = !isRequest;
    } catch (Exception e) {
      throw new AsymmetricCryptoException(e.getMessage(), e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isCardPkiSessionValid(byte[] cardSessionSignature)
      throws AsymmetricCryptoException {
    try {
      // Creates a DER sequence containing the first 32 bytes and the next 32 bytes from
      // cardSessionSignature as separate integers.
      BigInteger r = new BigInteger(1, Arrays.copyOfRange(cardSessionSignature, 0, 32));
      BigInteger s = new BigInteger(1, Arrays.copyOfRange(cardSessionSignature, 32, 64));

      // Ensure that r and s are not zero to prevent invalid signatures
      if (r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO)) {
        throw new AsymmetricCryptoException(
            "Invalid ECDSA signature: r or s is zero, rejecting signature.");
      }

      // Encodes the DER sequence into a byte array.
      DERSequence asn1Signature =
          new DERSequence(new ASN1Integer[] {new ASN1Integer(r), new ASN1Integer(s)});
      byte[] asn1EncodedSignature = asn1Signature.getEncoded();

      return signature.verify(asn1EncodedSignature);
    } catch (Exception e) {
      throw new AsymmetricCryptoException(e.getMessage(), e);
    }
  }
}
