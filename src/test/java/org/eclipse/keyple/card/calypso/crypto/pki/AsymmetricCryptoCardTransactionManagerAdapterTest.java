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

import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardPublicKeySpi;
import org.junit.Before;
import org.junit.Test;

public class AsymmetricCryptoCardTransactionManagerAdapterTest {

  private Signature mockSignature;
  private AsymmetricCryptoCardTransactionManagerAdapter adapter;
  private static final String ECC_KEY_VALID =
      "7D6E7314CA9B2E601FBF4CA144979B88F996D8A04D9F1E63E61CBECFBD0B0DE0ED84C5A052BFDAF1BC496762CE3ACB046C64959E1938ACA18DF97C278EFEE271";
  private static final String ECC_KEY_INVALID = "FFFF";
  private static final String ZERO_VALUE =
      "0000000000000000000000000000000000000000000000000000000000000000";
  private static final String VALID_VALUE =
      "7D6E7314CA9B2E601FBF4CA144979B88F996D8A04D9F1E63E61CBECFBD0B0DE0";

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Before
  public void setUp() throws Exception {
    mockSignature = mock(Signature.class);
    adapter =
        new AsymmetricCryptoCardTransactionManagerAdapter(); // Adjust based on actual constructor
    Field signatureField =
        AsymmetricCryptoCardTransactionManagerAdapter.class.getDeclaredField("signature");
    signatureField.setAccessible(true);
    signatureField.set(adapter, mockSignature);
  }

  @Test
  public void initTerminalPkiSession_whenPublicKeyIsValid_shouldInitializeSignature()
      throws Exception {
    // Mock a valid CardPublicKeySpi
    CardPublicKeySpi mockPublicKey = mock(CardPublicKeySpi.class);
    byte[] validPublicKey = HexUtil.toByteArray(ECC_KEY_VALID);
    when(mockPublicKey.getRawValue()).thenReturn(validPublicKey);

    // Create and initialize the adapter
    AsymmetricCryptoCardTransactionManagerAdapter adapter =
        new AsymmetricCryptoCardTransactionManagerAdapter();
    adapter.initTerminalPkiSession(mockPublicKey);

    // Verify signature initialization
    // ... assertions on signature object state (e.g., initialized for verification)
  }

  @Test(expected = AsymmetricCryptoException.class)
  public void initTerminalPkiSession_whenPublicKeyIsInvalid_shouldThrowICPE() throws Exception {
    // Mock an invalid CardPublicKeySpi
    CardPublicKeySpi mockPublicKey = mock(CardPublicKeySpi.class);
    byte[] invalidPublicKey = HexUtil.toByteArray(ECC_KEY_INVALID);
    when(mockPublicKey.getRawValue()).thenReturn(invalidPublicKey);

    // Create and initialize the adapter (should throw exception)
    AsymmetricCryptoCardTransactionManagerAdapter adapter =
        new AsymmetricCryptoCardTransactionManagerAdapter();
    adapter.initTerminalPkiSession(mockPublicKey);
  }

  @Test
  public void updateTerminalPkiSession_whenAPDUsAreValid_shouldUpdateSignature()
      throws AsymmetricCryptoException, SignatureException {
    byte[] cardApdu = {1, 2, 3, 4, 5};

    // First call, isRequest should be true
    adapter.updateTerminalPkiSession(cardApdu);
    verify(mockSignature, times(1)).update((byte) cardApdu.length);
    verify(mockSignature, times(1)).update(cardApdu);

    reset(mockSignature);

    // Second call, isRequest should be false
    adapter.updateTerminalPkiSession(new byte[] {6, 7, 8, 9, 10, 11});

    verify(mockSignature, times(1)).update((byte) 6);
    verify(mockSignature, times(1)).update(any(byte[].class));
  }

  @Test(expected = AsymmetricCryptoException.class)
  public void isCardPkiSessionValid_whenBothComponentsAreZero_shouldThrowAsymmetricCryptoException()
      throws Exception {
    adapter.isCardPkiSessionValid(HexUtil.toByteArray(ZERO_VALUE + ZERO_VALUE));
  }

  @Test(expected = AsymmetricCryptoException.class)
  public void isCardPkiSessionValid_whenRComponentIsZero_shouldThrowAsymmetricCryptoException()
      throws Exception {
    adapter.isCardPkiSessionValid(HexUtil.toByteArray(ZERO_VALUE + VALID_VALUE));
  }

  @Test(expected = AsymmetricCryptoException.class)
  public void isCardPkiSessionValid_whenSComponentIsZero_shouldThrowAsymmetricCryptoException()
      throws Exception {
    adapter.isCardPkiSessionValid(HexUtil.toByteArray(VALID_VALUE + ZERO_VALUE));
  }
}
