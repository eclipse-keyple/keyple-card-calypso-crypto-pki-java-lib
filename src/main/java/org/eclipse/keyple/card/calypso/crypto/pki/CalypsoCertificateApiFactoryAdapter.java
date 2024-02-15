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

import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.certificate.CalypsoCertificateApiFactory;
import org.eclipse.keypop.calypso.certificate.ca.CaCertificateBuilder;
import org.eclipse.keypop.calypso.certificate.ca.CaCertificateSettings;
import org.eclipse.keypop.calypso.certificate.ca.CaCertificateSettingsV1;
import org.eclipse.keypop.calypso.certificate.card.CardCertificateBuilder;
import org.eclipse.keypop.calypso.certificate.card.CardCertificateSettings;
import org.eclipse.keypop.calypso.certificate.card.CardCertificateSettingsV1;

/**
 * Adapter of {@link CalypsoCertificateApiFactory}.
 *
 * @since 0.1.0
 */
class CalypsoCertificateApiFactoryAdapter implements CalypsoCertificateApiFactory {

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public <T extends CaCertificateSettings> T createCaCertificateSettings(Class<T> classOfT) {
    Assert.getInstance().notNull(classOfT, "classOfT");
    if (classOfT == CaCertificateSettingsV1.class) {
      return classOfT.cast(new CaCertificateSettingsV1Adapter());
    }
    throw new UnsupportedOperationException(
        "Support for class '" + classOfT.getName() + "' not yet implemented");
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public <T extends CardCertificateSettings> T createCardCertificateSettings(Class<T> classOfT) {
    Assert.getInstance().notNull(classOfT, "classOfT");
    if (classOfT == CardCertificateSettingsV1.class) {
      return classOfT.cast(new CardCertificateSettingsV1Adapter());
    }
    throw new UnsupportedOperationException(
        "Support for class '" + classOfT.getName() + "' not yet implemented");
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CaCertificateBuilder createCaCertificateBuilder(CaCertificateSettings settings) {
    Assert.getInstance().notNull(settings, "settings");
    throw new UnsupportedOperationException("Not yet implemented.");
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateBuilder createCardCertificateBuilder(CardCertificateSettings settings) {
    Assert.getInstance().notNull(settings, "settings");
    throw new UnsupportedOperationException("Not yet implemented.");
  }
}
