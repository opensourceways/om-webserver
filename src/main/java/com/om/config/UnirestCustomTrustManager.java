/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public class UnirestCustomTrustManager implements X509TrustManager {
    /**
     * Logger for logging messages in CustomTrustManager class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(UnirestCustomTrustManager.class);

    /**
     * check client.
     *
     * @param chain the peer certificate chain
     * @param authType the authentication type based on the client certificate
     * @throws CertificateException exception
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        validCertificate(chain);
    }

    /**
     * check server.
     *
     * @param chain the peer certificate chain
     * @param authType the key exchange algorithm used
     * @throws CertificateException exception
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        validCertificate(chain);
    }

    /**
     * issuers.
     *
     * @return certificate
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    private void validCertificate(X509Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            LOGGER.error("no certificate found");
            return;
        }
        for (X509Certificate cert : chain) {
            try {
                cert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                LOGGER.error("certificate expired {}", e.getMessage());
            }

            if (cert.getSignature().length == 0) {
                LOGGER.error("certificate valid failed");
            }
        }
    }
}
