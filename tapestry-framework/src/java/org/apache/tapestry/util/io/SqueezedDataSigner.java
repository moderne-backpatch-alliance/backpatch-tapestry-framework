// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.apache.tapestry.util.io;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hivemind.HiveMind;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.StreamCorruptedException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Signs serialized values that travel through requests and refuses values this application did not sign.
 */
public final class SqueezedDataSigner
{
    static final String KEY_PROPERTY = "org.apache.tapestry.squeeze-signing-key";

    static final int SIGNATURE_LENGTH = 44;

    static final String REFUSAL = "Serialized request data is not signed by this application (CVE-2020-17531): "
            + "values are signed with a random key generated per JVM unless " + KEY_PROPERTY + " sets one.";

    private static final Log LOG = LogFactory.getLog(SqueezedDataSigner.class);

    private static final String ALGORITHM = "HmacSHA256";

    private static final String ENCODING = "UTF-8";

    private static byte[] _generatedKey;

    private SqueezedDataSigner()
    {
    }

    /**
     * Returns the one-character prefix, the signature of prefix and body, then the body.
     */
    public static String sign(String prefix, String body)
        throws GeneralSecurityException, UnsupportedEncodingException
    {
        return prefix + signature(prefix + body) + body;
    }

    /**
     * Returns the body of a value produced by {@link #sign(String, String)}.
     *
     * @throws StreamCorruptedException
     *             if the value does not carry this application's signature
     */
    public static String verifiedBody(String signed)
        throws GeneralSecurityException, UnsupportedEncodingException, StreamCorruptedException
    {
        int bodyStart = 1 + SIGNATURE_LENGTH;

        if (signed.length() < bodyStart
                || !matches(signature(signed.substring(0, 1) + signed.substring(bodyStart)), signed.substring(1, bodyStart)))
        {
            LOG.warn(REFUSAL);

            throw new StreamCorruptedException(REFUSAL);
        }

        return signed.substring(bodyStart);
    }

    private static String signature(String data)
        throws GeneralSecurityException, UnsupportedEncodingException
    {
        Mac mac = Mac.getInstance(ALGORITHM);

        mac.init(new SecretKeySpec(key(), ALGORITHM));

        return new String(Base64.encodeBase64(mac.doFinal(data.getBytes(ENCODING))));
    }

    private static boolean matches(String expected, String actual)
    {
        if (expected.length() != actual.length())
            return false;

        int difference = 0;

        for (int i = 0; i < expected.length(); i++)
            difference |= expected.charAt(i) ^ actual.charAt(i);

        return difference == 0;
    }

    private static byte[] key()
        throws UnsupportedEncodingException
    {
        String configured = configuredKey();

        return HiveMind.isBlank(configured) ? generatedKey() : configured.getBytes(ENCODING);
    }

    private static String configuredKey()
    {
        try
        {
            return System.getProperty(KEY_PROPERTY);
        }
        catch (SecurityException ex)
        {
            return null;
        }
    }

    private static synchronized byte[] generatedKey()
    {
        if (_generatedKey == null)
        {
            _generatedKey = new byte[32];

            new SecureRandom().nextBytes(_generatedKey);
        }

        return _generatedKey;
    }
}
