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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import org.apache.commons.codec.binary.Base64;
import org.apache.hivemind.ApplicationRuntimeException;
import org.apache.tapestry.services.DataSqueezer;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

@Test
public class SqueezedDataSignerTest
{
    private static final String KEY_PROPERTY = "org.apache.tapestry.squeeze-signing-key";

    @DataProvider(name = "plainValues")
    public Object[][] plainValues()
    {
        return new Object[][] { { "text" }, { "" }, { new Integer(42) }, { new Long(-7L) }, { new Short((short) 3) },
                { new Byte((byte) 1) }, { new Double(2.5d) }, { new Float(1.5f) }, { new Character('c') },
                { Boolean.TRUE }, { Boolean.FALSE } };
    }

    @Test(dataProvider = "plainValues")
    public void plainValuesSqueezeUnsignedAndRoundTripUnderAnyKey(Object value)
    {
        String previous = System.getProperty(KEY_PROPERTY);

        try
        {
            System.setProperty(KEY_PROPERTY, "first key");
            String first = DataSqueezerUtil.createUnitTestSqueezer().squeeze(value);

            System.setProperty(KEY_PROPERTY, "second key");
            DataSqueezer squeezer = DataSqueezerUtil.createUnitTestSqueezer();

            assertEquals(squeezer.squeeze(value), first);
            assertTrue(first.length() == 0 || "OZ".indexOf(first.charAt(0)) < 0, first);
            assertEquals(squeezer.unsqueeze(first), value);
        }
        finally
        {
            if (previous == null)
                System.clearProperty(KEY_PROPERTY);
            else
                System.setProperty(KEY_PROPERTY, previous);
        }
    }

    public void refusedSqueezedValueNamesTheCve()
    {
        String unsigned = "O" + new String(Base64.encodeBase64("not a signed value".getBytes()));

        try
        {
            Object result = DataSqueezerUtil.createUnitTestSqueezer().unsqueeze(unsigned);

            fail("Unsigned value was deserialized to: " + result);
        }
        catch (ApplicationRuntimeException expected)
        {
            assertTrue(expected.getMessage().indexOf("CVE-2020-17531") >= 0, expected.getMessage());
            assertTrue(expected.getMessage().indexOf(KEY_PROPERTY) >= 0, expected.getMessage());
        }
    }
}
