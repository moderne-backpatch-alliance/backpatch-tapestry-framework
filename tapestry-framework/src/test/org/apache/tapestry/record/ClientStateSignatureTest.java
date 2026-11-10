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

package org.apache.tapestry.record;

import static org.easymock.EasyMock.expect;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.codec.binary.Base64;
import org.apache.hivemind.ApplicationRuntimeException;
import org.apache.hivemind.ClassResolver;
import org.apache.hivemind.impl.DefaultClassResolver;
import org.apache.tapestry.BaseComponentTestCase;
import org.apache.tapestry.util.io.SerializableAdaptorSignatureTest.ApplicationBean;
import org.apache.tapestry.web.WebRequest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

@Test
public class ClientStateSignatureTest extends BaseComponentTestCase
{
    private static final String KEY_PROPERTY = "org.apache.tapestry.squeeze-signing-key";

    private static final String PAGE = "Home";

    private static class CountingResolver extends DefaultClassResolver
    {
        int _lookups;

        public Class findClass(String type)
        {
            _lookups++;

            return super.findClass(type);
        }
    }

    @DataProvider(name = "parameters")
    public Object[][] parameters()
    {
        return new Object[][] {
                { new PageClientPropertyPersistenceScope(), "state:" + PAGE, Boolean.FALSE },
                { new PageClientPropertyPersistenceScope(), "state:" + PAGE, Boolean.TRUE },
                { new AppClientPropertyPersistenceScope(), "appstate:" + PAGE, Boolean.FALSE },
                { new AppClientPropertyPersistenceScope(), "appstate:" + PAGE, Boolean.TRUE } };
    }

    @Test(dataProvider = "parameters")
    public void unsignedClientStateIsRefusedBeforeAnyClassIsResolved(ClientPropertyPersistenceScope scope,
            String parameter, Boolean compress) throws Exception
    {
        CountingResolver resolver = new CountingResolver();
        ClientPropertyPersistenceStrategy strategy = newStrategy(scope, parameter,
                unsigned(compress.booleanValue()), newEncoder(resolver));

        assertRefused(strategy);
        assertEquals(resolver._lookups, 0, "classes resolved before the value was refused");
        verify();
    }

    @Test(dataProvider = "parameters")
    public void clientStateSignedUnderAnotherKeyIsRefused(ClientPropertyPersistenceScope scope,
            String parameter, Boolean compress)
    {
        String previous = System.getProperty(KEY_PROPERTY);

        try
        {
            System.setProperty(KEY_PROPERTY, "first key");
            String encoded = newEncoder().encodePageChanges(changes(compress.booleanValue()));

            System.setProperty(KEY_PROPERTY, "second key");

            assertRefused(newStrategy(scope, parameter, encoded, newEncoder()));
            verify();
        }
        finally
        {
            restore(previous);
        }
    }

    @Test(dataProvider = "parameters")
    public void signedClientStateRoundTripsThroughTheStrategy(ClientPropertyPersistenceScope scope,
            String parameter, Boolean compress)
    {
        List changes = changes(compress.booleanValue());
        String encoded = newEncoder().encodePageChanges(changes);

        ClientPropertyPersistenceStrategy strategy = newStrategy(scope, parameter, encoded, newEncoder());

        assertEquals(strategy.getStoredChanges(PAGE), changes);
        verify();
    }

    public void clientStateWithAlteredBodyIsRefused()
    {
        String encoded = newEncoder().encodePageChanges(changes(false));

        try
        {
            newEncoder().decodePageChanges(encoded + "AAAA");

            unreachable();
        }
        catch (ApplicationRuntimeException expected)
        {
        }
    }

    public void clientStateRoundTripsThroughEncodeAndDecode()
    {
        PersistentPropertyDataEncoder encoder = newEncoder();

        List shortChanges = changes(false);
        List longChanges = changes(true);

        String shortEncoded = encoder.encodePageChanges(shortChanges);
        String longEncoded = encoder.encodePageChanges(longChanges);

        assertEquals(shortEncoded.substring(0, 1), "B");
        assertEquals(longEncoded.substring(0, 1), "Z");
        assertEquals(encoder.decodePageChanges(shortEncoded), shortChanges);
        assertEquals(encoder.decodePageChanges(longEncoded), longChanges);
    }

    public void refusedClientStateNamesTheCve() throws Exception
    {
        try
        {
            newEncoder().decodePageChanges(unsigned(false));

            unreachable();
        }
        catch (ApplicationRuntimeException expected)
        {
            assertTrue(expected.getMessage().indexOf("CVE-2020-17531") >= 0, expected.getMessage());
            assertTrue(expected.getMessage().indexOf(KEY_PROPERTY) >= 0, expected.getMessage());
        }
    }

    private ClientPropertyPersistenceStrategy newStrategy(ClientPropertyPersistenceScope scope,
            String parameter, String value, PersistentPropertyDataEncoder encoder)
    {
        WebRequest request = newRequest();

        expect(request.getParameterNames()).andReturn(Arrays.asList(new String[] { "foo", parameter }));
        expect(request.getParameterValue(parameter)).andReturn(value);

        replay();

        ClientPropertyPersistenceStrategy strategy = new ClientPropertyPersistenceStrategy();
        strategy.setRequest(request);
        strategy.setScope(scope);
        strategy.setEncoder(encoder);

        strategy.initializeService();

        return strategy;
    }

    private static void assertRefused(ClientPropertyPersistenceStrategy strategy)
    {
        Object result;

        try
        {
            result = strategy.getStoredChanges(PAGE);
        }
        catch (ApplicationRuntimeException expected)
        {
            return;
        }

        fail("Client state was deserialized to: " + result);
    }

    private PersistentPropertyDataEncoder newEncoder()
    {
        return newEncoder(getClassResolver());
    }

    private static PersistentPropertyDataEncoder newEncoder(ClassResolver resolver)
    {
        PersistentPropertyDataEncoderImpl encoder = new PersistentPropertyDataEncoderImpl();
        encoder.setClassResolver(resolver);

        return encoder;
    }

    private static List changes(boolean compressible)
    {
        if (!compressible)
            return Collections.singletonList(new PropertyChangeImpl("form", "name", "original"));

        List result = new ArrayList();
        for (int i = 0; i < 50; i++)
            result.add(new PropertyChangeImpl(null, "bean" + i, new ApplicationBean("repeated value")));

        return result;
    }

    private static String unsigned(boolean compress) throws Exception
    {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        OutputStream target = compress ? new GZIPOutputStream(bytes) : bytes;

        ObjectOutputStream output = new ObjectOutputStream(target);
        output.writeInt(1);
        output.writeBoolean(false);
        output.writeUTF("bean");
        output.writeObject(new ApplicationBean("original"));
        output.close();

        return (compress ? "Z" : "B") + new String(Base64.encodeBase64(bytes.toByteArray()));
    }

    private static void restore(String previous)
    {
        if (previous == null)
            System.clearProperty(KEY_PROPERTY);
        else
            System.setProperty(KEY_PROPERTY, previous);
    }
}
