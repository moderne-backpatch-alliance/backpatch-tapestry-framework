// Copyright 2004, 2005 The Apache Software Foundation
//
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
import org.apache.hivemind.ApplicationRuntimeException;
import org.apache.hivemind.impl.DefaultClassResolver;
import org.apache.tapestry.IRequestCycle;
import org.apache.tapestry.services.DataSqueezer;
import org.apache.tapestry.services.ServiceConstants;
import org.apache.tapestry.services.impl.LinkFactoryImpl;
import org.easymock.EasyMock;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

@Test
public class SerializableAdaptorSignatureTest
{
    private static final String KEY_PROPERTY = "org.apache.tapestry.squeeze-signing-key";

    public static class ApplicationBean implements Serializable
    {
        private static final long serialVersionUID = 1L;

        final String _name;

        public ApplicationBean(String name)
        {
            _name = name;
        }

        public boolean equals(Object other)
        {
            return other instanceof ApplicationBean && _name.equals(((ApplicationBean) other)._name);
        }

        public int hashCode()
        {
            return _name.hashCode();
        }
    }

    private static class CountingResolver extends DefaultClassResolver
    {
        int _lookups;

        public Class findClass(String type)
        {
            _lookups++;

            return super.findClass(type);
        }
    }

    private static String unsigned(char prefix, boolean compress) throws Exception
    {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        OutputStream target = compress ? new GZIPOutputStream(bytes) : bytes;

        ObjectOutputStream output = new ObjectOutputStream(target);
        output.writeObject(new ArrayList<String>(Arrays.asList("plain", "list")));
        output.close();

        return prefix + new String(Base64.encodeBase64(bytes.toByteArray()));
    }

    private static void assertRefusedUnresolved(String value)
    {
        CountingResolver resolver = new CountingResolver();
        SerializableAdaptor adaptor = new SerializableAdaptor();
        adaptor.setResolver(resolver);

        try
        {
            Object result = adaptor.unsqueeze(null, value);

            fail("Unsigned value was deserialized to: " + result);
        }
        catch (ApplicationRuntimeException expected)
        {
            assertEquals(resolver._lookups, 0, "classes resolved before the value was refused");
        }
    }

    private static void assertRefused(DataSqueezer squeezer, String value)
    {
        Object result;

        try
        {
            result = squeezer.unsqueeze(value);
        }
        catch (ApplicationRuntimeException expected)
        {
            return;
        }

        fail("Value was deserialized to: " + result);
    }

    public void unsigned_bytestream_is_refused_before_any_class_is_resolved() throws Exception
    {
        assertRefusedUnresolved(unsigned('O', false));
    }

    public void unsigned_gzip_bytestream_is_refused_before_any_class_is_resolved() throws Exception
    {
        assertRefusedUnresolved(unsigned('Z', true));
    }

    public void unsigned_sp_parameter_is_refused_by_the_link_factory() throws Exception
    {
        IRequestCycle cycle = EasyMock.createMock(IRequestCycle.class);
        EasyMock.expect(cycle.getParameters(ServiceConstants.PARAMETER))
                .andReturn(new String[] { unsigned('O', false) });
        EasyMock.replay(cycle);

        LinkFactoryImpl factory = new LinkFactoryImpl();
        factory.setDataSqueezer(DataSqueezerUtil.createUnitTestSqueezer());

        try
        {
            Object[] result = factory.extractListenerParameters(cycle);

            fail("Unsigned sp parameter was deserialized to: " + Arrays.asList(result));
        }
        catch (ApplicationRuntimeException expected)
        {
            EasyMock.verify(cycle);
        }
    }

    public void value_with_altered_body_is_refused()
    {
        DataSqueezer squeezer = DataSqueezerUtil.createUnitTestSqueezer();

        String squeezed = squeezer.squeeze(new ApplicationBean("original"));

        assertRefused(squeezer, squeezed + "AAAA");
    }

    public void value_signed_under_another_key_is_refused()
    {
        DataSqueezer squeezer = DataSqueezerUtil.createUnitTestSqueezer();
        String previous = System.getProperty(KEY_PROPERTY);

        try
        {
            System.setProperty(KEY_PROPERTY, "first key");
            String squeezed = squeezer.squeeze(new ApplicationBean("original"));

            System.setProperty(KEY_PROPERTY, "second key");

            assertRefused(squeezer, squeezed);
        }
        finally
        {
            restore(previous);
        }
    }

    public void application_bean_round_trips_under_the_generated_key()
    {
        DataSqueezer squeezer = DataSqueezerUtil.createUnitTestSqueezer();
        ApplicationBean bean = new ApplicationBean("original");

        assertEquals(squeezer.unsqueeze(squeezer.squeeze(bean)), bean);
    }

    public void compressed_value_round_trips()
    {
        DataSqueezer squeezer = DataSqueezerUtil.createUnitTestSqueezer();

        List<String> repetitive = new ArrayList<String>();
        for (int i = 0; i < 500; i++)
            repetitive.add("repeated value");

        String squeezed = squeezer.squeeze(repetitive);

        assertEquals(squeezed.charAt(0), 'Z');
        assertEquals(squeezer.unsqueeze(squeezed), repetitive);
    }

    public void value_round_trips_across_adaptors_sharing_a_configured_key()
    {
        String previous = System.getProperty(KEY_PROPERTY);

        try
        {
            System.setProperty(KEY_PROPERTY, "shared key");
            ApplicationBean bean = new ApplicationBean("original");

            String squeezed = DataSqueezerUtil.createUnitTestSqueezer().squeeze(bean);

            assertEquals(DataSqueezerUtil.createUnitTestSqueezer().unsqueeze(squeezed), bean);
        }
        finally
        {
            restore(previous);
        }
    }

    private static void restore(String previous)
    {
        if (previous == null)
            System.clearProperty(KEY_PROPERTY);
        else
            System.setProperty(KEY_PROPERTY, previous);
    }
}
