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
package de.gematik.ti.vauchannel.server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.Security;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SomeServiceTest {


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Autowired
    public SomeService someService;

    @Test
    public void isProperInitialized() throws Exception {
        Assert.assertNotNull(someService);
    }

    @Test
    public void sayHello() throws Exception {
        String result = someService.sayHello("hello from test client");
        Assert.assertNotNull(result);
        Assert.assertEquals("hello from server", result);
    }

}
