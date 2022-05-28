package com.fxal.client;

import com.fxal.client.cmp.CMPClient;
import com.fxal.client.netty.CAClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;

import java.security.Security;

/**
 * @author: caiming
 * @Date: 2022/5/17 9:29
 * @Description:
 */
@SpringBootApplication
@EnableConfigurationProperties
@EnableCaching
public class Application implements CommandLineRunner {

    @Autowired
    private CAClient caClient;

    @Autowired
    private CMPClient cmpClient;

    public static void main(String args[]) {
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(Application.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        caClient.connect();
        cmpClient.testSendCertReq();
    }
}
