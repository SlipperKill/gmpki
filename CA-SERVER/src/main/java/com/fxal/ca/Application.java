package com.fxal.ca;

import com.fxal.ca.protocol.km.CARequester;
import com.fxal.ca.server.cmp.CAServerListener;
import com.fxal.ca.server.km.KMClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import java.security.Security;

/**
 * @author: caiming
 * @Date: 2021/8/13 11:18
 * @Description:
 */
@SpringBootApplication
@EnableConfigurationProperties
@EnableTransactionManagement
@EnableCaching
@EnableAutoConfiguration(exclude={DataSourceAutoConfiguration.class})
public class Application implements CommandLineRunner {

    @Autowired
    private CAServerListener caServerListener;

    @Autowired
    private KMClient kmClient;

    @Autowired
    private CARequester caRequester;
    public static void main(String args[]) {
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(Application.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        //测试向KM发起密钥申请请求
       // caRequester.executeCARequest();
        kmClient.connect();
        caServerListener.start(6001);
    }
}
