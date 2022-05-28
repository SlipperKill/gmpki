package com.fxal.km.server;

import com.fxal.km.server.codec.CARequestDecoder;
import com.fxal.km.server.codec.KMRespondEncoder;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.timeout.IdleStateHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import java.util.concurrent.TimeUnit;

/**
 * @author: caiming
 * @Date: 2021/8/9 16:37
 * @Description:
 */
@Component
public class KMServerListener {

    Logger logger = LoggerFactory.getLogger(KMServerListener.class);

    /**
     * 创建bootstrap
     */
    ServerBootstrap serverBootstrap = new ServerBootstrap();
    /**
     * BOSS
     */
    EventLoopGroup boss = new NioEventLoopGroup();
    /**
     * Worker
     */
    EventLoopGroup work = new NioEventLoopGroup();

    @Autowired
    private CARequestHandler caRequestHandler;

    @Autowired
    private HeartBeatServerHandler heartBeatClientHandler;

    @Autowired
    private AcceptorIdleStateTrigger idleStateTrigger;

    @Autowired
    private CARequestDecoder caRequestDecoder;

    @Autowired
    private KMRespondEncoder kmRespondEncoder;

    /**
     * 关闭服务器方法
     */
    @PreDestroy
    public void close() {
        logger.info("关闭服务器....");
        //优雅退出
        boss.shutdownGracefully();
        work.shutdownGracefully();
    }

    public void start(int port) {
        serverBootstrap.group(boss, work)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, 1024)
                .handler(new LoggingHandler(LogLevel.INFO));
        try {
            //设置事件处理
            serverBootstrap.childHandler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) throws Exception {
                    ch.pipeline().addLast(new IdleStateHandler(5, 0, 0, TimeUnit.SECONDS));
                    ch.pipeline().addLast(idleStateTrigger);
                    //ch.pipeline().addLast("string_decoder", new StringDecoder());
                    ch.pipeline().addLast("string_encoder", new StringEncoder());
                    ByteBuf buf = Unpooled.copiedBuffer("$_good-luck_$".getBytes());
                    ch.pipeline().addLast(new DelimiterBasedFrameDecoder(10240, buf));
                    ch.pipeline().addLast("key_decoder", caRequestDecoder);
                    ch.pipeline().addLast("key_encoder", kmRespondEncoder);
                    ch.pipeline().addLast(heartBeatClientHandler);
                    ch.pipeline().addLast(caRequestHandler);
                }

                ;
            }).childOption(ChannelOption.SO_KEEPALIVE, true);
            // 绑定端口，开始接收进来的连接
            logger.info("netty服务器在[{}]端口启动监听", port);
            ChannelFuture future = serverBootstrap.bind(port).sync();
            System.out.println("KM 启动成功，端口： " + port);
            future.channel().closeFuture().sync();
        } catch (Exception e) {
            logger.info("[出现异常] 释放资源");
            boss.shutdownGracefully();
            work.shutdownGracefully();
        }
    }

}
