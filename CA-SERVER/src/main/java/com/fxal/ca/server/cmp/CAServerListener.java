package com.fxal.ca.server.cmp;

import com.fxal.ca.server.km.HeartBeatClientHandler;
import com.fxal.ca.server.cmp.codec.PKIMessageDecoder;
import com.fxal.ca.server.cmp.codec.PKIMessageEncoder;
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
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import java.util.concurrent.TimeUnit;

/**
 * @author: caiming
 * @Date: 2022/5/16 16:41
 * @Description:
 */
@Component
@Slf4j
public class CAServerListener {

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
    private PKIMessageDecoder pkiMessageDecoder;

    @Autowired
    private PKIMessageEncoder pkiMessageEncoder;

    @Autowired
    private PKIMessageHandler pkiMessageHandler;

    @Autowired
    private HeartBeatServerHandler heartBeatServerHandler;

    @Autowired
    private AcceptorIdleStateTrigger idleStateTrigger;

    /**
     * 关闭服务器方法
     */
    @PreDestroy
    public void close() {
        log.info("关闭服务器....");
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
                    ch.pipeline().addLast("pkiMessage_decoder", pkiMessageDecoder);
                    ch.pipeline().addLast("pkiMessage_encoder", pkiMessageEncoder);
                    ch.pipeline().addLast(heartBeatServerHandler);
                    ch.pipeline().addLast(pkiMessageHandler);
                }

                ;
            }).childOption(ChannelOption.SO_KEEPALIVE, true);
            // 绑定端口，开始接收进来的连接
            ChannelFuture future = serverBootstrap.bind(port).sync();
            log.info("CA服务器在[{}]端口启动监听", port);
            future.channel().closeFuture().sync();
        } catch (Exception e) {
            log.info("[出现异常] 释放资源");
            boss.shutdownGracefully();
            work.shutdownGracefully();
        }
    }
}
