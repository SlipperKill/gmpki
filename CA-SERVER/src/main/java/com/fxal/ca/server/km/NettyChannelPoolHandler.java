package com.fxal.ca.server.km;

import io.netty.channel.Channel;
import io.netty.channel.pool.ChannelPoolHandler;
import io.netty.channel.socket.nio.NioSocketChannel;
import lombok.extern.slf4j.Slf4j;

/**
 * @author caiming
 * @title: NettyChannelPoolHandler
 * @description: TODO
 * @date 2019/7/23 002317:12
 */
@Slf4j
public class NettyChannelPoolHandler implements ChannelPoolHandler {

    private final ConnectionWatchdog watchdog;

    public NettyChannelPoolHandler(ConnectionWatchdog watchdog) {
        this.watchdog = watchdog;
    }

    @Override
    public void channelReleased(Channel ch)  {
        log.info("释放channel:"+ch);
    }

    @Override
    public void channelAcquired(Channel ch) {
        log.info("获得channel:"+ch);
    }

    @Override
    public void channelCreated(Channel ch)  {
        log.info("创建channel:"+ch);
        NioSocketChannel channel = (NioSocketChannel) ch;
        channel.pipeline().addLast(watchdog.handlers());
    }
}
