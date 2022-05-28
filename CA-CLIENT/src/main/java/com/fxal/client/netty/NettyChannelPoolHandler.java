package com.fxal.client.netty;

import io.netty.channel.Channel;
import io.netty.channel.pool.ChannelPoolHandler;
import io.netty.channel.socket.nio.NioSocketChannel;

/**
 * @author caiming
 * @title: NettyChannelPoolHandler
 * @projectName IBK-SERVER
 * @description: TODO
 * @date 2019/7/23 002317:12
 */
public class NettyChannelPoolHandler implements ChannelPoolHandler {

    private final ConnectionWatchdog watchdog;

    public NettyChannelPoolHandler(ConnectionWatchdog watchdog) {
        this.watchdog = watchdog;
    }

    @Override
    public void channelReleased(Channel ch) throws Exception {
    }

    @Override
    public void channelAcquired(Channel ch) throws Exception {
    }

    @Override
    public void channelCreated(Channel ch) throws Exception {
        NioSocketChannel channel = (NioSocketChannel) ch;
        channel.pipeline().addLast(watchdog.handlers());
    }
}
