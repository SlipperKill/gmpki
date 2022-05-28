package com.fxal.client.netty;

import io.netty.channel.ChannelHandler;

/**
 * @author caiming
 * @title: ChannelHandlerHolder
 * @description: TODO
 * @date 2019/7/23 002315:55
 */
public interface ChannelHandlerHolder {
    ChannelHandler[] handlers();
}
