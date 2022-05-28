package com.fxal.km.server;

import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 *  @author: caiming
 *  @Date: 2021/8/10 15:22
 *  @Description:
 */
@ChannelHandler.Sharable
@Component
@Slf4j
public class HeartBeatServerHandler extends SimpleChannelInboundHandler<String> {

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        log.info("激活时间是：" + new Date());
        ctx.fireChannelActive();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("停止时间是：" + new Date());
    }


    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
        log.info("收到CA心跳信号："+msg);
        if (msg.equals("ping")) {
            log.info("向CA发送心跳:pong");
            ctx.write("pong$_good-luck_$");
            ctx.flush();
        }
    }




}
