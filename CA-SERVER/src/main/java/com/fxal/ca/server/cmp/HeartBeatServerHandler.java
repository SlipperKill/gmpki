package com.fxal.ca.server.cmp;

import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
        log.info("HeartBeatServerHandler 激活时间：" + new Date());
        ctx.fireChannelActive();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx)  {
        log.info("HeartBeatServerHandler 停止时间：" + new Date());
    }


    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) {
        log.info("收到Client 心跳信号"+msg);
        if (msg.equals("ping")) {
            log.info("向Client发送心跳信号pong");
            ctx.write("pong$_good-luck_$");
            ctx.flush();
        }
    }




}
