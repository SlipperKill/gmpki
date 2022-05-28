package com.fxal.ca.server.km;

import io.netty.channel.*;
import io.netty.util.ReferenceCountUtil;
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
public class HeartBeatClientHandler extends SimpleChannelInboundHandler<String> {
    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        log.info("CA与KM连接激活时间：" + new Date());
        ctx.fireChannelActive();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("CA与KM连接断开时间：" + new Date());
    }


    @Override
    protected void channelRead0(ChannelHandlerContext channelHandlerContext, String s) throws Exception {
        log.info("收到KM心跳信号："+s);
    }

}
