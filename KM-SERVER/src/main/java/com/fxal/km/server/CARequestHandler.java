package com.fxal.km.server;

import com.fxal.km.protocol.CAResponder;
import com.fxal.km.protocol.asn1.CARequest;
import com.fxal.km.protocol.asn1.KMRespond;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * @author: caiming
 * @Date: 2021/8/9 16:31
 * @Description:
 */
@Component
@ChannelHandler.Sharable
@Slf4j
public class CARequestHandler extends SimpleChannelInboundHandler<CARequest> {

    @Autowired
    private CAResponder caResponder;

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, CARequest caRequest) throws Exception {
        log.info("接收到CA发送的密钥申请请求");
        KMRespond kmRespond = caResponder.execute(caRequest);
        log.info("向CA响应密钥申请消息");
        ctx.channel().writeAndFlush(kmRespond);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
    }
}
