package com.fxal.ca.server.cmp;

import com.fxal.ca.protocol.cmp.PKIMessageDispatcher;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * @author: caiming
 * @Date: 2022/5/16 16:30
 * @Description:
 */
@Component
@ChannelHandler.Sharable
@Slf4j
public class PKIMessageHandler extends SimpleChannelInboundHandler<PKIMessage> {

    @Autowired
    private PKIMessageDispatcher dispatcher;

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        log.info("PKIMessageHandler 激活时间：" + new Date());
        ctx.fireChannelActive();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx){
        log.info("PKIMessageHandler 停止时间：" + new Date());
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, PKIMessage pkiMessage) {
        PKIMessage respPKIMessage = dispatcher.processPKIMessage(pkiMessage);
        if(respPKIMessage!=null) {
            ctx.channel().writeAndFlush(respPKIMessage);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
    }
}
