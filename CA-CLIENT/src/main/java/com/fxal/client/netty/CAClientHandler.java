package com.fxal.client.netty;

import com.fxal.client.cmp.CMPClient;
import com.fxal.client.cmp.CmpClientException;
import com.fxal.client.cmp.PKIErrorException;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Date;

/**
 * @author: caiming
 * @Date: 2022/5/19 9:05
 * @Description:
 */
@ChannelHandler.Sharable
@Slf4j
@Component
public class CAClientHandler extends SimpleChannelInboundHandler<PKIMessage> {

    @Autowired
    private CMPClient cmpClient;


    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        System.out.println("CAClientHandler 激活时间：" + new Date());
        ctx.fireChannelActive();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        log.info("CAClientHandler 停止时间：" + new Date());
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        if (cause instanceof CmpClientException) {
            log.error(cause.getMessage());
        } else if (cause instanceof PKIErrorException) {
            PKIErrorException e = (PKIErrorException) cause;
            log.error(e.toString());
        }
        cause.printStackTrace();
    }

    @Override
    protected void channelRead0(ChannelHandlerContext channelHandlerContext, PKIMessage pkiMessage) throws Exception {
        log.info("收到CA响应消息");
        cmpClient.processRespPKIMessage(pkiMessage, channelHandlerContext.channel());
    }
}
