package com.fxal.ca.server.km;

import com.fxal.ca.common.pojo.ApplyKeyResult;
import com.fxal.ca.protocol.km.CARequester;
import com.fxal.ca.protocol.km.asn1.KMRespond;
import com.fxal.ca.server.NettyMsgCache;
import io.netty.channel.*;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


/**
 *  @author: caiming
 *  @Date: 2021/8/10 15:32
 *  @Description:
 */
@ChannelHandler.Sharable
@Component
@Slf4j
public class KMClientHandler extends SimpleChannelInboundHandler<KMRespond> {


    @Autowired
    private CARequester caRequester;

    @Autowired
    private NettyMsgCache<ApplyKeyResult> nettyTool;

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.error(cause.getMessage());
        cause.printStackTrace();

    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("channelInactive");
        }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, KMRespond kmRespond) throws Exception {
        log.info("收到KM服务密钥申请响应消息");
        Long taskNo = kmRespond.getKsRespond().getTaskNO().longValueExact();
        ApplyKeyResult applyKeyResult = caRequester.executeKMRespond(kmRespond);
        nettyTool.setReceiveMsg(taskNo,applyKeyResult);
    }


}
