package com.fxal.km.server.codec;

import com.fxal.km.protocol.asn1.KMRespond;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * @author caiming
 * @title: KeyRespondEncoder
 * @projectName IBK-KMC
 * @description: TODO
 * @date 2019/7/23 002315:12
 */
@ChannelHandler.Sharable
@Component
public class KMRespondEncoder extends MessageToByteEncoder<KMRespond> {

    Logger logger = LoggerFactory.getLogger(KMRespondEncoder.class);

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        logger.error(cause.getMessage());
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, KMRespond msg, ByteBuf out) throws Exception {
        out.writeBytes(msg.getEncoded());
        out.writeBytes("$_good-luck_$".getBytes());
    }
}
