package com.fxal.ca.server.km.codec;

import com.fxal.ca.protocol.km.asn1.CARequest;
import com.fxal.ca.protocol.km.asn1.KMRespond;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * @author: caiming
 * @Date: 2021/8/10 15:21
 * @Description:
 */
@ChannelHandler.Sharable
@Component
public class CARequestEncoder extends MessageToByteEncoder<CARequest> {

    Logger logger = LoggerFactory.getLogger(CARequestEncoder.class);

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        logger.error(cause.getMessage());
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, CARequest msg, ByteBuf out) throws Exception {
        logger.debug("encoder caRequest................");
        out.writeBytes(msg.getEncoded());
        out.writeBytes("$_good-luck_$".getBytes());
    }
}
