package com.fxal.ca.server.cmp.codec;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.springframework.stereotype.Component;

/**
 * @author: caiming
 * @Date: 2022/5/16 16:36
 * @Description:
 */
@ChannelHandler.Sharable
@Component
@Slf4j
public class PKIMessageEncoder extends MessageToByteEncoder<PKIMessage> {

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        log.error(cause.getMessage());
    }


    @Override
    protected void encode(ChannelHandlerContext channelHandlerContext, PKIMessage msg, ByteBuf out) throws Exception {
        out.writeBytes(msg.getEncoded());
        out.writeBytes("$_good-luck_$".getBytes());
    }
}
