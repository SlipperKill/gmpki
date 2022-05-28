package com.fxal.ca.server.km.codec;

import com.fxal.ca.protocol.km.asn1.CARequest;
import com.fxal.ca.protocol.km.asn1.KMRespond;
import com.fxal.ca.util.NettyUtil;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageDecoder;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.List;

/**
 * @author: caiming
 * @Date: 2021/8/10 15:23
 * @Description:
 */
@ChannelHandler.Sharable
@Component
public class KMRespondDecoder extends MessageToMessageDecoder<ByteBuf> {

    Logger logger = LoggerFactory.getLogger(KMRespondDecoder.class);

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        logger.error(cause.getMessage());
        ctx.channel().close();
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf msg, List<Object> out) throws Exception {
        final byte[] array = NettyUtil.byteBuf2Array(msg);
        if(array.length==4){
            out.add("pong");
        }else {
            KMRespond respond = KMRespond.getInstance(array);
            out.add(respond);
        }
    }


}
