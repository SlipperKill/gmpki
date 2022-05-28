package com.fxal.km.server.codec;

import com.fxal.km.common.util.NettyUtil;
import com.fxal.km.protocol.asn1.CARequest;
import com.sun.org.apache.xpath.internal.operations.String;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author: caiming
 * @Date: 2021/8/3 15:46
 * @Description:
 */
@ChannelHandler.Sharable
@Component
public class CARequestDecoder extends MessageToMessageDecoder<ByteBuf> {

    Logger logger = LoggerFactory.getLogger(CARequestDecoder.class);

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
            out.add("ping");
        }else {
            CARequest req = CARequest.getInstance(array);
            logger.debug(req.getSignatureValue().getOctets().length + "<<<<<<<<<<<<<<");
            out.add(req);
        }
    }


}
