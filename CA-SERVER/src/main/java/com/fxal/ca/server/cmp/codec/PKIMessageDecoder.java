package com.fxal.ca.server.cmp.codec;

import com.fxal.ca.protocol.km.asn1.CARequest;
import com.fxal.ca.util.NettyUtil;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageDecoder;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author: caiming
 * @Date: 2022/5/16 16:33
 * @Description:
 */
@ChannelHandler.Sharable
@Component
@Slf4j
public class PKIMessageDecoder extends MessageToMessageDecoder<ByteBuf> {

    @Override
    protected void decode(ChannelHandlerContext channelHandlerContext, ByteBuf msg, List<Object> out) throws Exception {
        final byte[] array = NettyUtil.byteBuf2Array(msg);
        if(array.length==4){
            out.add(new String(array));
        }else {
            PKIMessage reqPKIMessage = PKIMessage.getInstance(array);
            out.add(reqPKIMessage);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        log.error(cause.getMessage());
        ctx.channel().close();
    }
}
