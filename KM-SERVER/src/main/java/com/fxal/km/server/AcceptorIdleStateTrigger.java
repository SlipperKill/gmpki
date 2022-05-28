package com.fxal.km.server;

import com.fxal.km.common.exception.KMSecurityException;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * @author caiming
 * @title: AcceptorIdleStateTrigger
 * @projectName IBK-KMC
 * @description: TODO
 * @date 2019/7/23 002315:59
 */
@ChannelHandler.Sharable
@Component
public class AcceptorIdleStateTrigger extends ChannelInboundHandlerAdapter {

    Logger logger = LoggerFactory.getLogger(AcceptorIdleStateTrigger.class);

    int readIdleTimes = 0;

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent) {
            IdleState state = ((IdleStateEvent) evt).state();
            String eventType = null;
            if (state == IdleState.READER_IDLE) {
                eventType = "读空闲";
                readIdleTimes++;
            }

            logger.error(ctx.channel().remoteAddress()+"超时事件："+eventType);
            if(readIdleTimes>3){
                ctx.channel().close();
                readIdleTimes = 0;
            }
        } else {
            super.userEventTriggered(ctx, evt);
        }
    }

}
