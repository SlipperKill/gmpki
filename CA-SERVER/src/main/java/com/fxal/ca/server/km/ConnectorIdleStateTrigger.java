package com.fxal.ca.server.km;

import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;


/**
 * @author: caiming
 * @Date: 2021/8/10 15:16
 * @Description:
 */

@ChannelHandler.Sharable
@Component
@Slf4j
public class ConnectorIdleStateTrigger extends ChannelInboundHandlerAdapter {

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent) {
            IdleState state = ((IdleStateEvent) evt).state();

            if (state == IdleState.WRITER_IDLE) {
                log.info("向KM发送心跳信号：ping");
                ctx.channel().writeAndFlush("ping$_good-luck_$");
            }
        } else {
            super.userEventTriggered(ctx, evt);
        }
    }

}
