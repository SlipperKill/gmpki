package com.fxal.client.netty;

import com.fxal.client.netty.codec.PKIMessageDecoder;
import com.fxal.client.netty.codec.PKIMessageEncoder;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.pool.FixedChannelPool;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.HashedWheelTimer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

/**
 * @author: caiming
 * @Date: 2022/5/19 8:53
 * @Description:
 */
@Component
@Slf4j
public class CAClient {

    protected final HashedWheelTimer timer = new HashedWheelTimer();

    @Value("${ca.server.ip}")
    private String caServerIP;

    @Value("${ca.server.port}")
    private Integer caServerPort;

    private FixedChannelPool channelPool;

    @Autowired
    private ConnectorIdleStateTrigger connectorIdleStateTrigger;

    @Autowired
    private PKIMessageDecoder pkiMessageDecoder;

    @Autowired
    private PKIMessageEncoder pkiMessageEncoder;

    @Autowired
    private CAClientHandler caClientHandler;

    @Autowired
    private HeartBeatClientHandler heartBeatClientHandler;

    public void connect() {
        log.info("初始化CA服务连接池");
        this.channelPool = connect(caServerPort, caServerIP, 20);
    }

    public void connect(int port, String host) {
        this.channelPool = connect(port, host, 20);
    }

    public FixedChannelPool getChannelPool() {
        if (this.channelPool == null) {
            connect();
        }
        return this.channelPool;
    }

    public Channel getChannel() throws RuntimeException {
        try {
            return getChannelPool().acquire().get();
        } catch (Exception e) {
            throw new RuntimeException("连接CA失败，请确认KM服务已启动。");
        }
    }

    /**
     * @author: caiming
     * @Date: 2021/8/10 15:37
     * @Description: readerIdleTimeSeconds, 读超时. 即当在指定的时间间隔内没有从 Channel 读取到数据时, 会触发一个 READER_IDLE 的 IdleStateEvent 事件.
     * writerIdleTimeSeconds, 写超时. 即当在指定的时间间隔内没有数据写入到 Channel 时, 会触发一个 WRITER_IDLE 的 IdleStateEvent 事件.
     * allIdleTimeSeconds, 读/写超时. 即当在指定的时间间隔内没有读或写操作时, 会触发一个 ALL_IDLE 的 IdleStateEvent 事件.
     */


    private FixedChannelPool connect(int port, String host, int maxChannel) {

        EventLoopGroup group = new NioEventLoopGroup();

        Bootstrap boot = new Bootstrap();
        // boot.group(group).channel(NioSocketChannel.class).handler(new LoggingHandler(LogLevel.INFO));

        final ConnectionWatchdog watchdog = new ConnectionWatchdog(boot, timer, port, host, true) {

            public ChannelHandler[] handlers() {
                return new ChannelHandler[]{
                        this,
                        new IdleStateHandler(0, 4, 0, TimeUnit.SECONDS),
                        connectorIdleStateTrigger,
                        //new StringDecoder(),
                        new StringEncoder(),
                        new DelimiterBasedFrameDecoder(10240, Unpooled.copiedBuffer("$_good-luck_$".getBytes())),
                        pkiMessageDecoder,
                        pkiMessageEncoder,
                        caClientHandler,
                        heartBeatClientHandler
                };
            }
        };

        InetSocketAddress remoteaddress = InetSocketAddress.createUnresolved(host, port);// 连接地址
        boot.group(group).channel(NioSocketChannel.class).handler(new LoggingHandler(LogLevel.INFO)).option(ChannelOption.TCP_NODELAY, true)
                .remoteAddress(remoteaddress);

        FixedChannelPool channelPool = new FixedChannelPool(boot, new NettyChannelPoolHandler(watchdog), maxChannel);
        return channelPool;
    }

}
