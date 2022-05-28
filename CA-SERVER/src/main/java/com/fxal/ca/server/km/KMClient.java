package com.fxal.ca.server.km;

import com.fxal.ca.mgmt.CaMgmtException;
import com.fxal.ca.server.km.codec.CARequestEncoder;
import com.fxal.ca.server.km.codec.KMRespondDecoder;
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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * @author: caiming
 * @Date: 2021/8/10 15:32
 * @Description:
 */
@Component
@Slf4j
public class KMClient {

    protected final HashedWheelTimer timer = new HashedWheelTimer();

    private FixedChannelPool channelPool;

    @Autowired
    private ConnectorIdleStateTrigger connectorIdleStateTrigger;

    @Autowired
    private KMClientHandler kmClientHandler;

    @Autowired
    private HeartBeatClientHandler heartBeatClientHandler;

    @Autowired
    private CARequestEncoder caRequestEncoder;
    @Autowired
    private KMRespondDecoder kmRespondDecoder;

    @Value("${km.server.ip}")
    private String kmServerIP;

    @Value("${km.server.port}")
    private Integer kmServerPort;

    public void connect() {
        log.info("初始化KM服务连接池");
        this.channelPool = connect(kmServerPort, kmServerIP, 20);
    }

    public void connectTest(Integer port, String ip) {
        log.info("初始化KM服务连接池测试");
        this.channelPool = connect(port, ip, 20);
    }

    private FixedChannelPool getChannelPool() {
        if (this.channelPool == null) {
            connect();
        }
        return this.channelPool;
    }

    public Channel getChannel() throws CaMgmtException {
        try {
            return getChannelPool().acquire().get();
        } catch (Exception e) {
           throw new CaMgmtException("连接KM失败，请确认KM服务已启动。");
        }
    }

    public void releaseChannel(Channel ch){
        this.channelPool.release(ch);
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
                        new StringEncoder(),
                        new DelimiterBasedFrameDecoder(10240, Unpooled.copiedBuffer("$_good-luck_$".getBytes())),
                        caRequestEncoder,
                        kmRespondDecoder,
                        kmClientHandler,
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
