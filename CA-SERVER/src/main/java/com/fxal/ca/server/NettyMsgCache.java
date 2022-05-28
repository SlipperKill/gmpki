package com.fxal.ca.server;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * @author: caiming
 * @Date: 2022/5/24 14:20
 * @Description:
 */
@Slf4j
@Component
public class NettyMsgCache<T> {

    /**
     * 响应消息缓存
     */
    private  Cache<Long, BlockingQueue<T>> responseMsgCache = CacheBuilder.newBuilder()
            .maximumSize(50000)
            .expireAfterWrite(100, TimeUnit.SECONDS)
            .build();


    /**
     * 等待响应消息
     *
     * @param key 消息唯一标识
     * @return ReceiveDdcMsgVo
     */
    public T waitReceiveMsg(Long key) {

        try {
            //设置超时时间
            T vo = Objects.requireNonNull(responseMsgCache.getIfPresent(key))
                    .poll(3000, TimeUnit.MILLISECONDS);

            //删除key
            responseMsgCache.invalidate(key);
            return vo;
        } catch (Exception e) {
            log.error("获取数据异常,sn={},msg=null", key);
            return null;
        }

    }

    /**
     * 初始化响应消息的队列
     *
     * @param key 消息唯一标识
     */
    public void initReceiveMsg(Long key) {
        responseMsgCache.put(key, new LinkedBlockingQueue<T>(1));
    }

    /**
     * 设置响应消息
     *
     * @param key 消息唯一标识
     */
    public void setReceiveMsg(Long key, T msg) {

        if (responseMsgCache.getIfPresent(key) != null) {
            responseMsgCache.getIfPresent(key).add(msg);
            return;
        }
        log.warn("sn {}不存在", key);
    }
}
