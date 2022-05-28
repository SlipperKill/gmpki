package com.fxal.ca.util;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.*;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * @author caiming
 * @title: NettyUtil
 * @projectName ibk-cert-sign
 * @description: TODO
 * @date 2019/7/9 000915:22
 */
public class NettyUtil {

    public static byte[] byteBuf2Array(ByteBuf byteBuf) {
        int length = byteBuf.readableBytes();
        byte[] array = new byte[length];
        byteBuf.getBytes(byteBuf.readerIndex(), array, 0, length);
        return array;
    }

    public static String getHttpHeaderContentType(HttpHeaders httpHeaders) {
        String contentType = httpHeaders.get(HttpHeaderNames.CONTENT_TYPE);
        return contentType;
    }


}
