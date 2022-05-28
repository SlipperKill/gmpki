package com.fxal.ca.server;

import com.fxal.ca.common.pojo.ApplyKeyResult;
import com.fxal.ca.protocol.km.asn1.ApplyKeyRequest;

import java.util.concurrent.ConcurrentHashMap;

/**
 * @author: caiming
 * @Date: 2022/5/24 14:37
 * @Description:
 */
public class NettyServerData {

    public static ConcurrentHashMap<Long, ApplyKeyResult> KEY_APPLY_RESULT_MAP = new ConcurrentHashMap();
}
