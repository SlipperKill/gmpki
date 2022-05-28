package com.fxal.ca.util;

public class ByteIntUtil {
	/**
	 * 将整数转换为byte数组并指定长度
	 * @param a 整数
	 * @param length 指定长度
	 * @return
	 */
	public static byte[] intToBytes(int a, int length) {
	    byte[] bs = new byte[length];
	    for (int i = bs.length - 1; i >= 0; i--) {
	        bs[i] = (byte) (a % 255);
	        a = a / 255;
	    }
	    return bs;
	}

	/**
	 * 将byte数组转换为整数
	 * @param bs
	 * @return
	 */
	public static int bytes2Int(byte[] bytes){
        int value=0;
        value = ((bytes[3] & 0xff)<<24)|
                ((bytes[2] & 0xff)<<16)|
                ((bytes[1] & 0xff)<<8)|
                (bytes[0] & 0xff);
        return value;
}
}
