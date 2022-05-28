package com.fxal.ca.util;


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import java.io.IOException;

public class AsnUtil {

	/**
	 * asn1实体转换为byte数组
	 * @param obj
	 * @return
	 * @throws IOException 
	 */
	public static byte[] asn1ToByte(ASN1Object obj) {
		byte[] bytes = null;
		if(null!=obj){
			try {
				bytes = obj.getEncoded("DER");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return bytes;
	}
	
	/**
	 * byte数组转换为ASN1Sequence对象
	 * @param bytes
	 * @param
	 */
	public static ASN1Sequence byteToASN1Sequence(byte[] bytes) {
		ASN1InputStream input = null;
		ASN1Primitive object = null;
		if(null!=bytes){
			try {
				input = new ASN1InputStream(bytes);
				object = input.readObject();
			} catch (IOException ioe) {
				ioe.printStackTrace();
				return null;
			} finally {
				try {
					if (null != input) {
						input.close();
					}
				} catch (IOException e) {
					return null;
				}
			}
		}
		return (ASN1Sequence)object;
	}
	

}
