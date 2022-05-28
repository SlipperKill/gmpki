package com.fxal.ca.util;


import java.util.UUID;

/**
 * @ClassName: UUIDGenerator  
 * @Description: TODO(这里用一句话描述这个类的作用)  
 * @author yk  
 * @date 2019年5月20日
 */
public class UUIDGenerator { 
    private UUIDGenerator() {
    } 
    /***
     * 获取32位随机数
     * @标题：
     * @描述: 
     * @创建人：yk
     * @创建日期：2016年10月26日-下午5:01:43
     * @return
     */
    public static String getUUID(){ 
        String s = UUID.randomUUID().toString(); 
        return s.substring(0,8)+s.substring(9,13)+s.substring(14,18)+s.substring(19,23)+s.substring(24); 
    } 

    /***
     * 自定义位数
     * @标题：
     * @描述: 
     * @创建人：yk
     * @创建日期：2016年10月26日-下午5:02:01
     * @param number
     * @return
     */
    public static String[] getUUID(int number){ 
        if(number < 1){ 
            return null; 
        } 
        String[] ss = new String[number]; 
        for(int i=0;i<number;i++){ 
            ss[i] = getUUID(); 
        } 
        return ss; 
    } 

    /***
     * 16位随机数
     * @标题：
     * @描述: 
     * @创建人：yk
     * @创建日期：2016年10月26日-下午5:02:15
     * @return
     */
    public static String getSerialId(){
    	 String s = UUID.randomUUID().toString(); 
    	 return s.substring(0,16);
    }
    
    
}   