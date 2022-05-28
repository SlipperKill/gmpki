package com.fxal.ca.util;


import java.io.*;

/**
 * @ClassName: FileUtils  
 * @Description: TODO(这里用一句话描述这个类的作用)  
 * @author yk  
 * @date 2019年5月20日
 */
public class FileUtils {

	
	public static byte[] getBytes(String filePath){  
        byte[] buffer = null;  
        try {  
            File file = new File(filePath);  
            FileInputStream fis = new FileInputStream(file);  
            ByteArrayOutputStream bos = new ByteArrayOutputStream(1000);  
            byte[] b = new byte[1000];  
            int n;  
            while ((n = fis.read(b)) != -1) {  
                bos.write(b, 0, n);  
            }  
            fis.close();  
            bos.close();  
            buffer = bos.toByteArray();  
        } catch (FileNotFoundException e) {  
            e.printStackTrace();  
        } catch (IOException e) {  
            e.printStackTrace();  
        }  
        return buffer;  
    }
	
	
    /**
     * 从文件中获取byte[]内容
     * @创建人 hexin
     * @创建时间 2018年2月6日
     * @创建目的【】
     * @修改目的【修改人：，修改时间：】
     * @param filePath
     * @return
     * @throws IOException
     */
    public synchronized static byte[] getFileContent(String filePath){
    	FileInputStream in = null;
    	ByteArrayOutputStream out = null;
    	byte[] bytes = null;
    	try {
	        in = new FileInputStream(filePath);
	        out=new ByteArrayOutputStream(1024);
	        byte[] temp=new byte[1024];
	        
	        int size=0;
	        while((size=in.read(temp))!=-1)
	        {
	            out.write(temp,0,size);
	        }

	        bytes = out.toByteArray();
	        
		} catch (IOException ex) {
			ex.printStackTrace();
		} finally {
			if(null!=in){
				try {
					in.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if(null!=out){
				try {
					out.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

        return bytes;
     }
    
    /** 
     * 根据byte数组，生成文件 
     */  
    public static void getFile(byte[] bfile, String filePath,String fileName) {  
        BufferedOutputStream bos = null;  
        FileOutputStream fos = null;  
        File file = null;  
        try {  
            File dir = new File(filePath);  
            if(!dir.exists()&&dir.isDirectory()){//判断文件目录是否存在  
                dir.mkdirs();  
            }  
            file = new File(filePath+fileName);  
            fos = new FileOutputStream(file);  
            bos = new BufferedOutputStream(fos);  
            bos.write(bfile);  
        } catch (Exception e) {  
            e.printStackTrace();  
        } finally {  
            if (bos != null) {  
                try {  
                    bos.close();  
                } catch (IOException e1) {  
                    e1.printStackTrace();  
                }  
            }  
            if (fos != null) {  
                try {  
                    fos.close();  
                } catch (IOException e1) {  
                    e1.printStackTrace();  
                }  
            }  
        }  
    }  
	
    
	 /**
	  * 将文本文件中的内容读入到buffer中
	  * @param buffer buffer
	  * @param filePath 文件路径
	  * @throws IOException 异常
	  * @author cn.outofmemory
	  * @date 2013-1-7
	  */
	 public synchronized static void readToBuffer(StringBuffer buffer, String filePath) throws IOException {
	     InputStream is = new FileInputStream(filePath);
	     String line; // 用来保存每行读取的内容
	     BufferedReader reader = new BufferedReader(new InputStreamReader(is));
	     line = reader.readLine(); // 读取第一行
	     while (line != null) { // 如果 line 为空说明读完了
	         buffer.append(line); // 将读到的内容添加到 buffer 中
	         buffer.append("\n"); // 添加换行符
	         line = reader.readLine(); // 读取下一行
	     }
	     reader.close();
	     is.close();
	 }
	
	 /**
	  * 读取文本文件内容
	  * @param filePath 文件所在路径
	  * @return 文本内容
	  * @throws IOException 异常
	  * @author cn.outofmemory
	  * @date 2013-1-7
	  */
	 public synchronized static String readFile(String filePath) throws IOException {
	     StringBuffer sb = new StringBuffer();
	     readToBuffer(sb, filePath);
	     return sb.toString();
	 }
	
}
