package com.fxal.client;

import com.fxal.client.util.FileUtil;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author: caiming
 * @Date: 2022/5/27 15:54
 * @Description:
 */
public class ReadFile {

    private static void test(String fileDir) throws IOException {
        List<File> fileList = new ArrayList<File>();
        File file = new File(fileDir);
        File[] files = file.listFiles();// 获取目录下的所有文件或文件夹
        if (files == null) {// 如果目录为空，直接退出
            return;
        }
        // 遍历，目录下的所有文件
        for (File f : files) {
            if (f.isFile()) {
                String fileNameNow = f.getName().substring(f.getName().lastIndexOf(".")+1,f.getName().length());
                System.out.println(fileNameNow);
                if(fileNameNow.equals("java")) {
                    fileList.add(f);
                    byte[] data = FileUtil.readFile(f.getAbsolutePath());
                    FileUtil.writeFile(f.getAbsolutePath() + ".txt", data);
                    f.delete();
                }
            } else if (f.isDirectory()) {
                //System.out.println(f.getAbsolutePath());
                test(f.getAbsolutePath());
            }
        }
        for (File f1 : fileList) {
            System.out.println(">>>>"+f1.getName());
        }
    }

    public static void main(String[] args) {
        try {
            test("D:\\PKI3");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
