package com.zzc.vigenere;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;

/**
 * Created by ying on 2016/11/18.
 * 维吉尼亚加密算法
 */
public class VigenereCode {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 字符集
     */
    private String charset;
    /**
     * 字符个数
     */
    private int charsetSize;
    /**
     * 密码表
     */
    private char[][] passwordTable;

    /**
     *
     * @param charset 字符集顺序不同也会影响加密结果。字符集规定了加密的目标字符串字符集，秘钥的字符集。秘钥和目标字符串必须在指定字符集之中。
     * @param orderCharset 是否对字符集重新排序。false 不重新排序的时候，字符集和秘钥一致的时候，重新创建对象是可以正确加密解密的。true 重复排序必须使用当前对象的方法才能正确解密。
     */
    public VigenereCode(String charset,boolean orderCharset){
        this.charset = charset;
        this.charsetSize = charset.length();
        passwordTable = new char[this.charsetSize][this.charsetSize];

        ArrayList<Character> chars = new ArrayList<Character>();
        for(int i = 0 ; i < this.charsetSize ; i++){
            chars.add(this.charset.charAt(i));
        }
        if(orderCharset){
            Collections.shuffle(chars);
        }

        //初始化密码表
        for (int i = 0; i < this.charsetSize; i++) {
            for (int j = 0; j < this.charset.length(); j++) {
                passwordTable[i][j] = chars.get((i + j) % this.charsetSize);
            }
        }
    }

    /**
     *
     * 此构造方法必须使用当前对象才能解密
     * @param charset 字符集顺序不同也会影响加密结果。字符集规定了加密的目标字符串字符集，秘钥的字符集。秘钥和目标字符串必须在指定字符集之中。
     */
    public VigenereCode(String charset){
        this(charset, true);
    }

    /**
     * 加密
     * @param plaintext 明文
     * @param key 秘钥
     * @return
     */
    public String encrypt(String plaintext , String key){
        int[] keyInt = this.keyInt(key);
        try{
            char[] targetChars = plaintext.toCharArray();
            for(int i = 0 ; i < targetChars.length ; i++){
                //行
                int row = keyInt[i % keyInt.length];
                //列
                int col = this.charset.indexOf(targetChars[i]);
                //替换
                targetChars[i] = passwordTable[row][col];
            }

            return String.valueOf(targetChars);
        }catch (Exception e){
            logger.error(e.getMessage(),e);
            throw new IllegalArgumentException("参数错误，请注意明文和秘钥中的字符必须包含在指定字符集中");
        }
    }

    /**
     * 解密
     * @param ciphertext
     * @param key
     * @return
     */
    public String decrypt(String ciphertext , String key){
        int[] keyInt = this.keyInt(key);
        try {
            char[] targetChars = ciphertext.toCharArray();
            //解密
            for (int i = 0; i < targetChars.length; i++) {
                //行
                int row = keyInt[i % keyInt.length];
                //列
                int col = 0;
                for (int j = 0; j < this.charsetSize; j++) {
                    if (targetChars[i] == passwordTable[row][j]) {
                        col = j;
                    }
                }
                //替换
                targetChars[i] = this.charset.charAt(col);
            }

            return String.valueOf(targetChars);
        }catch (Exception e){
            logger.error(e.getMessage(),e);
            throw new IllegalArgumentException("参数错误，请注意明文和秘钥中的字符必须包含在指定字符集中");
        }
    }

    /**
     * 将key转化为对应的int数组
     * @param key
     * @return
     */
    private int[] keyInt(String key){
        if(key.length() < 10){
            throw new IllegalArgumentException("秘钥长度必须大于等于10");
        }
        int[] keyInt = new int[key.length()];
        for(int i = 0 ; i < key.length() ; i++){
//            keyInt[i] = this.charset.indexOf(key.charAt(i));
            //稍作变更
            keyInt[i] = (this.charset.indexOf(key.charAt(i))+i) % this.charsetSize;
        }
        return keyInt;
    }

    public static void main(String[] args){
        VigenereCode vigenereCode = new VigenereCode("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWZYZ_1234567890");

        String txt = "helloword88888888888888";
        String key = "1234567890";

        String cipherText = vigenereCode.encrypt(txt,key);
        System.out.println(cipherText);
        System.out.println(vigenereCode.decrypt(cipherText,key));
    }
}
