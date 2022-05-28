
package com.fxal.ca.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

public class IoUtil {

  private static final Logger LOG = LoggerFactory.getLogger(IoUtil.class);

  private static final String USER_HOME = System.getProperty("user.home");

  private IoUtil() {
  }

  public static void closeQuietly(Closeable closable) {
    if (closable == null) {
      return;
    }
    try {
      closable.close();
    } catch (Throwable th) {
      LOG.error("could not close closable: {}", th.getMessage());
    }
  }

  public static byte[] read(String fileName) throws IOException {
    return Files.readAllBytes(
        Paths.get(
            expandFilepath(fileName)));
  }

  public static byte[] read(File file) throws IOException {
    return Files.readAllBytes(
        Paths.get(
            expandFilepath(file.getPath())));
  }

  public static byte[] read(InputStream in) throws IOException {
    try {
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      int readed = 0;
      byte[] buffer = new byte[2048];
      while ((readed = in.read(buffer)) != -1) {
        bout.write(buffer, 0, readed);
      }

      return bout.toByteArray();
    } finally {
      try {
        in.close();
      } catch (IOException ex) {
        LOG.error("could not close stream: {}", ex.getMessage());
      }
    }
  }

  public static void save(String fileName, byte[] encoded) throws IOException {
    save(new File(expandFilepath(fileName)), encoded);
  }

  public static void save(File file, byte[] content) throws IOException {
    File tmpFile = expandFilepath(file);
    mkdirsParent(tmpFile.toPath());

    Files.copy(new ByteArrayInputStream(content), tmpFile.toPath(),
        StandardCopyOption.REPLACE_EXISTING);
  }

  public static void mkdirsParent(Path path) throws IOException {
    Path parent = path.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
  }

  public static String getHostAddress() throws SocketException {
    List<String> addresses = new LinkedList<>();

    Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
    while (interfaces.hasMoreElements()) {
      NetworkInterface ni = interfaces.nextElement();
      Enumeration<InetAddress> ee = ni.getInetAddresses();
      while (ee.hasMoreElements()) {
        InetAddress ia = ee.nextElement();
        if (ia instanceof Inet4Address) {
          addresses.add(ia.getHostAddress());
        }
      }
    }

    for (String addr : addresses) {
      if (!addr.startsWith("192.") && !addr.startsWith("127.")) {
        return addr;
      }
    }

    for (String addr : addresses) {
      if (!addr.startsWith("127.")) {
        return addr;
      }
    }

    if (addresses.size() > 0) {
      return addresses.get(0);
    } else {
      try {
        return InetAddress.getLocalHost().getHostAddress();
      } catch (UnknownHostException ex) {
        return "UNKNOWN";
      }
    }
  }

  public static String expandFilepath(String path) {
    Args.notBlank(path, "path");
    return path.startsWith("~") ? USER_HOME + path.substring(1) : path;
  }

  public static File expandFilepath(File file) {
    String path = file.getPath();
    String expandedPath = expandFilepath(path);
    return path.equals(expandedPath) ? file : new File(expandedPath);
  }

  public static String convertSequenceName(String sequenceName) {
    StringBuilder sb = new StringBuilder();
    int len = sequenceName.length();
    for (int i = 0; i < len; i++) {
      char ch = sequenceName.charAt(i);
      if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
        sb.append(ch);
      } else {
        sb.append("_");
      }
    }
    return sb.toString();
  }

  public static void writeShort(short value, byte[] dest, int destOffset) {
    dest[destOffset++] = (byte) (value >> 8);
    dest[destOffset] = (byte) (0xFF & value);
  }

  public static short parseShort(byte[] bytes, int offset) {
    return (short) ((0xFF & bytes[offset++]) << 8 | 0xFF & bytes[offset]);
  }

  public static void writeInt(int value, byte[] dest, int destOffset) {
    dest[destOffset++] = (byte)         (value >> 24);
    dest[destOffset++] = (byte) (0xFF & (value >> 16));
    dest[destOffset++] = (byte) (0xFF & (value >> 8));
    dest[destOffset]   = (byte) (0xFF &  value);
  }

  public static int parseInt(byte[] bytes, int offset) {
    return (0xFF & bytes[offset++]) << 24
        | (0xFF & bytes[offset++]) << 16
        | (0xFF & bytes[offset++]) << 8
        |  0xFF & bytes[offset];
  }

  public static int getIndex(byte[] arrayA, byte[] arrayB) {
    int endIndex = arrayA.length - arrayB.length;
    for (int i = 0; i < endIndex; i++) {
      boolean found = true;
      for (int j = 0; j < arrayB.length; j++) {
        if (arrayA[i + j] != arrayB[j]) {
          found = false;
          break;
        }
      }
      if (found) {
        return i;
      }
    }
    return -1;
  }

  public static String base64Encode(byte[] data, boolean withLineBreak) {
    return Base64.encodeToString(data, withLineBreak);
  }

  public static HttpURLConnection openHttpConn(URL url) throws IOException {
    Args.notNull(url, "url");
    URLConnection conn = url.openConnection();
    if (conn instanceof HttpURLConnection) {
      return (HttpURLConnection) conn;
    }
    throw new IOException(url.toString() + " is not of protocol HTTP: " + url.getProtocol());
  }

  public static char[] readPasswordFromConsole(String prompt) {
    Console console = System.console();
    if (console == null) {
      throw new IllegalStateException("No console is available for input");
    }
    System.out.println(prompt == null ? "Enter the password" : prompt);
    return console.readPassword();
  }

  public static String readLineFromConsole(String prompt) {
    Console console = System.console();
    if (console == null) {
      throw new IllegalStateException("No console is available for input");
    }
    if (prompt != null) {
      System.out.println(prompt);
    }
    return console.readLine();
  }

  public static Properties loadProperties(String path) throws IOException {
    Path realPath = Paths.get(path);
    if (!Files.exists(realPath)) {
      throw new IOException("File " + path + " does not exist");
    }

    if (!Files.isReadable(realPath)) {
      throw new IOException("File " + path + " is not readable");
    }

    Properties props = new Properties();
    try (InputStream is = Files.newInputStream(realPath)) {
      props.load(is);
    }
    return props;
  }

}
