import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DecodeWeather {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String url = "";
		// 70445
		String areaCode = "t_1925";
		if (areaCode.contains("_")) {
			areaCode = areaCode.split("_")[1];
			url = String
					.format("http://tianqi.2345.com/api/getDistrictWeather.json?cityId=%s&token=%s",
							areaCode, getMd5(areaCode + "2345FIkfwEPWOK"));
		} else {
			url = String.format(
					"http://tianqi.2345.com/t/new_mobile_json/%s.json",
					areaCode);
		}

		System.out.println(url);

		try {
			decodeResponse(sendGet(url, ""));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	static void decodeResponse(String str) throws Exception {
		String CIPHER_ALGORITHM_CBC_NoPadding = "AES/CBC/NoPadding";
		String KEY_ALGORITHM = "AES";
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CBC_NoPadding);
		SecretKeySpec secretKey = new SecretKeySpec(
				"2345android_key_".getBytes(), KEY_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(
				"2345tqIv_shiqing".getBytes()));// 使用解密模式初始化 密钥
		byte[] decrypt = cipher.doFinal(hexString2Bytes(str));
		String response = decodeUnicode(new String(decrypt));
		int last = response.lastIndexOf("}");
		response = response.substring(0, last + 1);
		System.out.println(response);
	}

	public static String decodeUnicode(String str) {
		Charset set = Charset.forName("UTF-16");
		Pattern p = Pattern.compile("\\\\u([0-9a-fA-F]{4})");
		Matcher m = p.matcher(str);
		int start = 0;
		int start2 = 0;
		StringBuffer sb = new StringBuffer();
		while (m.find(start)) {
			start2 = m.start();
			if (start2 > start) {
				String seg = str.substring(start, start2);
				sb.append(seg);
			}
			String code = m.group(1);
			int i = Integer.valueOf(code, 16);
			byte[] bb = new byte[4];
			bb[0] = (byte) ((i >> 8) & 0xFF);
			bb[1] = (byte) (i & 0xFF);
			ByteBuffer b = ByteBuffer.wrap(bb);
			sb.append(String.valueOf(set.decode(b)).trim());
			start = m.end();
		}
		start2 = str.length();
		if (start2 > start) {
			String seg = str.substring(start, start2);
			sb.append(seg);
		}
		return sb.toString();
	}

	/**
	 * @Title:hexString2Bytes
	 * @Description:16进制字符串转字节数组
	 * @param src
	 *            16进制字符串
	 * @return 字节数组
	 * @throws
	 */
	public static byte[] hexString2Bytes(String src) {
		int l = src.length() / 2;
		byte[] ret = new byte[l];
		for (int i = 0; i < l; i++) {
			ret[i] = (byte) Integer
					.valueOf(src.substring(i * 2, i * 2 + 2), 16).byteValue();
		}
		return ret;
	}

	static byte[] getIV() {
		String iv = "2345tqIv_shiqing"; // IV length: must be 16 bytes long
		return iv.getBytes();
	}

	public static String getMd5(String str) {
		byte[] bs = md5.digest(str.getBytes());
		StringBuilder sb = new StringBuilder(40);
		for (byte x : bs) {
			if ((x & 0xff) >> 4 == 0) {
				sb.append("0").append(Integer.toHexString(x & 0xff));
			} else {
				sb.append(Integer.toHexString(x & 0xff));
			}
		}
		return sb.toString();
	}

	private static MessageDigest md5 = null;
	static {
		try {
			md5 = MessageDigest.getInstance("MD5");
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	public static String sendGet(String url, String param) {
		String result = "";
		BufferedReader in = null;
		try {

			// String u =
			// "http://tianqi.2345.com/t/inter/mobile_json/54511.json";

			String urlNameString = url + "?" + param;
			URL realUrl = new URL(urlNameString);
			// 打开和URL之间的连接
			URLConnection connection = realUrl.openConnection();

			HttpURLConnection httpUrlConnection = (HttpURLConnection) connection;

			httpUrlConnection.setDoInput(true);
			httpUrlConnection.setRequestMethod("GET");
			httpUrlConnection.setRequestProperty("accept", "*/*");
			httpUrlConnection.setRequestProperty("Content-Type",
					"text/plain; charset=utf-8");
			in = new BufferedReader(new InputStreamReader(
					httpUrlConnection.getInputStream()));
			String line;
			while ((line = in.readLine()) != null) {
				result += line;
			}
		} catch (Exception e) {
			System.out.println("发送GET请求出现异常！" + e);
			e.printStackTrace();
		}
		finally {
			try {
				if (in != null) {
					in.close();
				}
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		}
		return result;
	}

}
