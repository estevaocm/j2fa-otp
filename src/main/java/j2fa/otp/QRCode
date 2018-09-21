package j2fa.otp;

import java.io.IOException;
import java.io.OutputStream;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

public final class QRCode {
	
	private QRCode() {}
	
	public static void generateQRCodeImage(String text, int width, int height, OutputStream out)
            throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height);

        //Path path = FileSystems.getDefault().getPath(filePath);
        //MatrixToImageWriter.writeToPath(bitMatrix, "PNG", path);
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", out);
    }
}
