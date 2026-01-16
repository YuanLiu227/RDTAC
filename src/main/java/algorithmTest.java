import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * ClassName: algorithmTest
 * Package: PACKAGE_NAME
 * Description:
 *
 * @Author Yuan Liu
 * @Create 2025/10/10 8:50
 * @Version 1.0
 */
public class algorithmTest {

    public static void main(String[] args) {
        try {
            System.out.println("在类型F的双线性群上:");
            TypeFCurveGenerator pg = new TypeFCurveGenerator(160);
            PairingParameters typeFparams=pg.generate();
            System.out.println(typeFparams.toString());
            Pairing bp=PairingFactory.getPairing(typeFparams);
           // PairingFactory.getInstance().setUsePBCWhenPossible(true);
          //  Pairing bp = PairingFactory.getPairing("a.properties");
            Field G1 = bp.getG1();
            Field G2=bp.getG2();
            Field GT=bp.getGT();
            Field Zr = bp.getZr();
            Element g1 = G1.newRandomElement().getImmutable();
            Element g=G1.newRandomElement().getImmutable();
            Element g2 = G2.newRandomElement().getImmutable();
            Element gt=GT.newRandomElement().getImmutable();
            Element e = g2.pow(BigInteger.valueOf(12345));
//            System.out.println(Arrays.toString(e.toBytes()));
//            System.out.println(Arrays.toString(e.toBytes()));
//            System.out.println(e.isEqual(e)); // true
            int warmup = 20;  // 预热次数
            int iterations = 1000; // 正式测试次数
            byte[] g1bytes = g1.toBytes();
            int g1length = g1bytes.length;
            System.out.println(g1length);
            byte[] g2bytes = g2.toBytes();
            int g2length = g2bytes.length;
            System.out.println(g2length);
            BigInteger q = Zr.getOrder();
            System.out.println(q.bitLength());
            byte[] gtbytes = gt.toBytes();
            int gtlength = gtbytes.length;
            System.out.println(gtlength);
            // 预热阶段
            for (int i = 0; i < warmup; i++) {
                Element a = Zr.newRandomElement().getImmutable();
                g1.powZn(a);
            }
            // 测试G1上的指数操作
            long start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                Element a = Zr.newRandomElement().getImmutable(); // 动态指数
                g1.powZn(a);
            }
            double avgG1 = (System.nanoTime() - start) / 1e3 / iterations; // 转换为 µs
            System.out.println("G1上指数操作的平均耗时: " + avgG1/1e3 + " ms");

            //预热操作
            for (int i = 0; i < warmup; i++) {
                Element a = Zr.newRandomElement().getImmutable();
                g2.powZn(a);
            }
            // 测试G2上的指数操作
            start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                Element a = Zr.newRandomElement().getImmutable();
                g2.powZn(a);
            }
            double avgG2 = (System.nanoTime() - start) / 1e3 / iterations;
            System.out.println("G2上指数操作的平均耗时: " + avgG2/1e3 + " ms");

            //预热操作
            for (int i = 0; i < warmup; i++) {
                Element a = Zr.newRandomElement().getImmutable();
                gt.powZn(a);
            }
            // 测试GT上的指数操作
            start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                Element a = Zr.newRandomElement().getImmutable();
                gt.powZn(a);
            }
            double avgGT = (System.nanoTime() - start) / 1e3 / iterations;
            System.out.println("GT上指数操作的平均耗时: " + avgGT/1e3 + " ms");

            //预热操作
            for (int i = 0; i < warmup; i++) {
                bp.pairing(g1,g2);
            }
            // 测试配对操作
            start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                bp.pairing(g1,g2);
            }
            double avgbp = (System.nanoTime() - start) / 1e3 / iterations;
            System.out.println("配对操作的平均耗时: " + avgbp/1e3 + " ms");

            //预热操作
            for (int i = 0; i < warmup; i++) {
                g1.mul(g);
            }
            // 测试G1上的乘法操作
            start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                g1.mul(g);
            }
            double avgmul = (System.nanoTime() - start) / 1e3 / iterations;
            System.out.println("G1上乘法操作的平均耗时: " + avgmul/1e3 + " ms");

        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("在类型A的双线性群上:");
        Pairing bp = PairingFactory.getPairing("a.properties");
        Field G1 = bp.getG1();
        Field G2=bp.getG2();
        Field GT=bp.getGT();
        Field Zr = bp.getZr();
        Element g1 = G1.newRandomElement().getImmutable();
        Element g2 = G2.newRandomElement().getImmutable();
        Element gt=GT.newRandomElement().getImmutable();
        byte[] g1bytes = g1.toBytes();
        int g1length = g1bytes.length;
        System.out.println(g1length);
        byte[] g2bytes = g2.toBytes();
        int g2length = g2bytes.length;
        System.out.println(g2length);
        BigInteger order = Zr.getOrder();
        System.out.println(order.bitLength());
        int warmup = 20;  // 预热次数
        int iterations = 1000; // 正式测试次数
        // 预热阶段
        for (int i = 0; i < warmup; i++) {
            Element a = Zr.newRandomElement().getImmutable();
            g1.powZn(a);
        }
        // 测试G上的指数操作
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            Element a = Zr.newRandomElement().getImmutable(); // 动态指数
            g1.powZn(a);
        }
        double avgG1 = (System.nanoTime() - start) / 1e3 / iterations; // 转换为 µs
        System.out.println("G1上指数操作的平均耗时: " + avgG1/1e3 + " ms");

        // 预热阶段
        for (int i = 0; i < warmup; i++) {
            Element a = Zr.newRandomElement().getImmutable();
            g2.powZn(a);
        }
        // 测试G上的指数操作
        start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            Element a = Zr.newRandomElement().getImmutable(); // 动态指数
            g2.powZn(a);
        }
        double avgG2= (System.nanoTime() - start) / 1e3 / iterations; // 转换为 µs
        System.out.println("G2上指数操作的平均耗时: " + avgG2/1e3 + " ms");


    }
}
