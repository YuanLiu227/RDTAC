import it.unisa.dia.gas.jpbc.Field;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class ShamirSecretSharing {
    public BigInteger p; //有限域的素数模数,属于Zp
    public Field Zr; //有限域
    public ShamirSecretSharing(BigInteger p,Field Zr) {
        this.p = p;
        this.Zr=Zr;
    }

    // 在有限域中生成随机多项式(输入阶和秘密值，返回多项式的参数)
    public BigInteger[] generatePolynomial(int degree, BigInteger secret) {
        //多项式参数
        BigInteger[] polynomial = new BigInteger[degree + 1];
        polynomial[0] = secret;
        for (int i = 1; i <= degree; i++) {
            //从有限域Zp中随机选取元素
            polynomial[i] = Zr.newRandomElement().getImmutable().toBigInteger();
        }
        return polynomial;
    }

    // 计算多项式在某点的值(输入第i个参与方的i，和多项式的参数，输出f(i))
    public BigInteger evaluatePolynomial(BigInteger[] polynomial, BigInteger x) {
        BigInteger result = BigInteger.ZERO;
        for (int i = polynomial.length - 1; i >= 0; i--) {
            result = result.multiply(x).add(polynomial[i]).mod(p);
        }
        return result;
    }

    // 秘密共享分发(输入秘密值secret，参与方数量num，阈值threshold，输出每个参与方的份额)
    public Map<Integer, BigInteger> shareSecret(BigInteger secret, int num, int threshold) {
        BigInteger[] polynomial = generatePolynomial(threshold - 1, secret);
        Map<Integer, BigInteger> shares = new HashMap<>();

        for (int i = 1; i <= num; i++) {
            BigInteger x = BigInteger.valueOf(i);
            shares.put(i, evaluatePolynomial(polynomial, x));
        }

        return shares;
    }

    // 秘密重建（输入阈值数量的参与方的份额，使用拉格朗日插值进行秘密重建）
    public BigInteger reconstructSecret(Map<Integer, BigInteger> shares) {
        BigInteger result = BigInteger.ZERO;

        for (Map.Entry<Integer, BigInteger> entry1 : shares.entrySet()) {
            BigInteger xi = BigInteger.valueOf(entry1.getKey());
            BigInteger yi = entry1.getValue();
            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;

            for (Map.Entry<Integer, BigInteger> entry2 : shares.entrySet()) {
                if (entry1.getKey().equals(entry2.getKey())) continue;

                BigInteger xj = BigInteger.valueOf(entry2.getKey());
                numerator = numerator.multiply(xj).mod(p);
                denominator = denominator.multiply(xj.subtract(xi)).mod(p);
            }

            BigInteger term = yi.multiply(numerator).multiply(denominator.modInverse(p)).mod(p);
            result = result.add(term).mod(p);
        }

        return result;
    }
    //计算拉格朗日参数
    public Map<Integer, BigInteger> computeLagrangeCoefficients(Map<Integer, BigInteger> shares) {
        Map<Integer, BigInteger> lagrangeCoefficients = new HashMap<>();
        for (Map.Entry<Integer, BigInteger> entry1 : shares.entrySet()) {
            BigInteger xi = BigInteger.valueOf(entry1.getKey());
            BigInteger numerator = BigInteger.ONE;  // 分子部分: Π(xj)
            BigInteger denominator = BigInteger.ONE; // 分母部分: Π(xj - xi)

            // 遍历其他点计算分子和分母
            for (Map.Entry<Integer, BigInteger> entry2 : shares.entrySet()) {
                if (entry1.getKey().equals(entry2.getKey())) continue;

                BigInteger xj = BigInteger.valueOf(entry2.getKey());
                numerator = numerator.multiply(xj).mod(p);
                denominator = denominator.multiply(xj.subtract(xi)).mod(p);
            }
            // 拉格朗日参数计算: L_i(0) = numerator * denominator^{-1} mod p
            BigInteger denominatorInv = denominator.modInverse(p); // 分母的模逆元
            BigInteger li = numerator.multiply(denominatorInv).mod(p);

            lagrangeCoefficients.put(entry1.getKey(), li);
        }
        return lagrangeCoefficients;
    }
}
