import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;


public class RevocationManager {
    private ShamirSecretSharing shamir;
    private BigInteger p;
    private Field Zr;

    private BigInteger ashare;
    private BigInteger bshare;
    private BigInteger cshare;

    public Element dpk;
    public BigInteger dsk_m;

    public Element rsk_m;
    public Element rpk_m;

    //存储撤销标识符和开放份额的注册表Regm
    public Map<BigInteger,Element> Regm=new HashMap<>();
    public void setRegm(BigInteger k_l, Element mu_m) {
        Regm.put(k_l,mu_m);
    }
    public Map<BigInteger, Element> getRegm() {
        return Regm;
    }
    public Element getmu_m(BigInteger k_l) {
        return this.Regm.get(k_l);
    }

    public Element getRsk_m() {
        return rsk_m;
    }
    public void setRsk_m(Element rsk_m) {
        this.rsk_m = rsk_m;
    }

    public Element getRpk_m() {
        return rpk_m;
    }
    public void setRpk_m(Element rpk_m) {
        this.rpk_m = rpk_m;
    }

    public Element getDpk() {
        return dpk;
    }
    public void setDpk(Element dpk) {
        this.dpk = dpk;
    }

    public BigInteger getDsk_m() {
        return dsk_m;
    }
    public void setDsk_m(BigInteger dsk_m) {
        this.dsk_m = dsk_m;
    }

    public RevocationManager(BigInteger p, Field Zr) {
        this.p = p;
        this.shamir = new ShamirSecretSharing(p,Zr);
    }

    // 接收Beaver三元组分配
    public void receiveBeaverShares(BigInteger ashare, BigInteger bshare, BigInteger cshare) {
        this.ashare=ashare;
        this.bshare=bshare;
        this.cshare=cshare;
    }
    // 显示当前参与者持有的Beaver三元组份额
    public void showBeaverShares() {
        System.out.println("Beaver Triple Shares:");
        System.out.println("aShare: " + ashare);
        System.out.println("bShare: " + bshare);
        System.out.println("cShare: " + cshare);
    }

    // 使用Beaver三元组进行安全乘法
    public BigInteger secureMultiply(BigInteger xShare, BigInteger yShare) {
        // 计算ε = x - a
        BigInteger epsilon = xShare.subtract(ashare).mod(p);
        // 计算δ = y - b
        BigInteger delta = yShare.subtract(bshare).mod(p);
        // z = c + ε*b + δ*a + ε*δ
        BigInteger term1 = cshare;
        BigInteger term2 = epsilon.multiply(bshare).mod(p);
        BigInteger term3 = delta.multiply(ashare).mod(p);
        BigInteger term4 = epsilon.multiply(delta).mod(p);
        return term1.add(term2).add(term3).add(term4).mod(p);
    }
}
