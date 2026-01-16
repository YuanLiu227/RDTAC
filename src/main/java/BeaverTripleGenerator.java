import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import it.unisa.dia.gas.jpbc.Field;
//生成Beaver三元组的类
public class BeaverTripleGenerator {
    private ShamirSecretSharing shamir;
    private BigInteger p;
    private int Rnum;
    private int Rthreshold;
    private Field Zr;

    public BeaverTripleGenerator(BigInteger p, int Rnum, int Rthreshold,Field Zr) {
        this.p = p;
        this.Rnum = Rnum;
        this.Rthreshold = Rthreshold;
        this.Zr=Zr;
        this.shamir = new ShamirSecretSharing(p, Zr);

    }

    // 生成单个Beaver三元组的所有份额
    public BeaverTripleShares generateTripleShares() {
        // 生成随机秘密值a和b
        BigInteger a = Zr.newRandomElement().getImmutable().toBigInteger();
        BigInteger b = Zr.newRandomElement().getImmutable().toBigInteger();
        BigInteger c = a.multiply(b).mod(p);

        // 对各值进行秘密共享
        Map<Integer, BigInteger> aShares = shamir.shareSecret(a, Rnum, Rthreshold);
        Map<Integer, BigInteger> bShares = shamir.shareSecret(b, Rnum, Rthreshold);
        Map<Integer, BigInteger> cShares = shamir.shareSecret(c, Rnum, Rthreshold);

        return new BeaverTripleShares(aShares, bShares, cShares);
    }

    // 批量生成Beaver三元组
    public List<BeaverTripleShares> generateBatchTriples(int count) {
        List<BeaverTripleShares> triples = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            triples.add(generateTripleShares());
        }
        return triples;
    }

    // 验证Beaver三元组的正确性
    public boolean verifyTriple(BeaverTripleShares triple) {
        BigInteger a = shamir.reconstructSecret(triple.aShares);
        BigInteger b = shamir.reconstructSecret(triple.bShares);
        BigInteger c = shamir.reconstructSecret(triple.cShares);
        return c.equals(a.multiply(b).mod(p));
    }
}
