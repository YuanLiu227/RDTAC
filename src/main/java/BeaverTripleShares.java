import java.math.BigInteger;
import java.util.Map;

// Beaver三元组数据结构
public class BeaverTripleShares {
    public Map<Integer, BigInteger> aShares;
    public Map<Integer, BigInteger> bShares;
    public Map<Integer, BigInteger> cShares;

    public BeaverTripleShares(Map<Integer, BigInteger> aShares,
                              Map<Integer, BigInteger> bShares,
                              Map<Integer, BigInteger> cShares) {
        this.aShares = aShares;
        this.bShares = bShares;
        this.cShares = cShares;
    }
}