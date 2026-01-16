import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class DTA {
    Pairing bp;
    public Field G;
    public Field G_tilde;
    public Field GT;
    public Field Zr;
    public Element g;
    public Element g_tilde;
    public BigInteger p;
    //撤销管理者的数量和阈值
    public static int Rnum=5;
    public static int Rthreshold=3;
    //允许数据库(存储kl和属性)的列表
    public Map<Integer, List<String>> AL;
    //动态阈值累加器的公钥
    public Element dpk;
    //累加器的累加值
    public Element delta;
    //在动态阈值累加器中不添加重复的元素,k_exist用于检查
    public List<BigInteger> k_exist;
    //撤销管理者集合
    public RevocationManager[] revocationManagers = new RevocationManager[Rnum];

    public Pairing getBp() {return bp;}
    public void setBp(Pairing bp) {
        this.bp = bp;
    }

    public RevocationManager[] getRevocationManagers() {
        return revocationManagers;
    }
    public void setRevocationManagers(RevocationManager[] revocationManagers) {
        this.revocationManagers = revocationManagers;
    }

    public Element getDpk() {
        return dpk;
    }
    public void setDpk(Element dpk) {
        this.dpk = dpk;
    }

    public Element getDelta() {
        return delta;
    }

    public Field getZr() {
        return Zr;
    }
    public void setZr(Field zr) {
        Zr = zr;
    }

    public Field getGT() {
        return GT;
    }
    public void setGT(Field GT) {
        this.GT = GT;
    }

    public Element getg() {
        return g;
    }
    public void setg(Element g) {
        this.g = g;
    }

    public Element getg_tilde() {
        return g_tilde;
    }
    public void setg_tilde(Element g_tilde) {
        this.g_tilde = g_tilde;
    }

    public Field getG() {
        return G;
    }
    public void setG(Field g) {
        G = g;
    }

    public Field getG_tilde() {
        return G_tilde;
    }
    public void setG_tilde(Field g_tilde) {
        G_tilde = g_tilde;
    }

    public BigInteger getp() {
        return p;
    }
    public void setp(BigInteger p) {
        this.p = p;
    }

    public Map<Integer, List<String>> getAL() {
        return AL;
    }
    public void setAL(Map<Integer, List<String>> AL) {
        this.AL = AL;
    }

    public static int getRnum() {
        return Rnum;
    }
    public static void setRnum(int rnum) {
        Rnum = rnum;
    }

    public static int getRthreshold() {
        return Rthreshold;
    }
    public static void setRthreshold(int rthreshold) {
        Rthreshold = rthreshold;
    }

    public Map<String, Object> Setup() {
        //生成双线性群bp
        Pairing bp = PairingFactory.getPairing("a.properties");
        this.bp=bp;
        G = bp.getG1(); //G
        setG(G);
        G_tilde = bp.getG2(); //G_tilde
        setG_tilde(G_tilde);
        GT = bp.getGT(); //GT
        setGT(GT);
        Zr = bp.getZr(); //Zp
        setZr(Zr);
        g = G.newRandomElement().getImmutable(); //G的生成元g
        setg(g);
        g_tilde = G_tilde.newRandomElement().getImmutable(); //G_tilde的生成元g_tilde
        setg_tilde(g_tilde);
        p = Zr.getOrder(); //双线性群的阶p
        setp(p);
        //生成撤销管理者
        for(int i=0;i<Rnum;i++){
            revocationManagers[i]=new RevocationManager(p,Zr);
        }
        setRevocationManagers(revocationManagers);
        Map<String, Object> pp = new HashMap<>();
        pp.put("G", G);
        pp.put("G_tilde", G_tilde);
        pp.put("GT", GT);
        pp.put("Zr", Zr);
        pp.put("g", g);
        pp.put("g_tilde", g_tilde);
        pp.put("p", p);
        pp.put("AL", AL);
        return pp;
    }
    //每次进行运算时，需要为撤销管理者生成新的Beaver三元组来进行后续的运算
    public void generateBeaverTriplesForR(){
        //生成Beaver三元组
        // 初始化生成器和参与者
        BeaverTripleGenerator generator = new BeaverTripleGenerator(p, Rnum, Rthreshold, Zr);
        // 生成并分发三元组
        List<BeaverTripleShares> triples = generator.generateBatchTriples(1);
        BeaverTripleShares triple = triples.get(0);
        for (int i = 0; i < Rnum; i++) {
            // 为每个参与者分配三元组份额
            revocationManagers[i].receiveBeaverShares(
                    triple.aShares.get(i + 1),
                    triple.bShares.get(i + 1),
                    triple.cShares.get(i + 1));
        }
        this.setRevocationManagers(revocationManagers);
    }
    public void KeyGen(Map<String, Object> pp) {
        k_exist = new ArrayList<>();
        //生成撤销管理者的公钥和私钥
        Element dsk = Zr.newRandomElement().getImmutable();
        Element dpk = g_tilde.duplicate().powZn(dsk).getImmutable();
        setDpk(dpk);
        //对撤销管理者的私钥份额使用shamir秘密共享进行拆分
        ShamirSecretSharing shamir = new ShamirSecretSharing(p, Zr);
        Map<Integer, BigInteger> dskShares = shamir.shareSecret(dsk.toBigInteger(), Rnum, Rthreshold);
        for (int i = 0; i < Rnum; i++) {
            revocationManagers[i].setDpk(dpk);
            revocationManagers[i].setDsk_m(dskShares.get(i + 1));
        }
    }
    public Element eval(BigInteger k_l){
        //Eval阶段需要使用到Beaver三元组
        generateBeaverTriplesForR();

        for(int i=0;i<k_exist.size();i++){
            if(k_exist.get(i).equals(k_l)){
                System.out.println("该撤销标识符k_l已经存在于累加器中，无法再添加!!!");
                return null;
            }
        }
        k_exist.add(k_l);

        BigInteger[] x_m=new BigInteger[Rnum];
        BigInteger[] r=new BigInteger[Rnum];
        BigInteger[] r1=new BigInteger[Rnum];
        BigInteger[] z=new BigInteger[Rnum];
        Element delta;

        for(int i=0;i<Rnum;i++)
            r1[i]=BigInteger.ZERO;

        for(int i=0;i<Rnum;i++)
        {
            x_m[i]=k_l.add(revocationManagers[i].getDsk_m());
            r[i]= Zr.newRandomElement().toBigInteger();
            ShamirSecretSharing shamirSecretSharing=new ShamirSecretSharing(p,Zr);
            Map<Integer, BigInteger> rm = shamirSecretSharing.shareSecret(r[i], Rnum, Rthreshold);
            for(int j=0;j<Rnum;j++)
            {
                r1[j] = r1[j].add(rm.get(j+1));
            }
        }

        ShamirSecretSharing shamirSecretSharing=new ShamirSecretSharing(p,Zr);
        Map<Integer,BigInteger> shares=new HashMap<>();

        for(int i=0;i<Rnum;i++)
        {
            z[i]=revocationManagers[i].secureMultiply(x_m[i],r1[i]);
            shares.put(i+1,z[i]);
        }
        delta=g.duplicate().pow(shamirSecretSharing.reconstructSecret(shares));
        this.delta=delta;
        System.out.println("动态阈值累加器生成生成累加器值Delta!!!");
        return delta;
    }
    public Map<String,Object> add(BigInteger k_l){

        for(int i=0;i<k_exist.size();i++){
            if(k_exist.get(i).equals(k_l)){
                System.out.println("该撤销标识符k_l已经存在于累加器中，无法再添加!!!");
                return null;
            }
        }
        k_exist.add(k_l);

        Element delta1;
        BigInteger[] x_m=new BigInteger[Rnum];
        for(int i=0;i<Rnum;i++)
            x_m[i]=k_l.add(revocationManagers[i].getDsk_m());
        ShamirSecretSharing shamirSecretSharing=new ShamirSecretSharing(p,Zr);
        Map<Integer,BigInteger> shares=new HashMap<>();
        for(int i=0;i<Rnum;i++)
            shares.put(i+1,x_m[i]);
        delta1=delta.duplicate().pow(shamirSecretSharing.reconstructSecret(shares));
        Map<String,Object> msg=new HashMap<>();
        msg.put("k_l",k_l);
        msg.put("delta",delta);
        msg.put("delta1",delta1);
        msg.put("Add",1);
        this.delta=delta1;
        System.out.println("撤销标识符k_l成功添加到累加器中");
        return msg;

    }
    public Map<String,Object> delete(BigInteger k_l){
        Boolean flag=false;
        for(int i=0;i<k_exist.size();i++){
            if(k_exist.get(i).equals(k_l)){
                flag=true;
                break;
            }
        }
        if(flag==false)
            System.out.println("该撤销标识符k_l不存在于累加器中，执行删除操作失败!!!");
        k_exist.remove(k_l);
        generateBeaverTriplesForR();
        BigInteger[] x_m=new BigInteger[Rnum];
        BigInteger[] r=new BigInteger[Rnum];
        BigInteger[] r1=new BigInteger[Rnum];
        BigInteger[] z1=new BigInteger[Rnum];
        BigInteger[] f=new BigInteger[Rnum];
        for(int i=0;i<Rnum;i++)
            r1[i]=BigInteger.ZERO;
        for(int i=0;i<Rnum;i++)
        {
            x_m[i]=k_l.add(revocationManagers[i].getDsk_m());
            r[i]= Zr.newRandomElement().toBigInteger();
            ShamirSecretSharing shamirSecretSharing=new ShamirSecretSharing(p,Zr);
            Map<Integer, BigInteger> rm = shamirSecretSharing.shareSecret(r[i], Rnum, Rthreshold);
            for(int j=0;j<Rnum;j++) {
                r1[j] = r1[j].add(rm.get(j+1));
            }
        }
        ShamirSecretSharing shamirSecretSharing=new ShamirSecretSharing(p,Zr);
        Map<Integer,BigInteger> shares=new HashMap<>();

        for(int i=0;i<Rnum;i++)
        {
            z1[i]=revocationManagers[i].secureMultiply(x_m[i],r1[i]);
            shares.put(i+1,z1[i]);
        }
        BigInteger z=shamirSecretSharing.reconstructSecret(shares);
        z=z.modInverse(p);
        for(int i=0;i<Rnum;i++) {
            f[i] = z.multiply(r1[i]);
            shares.put(i+1,f[i]);
        }
        Element delta1=this.delta.duplicate().pow(shamirSecretSharing.reconstructSecret(shares));
        Map<String,Object> msg=new HashMap<>();
        msg.put("k_l",k_l);
        msg.put("delta",delta);
        msg.put("delta1",delta1);
        msg.put("Add",-1);
        this.delta=delta1;
        System.out.println("撤销标识符k_l成功从累加器中删除!!!");
        return msg;
    }
    public Element Witupdate(Map<String,Object> msg,BigInteger k1,Element Wit1){
        BigInteger k_l =(BigInteger) msg.get("k_l");
        Element delta=(Element) msg.get("delta");
        Element delta1=(Element) msg.get("delta1");
        Integer add=(Integer) msg.get("Add");

        if(add.equals(1)) {
            Wit1=delta.duplicate().mul(Wit1).pow(k_l.subtract(k1));
        }else if(add.equals(-1)){
            Wit1=(delta1.duplicate().invert().mul(Wit1.duplicate())).pow((k_l.subtract(k1)).modInverse(p));
        }
        System.out.println("用户持有的撤销标识符的见证Wit更新成功!!!");
        return Wit1;
    }
    public Element WitCreate(BigInteger k_l){
        generateBeaverTriplesForR();
        BigInteger[] x_m=new BigInteger[Rnum];
        BigInteger[] r=new BigInteger[Rnum];
        BigInteger[] r1=new BigInteger[Rnum];
        BigInteger[] z1=new BigInteger[Rnum];
        BigInteger[] f=new BigInteger[Rnum];
        Element wit;

        for(int i=0;i<Rnum;i++)
            r1[i]=BigInteger.ZERO;
        for(int i=0;i<Rnum;i++)
        {
            x_m[i]=k_l.add(revocationManagers[i].getDsk_m());
            r[i]= Zr.newRandomElement().toBigInteger();
            ShamirSecretSharing shamirSecretSharing=new ShamirSecretSharing(p,Zr);
            Map<Integer, BigInteger> rm = shamirSecretSharing.shareSecret(r[i], Rnum, Rthreshold);
            for(int j=0;j<Rnum;j++) {
                r1[j] = r1[j].add(rm.get(j+1));
            }
        }
        ShamirSecretSharing shamirSecretSharing=new ShamirSecretSharing(p,Zr);
        Map<Integer,BigInteger> shares=new HashMap<>();

        for(int i=0;i<Rnum;i++)
        {
            z1[i]=revocationManagers[i].secureMultiply(x_m[i],r1[i]);
            shares.put(i+1,z1[i]);
        }
        BigInteger z=shamirSecretSharing.reconstructSecret(shares);
        z=z.modInverse(p);
        for(int i=0;i<Rnum;i++) {
            f[i] = z.multiply(r1[i]);
            shares.put(i+1,f[i]);
        }
        wit=this.delta.duplicate().pow(shamirSecretSharing.reconstructSecret(shares));
        System.out.println("撤销标识符k_l所对应的见证Wit生成成功!!!");
        return wit;
    }
    public boolean Verify(BigInteger k_l,Element wit,Element delta){
        Element e1=bp.pairing(delta,g_tilde);
        Element e2=bp.pairing(wit,g_tilde.duplicate().pow(k_l).mul(dpk));
        if(e1.isEqual(e2)) {
            System.out.println("验证成功，撤销标识符k_l存在于累加器中!!!");
            return true;
        }else{
            System.out.println("验证失败，撤销标识符k_l不存在于累加器中!!!");
            return false;
        }
    }
    public static void main(String[] args) {
        DTA dta=new DTA();
        Map<String, Object> pp = dta.Setup();
        dta.KeyGen(pp);
        BigInteger k_l=new BigInteger("1");
        Element delta = dta.eval(k_l);
        System.out.println("考虑添加元素");
        Element wit = dta.WitCreate(k_l);
        boolean verify = dta.Verify(k_l, wit, dta.delta);
        BigInteger k1=new BigInteger("2");
        System.out.println("添加元素");
        Map<String, Object> msg = dta.add(k1);
        dta.Verify(k_l,wit,dta.delta);
        System.out.println("更新见证");
        Element witupdate = dta.Witupdate(msg, k_l, wit);
        dta.Verify(k_l,witupdate,dta.delta);
        Element wit1=dta.WitCreate(k1);
        System.out.println("考虑删除元素");
       // System.out.println("k1");
        dta.Verify(k1,wit1,dta.delta);
        System.out.println("删除元素");
        Map<String, Object> msg1 = dta.delete(k_l);
        //System.out.println("k1");
        dta.Verify(k1,wit1,dta.delta);
        System.out.println("更新见证");
        Element witupdate1 = dta.Witupdate(msg1, k1, wit1);
       // System.out.println("k1");
        dta.Verify(k1,witupdate1,dta.delta);
       // System.out.println(dta.revocationManagers);
    }
}
