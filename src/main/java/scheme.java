import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;


public class scheme {
    public long totalTime;
    DTA dta=new DTA();
    public Pairing bp;
    public Field G;
    public Field G_tilde;
    public Field GT;
    public Element g;
    public Element g_tilde;
    public Field Zr;
    public BigInteger p;
    public Element g1;
    public Element g2;
    public Element[] h;
    public int Rnum;
    public int Rthreshold;
    public static int Inum;
    public static int Ithreshold;
    //用户
    User user=new User();
    //认证者
    Certifier certifier;
    //发行人
    Issuer[] issuers=new Issuer[Inum];
    //撤销管理者
    RevocationManager[] revocationManagers;

    Map<String,Object> pp;
    //设置发行人的数量
    public static int getInum() {
        return Inum;
    }
    public static void setInum(int inum) {
        Inum = inum;
    }
    //设置发行人的阈值
    public static int getIthreshold() {
        return Ithreshold;
    }
    public static void setIthreshold(int ithreshold) {
        Ithreshold = ithreshold;
    }
    //初始化系统执行时间
    public long getTotalTime() {
        return totalTime;
    }
    public void setTotalTime(int Time) {
        totalTime = Time;
    }

    //系统设置阶段(输入元素的数量q)
    public void Setup(int q){
        System.out.println("********************");
        System.out.println("设置阶段开始");
        long start = System.currentTimeMillis();
        this.pp = dta.Setup();
        revocationManagers=dta.getRevocationManagers();
        bp=dta.getBp();
        G= (Field) dta.getG();
        G_tilde=(Field) dta.getG_tilde();
        GT=(Field) dta.getGT();
        g=(Element) dta.getg();
        g_tilde=(Element) dta.getg_tilde();
        Zr=(Field) dta.getZr();
        Zr=(Field) dta.getZr();
        p=dta.getp();
        Rnum=dta.getRnum();
        Rthreshold=dta.getRthreshold();
        g1=G.newRandomElement().getImmutable();
        g2=G_tilde.newRandomElement().getImmutable();
        certifier=new Certifier(p,Zr);
        h=new Element[q+1];
        for(int i=0;i<q+1;i++){
            h[i]=G.newRandomElement().getImmutable();
        }
        long time=System.currentTimeMillis()-start;
        System.out.println("设置阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("设置阶段结束");
        System.out.println("********************");
        System.out.println();
    }
    public void C_keyGen(){
        System.out.println("********************");
        System.out.println("认证者密钥生成阶段阶段开始");
        long start = System.currentTimeMillis();
        Element csk = Zr.newRandomElement().getImmutable();
        Element cpk = g.duplicate().powZn(csk);
        certifier.setCsk(csk);
        certifier.setCpk(cpk);
        long time=(System.currentTimeMillis()-start);
        totalTime+=time;
        System.out.println("认证者密钥生成阶段所花费的时间为"+time+"ms");
        System.out.println("认证者密钥生成阶段结束");
        System.out.println("********************");
        System.out.println();
    }
    public void U_keyGen(){
        System.out.println("********************");
        System.out.println("用户密钥生成阶段阶段开始");
        long start = System.currentTimeMillis();
        Element usk = Zr.newRandomElement().getImmutable();
        Element upk = g.duplicate().powZn(usk);
        user.setUsk(usk);
        user.setUpk(upk);
        long time=(System.currentTimeMillis()-start);
        totalTime+=time;
        System.out.println("用户密钥生成阶段所花费的时间为"+time+"ms");
        System.out.println("用户密钥生成阶段结束");
        System.out.println("********************");
        System.out.println();
    }
    public void I_keyGen(int q){
        System.out.println("********************");
        System.out.println("发行人密钥生成阶段阶段开始");
        long start = System.currentTimeMillis();
        for(int i=0;i<Inum;i++)
        {
            Element isk_i;
            Element[] r_ij=new Element[q];
            Element ask_i;
            Element ipk_i;
            Element[] R_ij=new Element[q];
            Element[] R_tilde_ij=new Element[q];
            Element apk_i;
            issuers[i]=new Issuer();
            //私钥
            isk_i=Zr.newRandomElement().getImmutable();
            for(int j=0;j<q;j++) {
                r_ij[j] = Zr.newRandomElement().getImmutable();
            }
            ask_i=Zr.newRandomElement().getImmutable();
            //公钥
            ipk_i=g_tilde.duplicate().powZn(isk_i);
            for(int j=0;j<q;j++)
            {
                R_ij[j]=g.duplicate().powZn(r_ij[j]);
                R_tilde_ij[j]=g_tilde.duplicate().powZn(r_ij[j]);
            }
            apk_i=g_tilde.duplicate().powZn(ask_i);
            issuers[i].setIsk_i(isk_i);
            issuers[i].setr_ij(r_ij);
            issuers[i].setAsk_i(ask_i);
            issuers[i].setIpk_i(ipk_i);
            issuers[i].setR_ij(R_ij);
            issuers[i].setR_tilde_ij(R_tilde_ij);
            issuers[i].setApk_i(apk_i);
        }
        long time=(System.currentTimeMillis()-start);
        totalTime+=time;
        System.out.println("发行人密钥生成阶段所花费的时间为"+time+"ms");
        System.out.println("发行人密钥生成阶段结束");
        System.out.println("********************");
        System.out.println();
    }
    public void R_keyGen(){
        System.out.println("********************");
        System.out.println("撤销管理者密钥生成阶段阶段开始");
        long start = System.currentTimeMillis();
        dta.KeyGen(pp);
        for(int i=0;i<revocationManagers.length;i++)
        {
            Element rsk_m=Zr.newRandomElement().getImmutable();
            Element rpk_m=g_tilde.powZn(rsk_m);
            revocationManagers[i].setRsk_m(rsk_m);
            revocationManagers[i].setRpk_m(rpk_m);
        }
        long time=(System.currentTimeMillis()-start);
        totalTime+=time;
        System.out.println("撤销管理者密钥生成阶段所花费的时间为"+time+"ms");
        System.out.println("撤销管理者密钥生成阶段结束");
        System.out.println("********************");
        System.out.println();
    }
    public void KeyGen(int q){
        //认证者
        C_keyGen();
        //用户
        U_keyGen();
        //发行人
        I_keyGen(q);
        //撤销管理者
        R_keyGen();
    }
    // 将一系列元素进行哈希，转化为大整数
//    public BigInteger Hash(List<Element> elements) throws NoSuchAlgorithmException {
//        // 1. 初始化SHA-256
//        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
//        // 2. 遍历所有元素，转换为字节并拼接
//        byte[] concatenatedBytes = new byte[0];
//        int bytes=100;
//        for (Element element : elements) {
//            // 2.1 将Element转换为字节（仿to_binary256）
//            byte[] elementBytes = element.toBytes();  // 默认返回压缩格式的字节
//            // 2.2 可选：确保固定长度256位（32字节），不足补零
//            byte[] fixedLengthBytes = new byte[bytes];
//            System.arraycopy(elementBytes, 0, fixedLengthBytes,
//                    Math.max(0, bytes - elementBytes.length),
//                    Math.min(elementBytes.length, bytes));
//            // 2.3 拼接字节
//            byte[] newConcatenated = new byte[concatenatedBytes.length + fixedLengthBytes.length];
//            System.arraycopy(concatenatedBytes, 0, newConcatenated, 0, concatenatedBytes.length);
//            System.arraycopy(fixedLengthBytes, 0, newConcatenated, concatenatedBytes.length, fixedLengthBytes.length);
//            concatenatedBytes = newConcatenated;
//        }
//        // 3. 计算SHA-256哈希
//        byte[] hashBytes = sha256.digest(concatenatedBytes);
//        // 4. 将哈希结果转为无符号大整数（模拟Python的int.from_bytes）
//        return new BigInteger(1, hashBytes);  // 参数1表示正数
//    }
    public BigInteger Hash(List<Element> elements) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        for (Element e : elements) {
            sha256.update(e.toBytes());  // 不需要手动补零、拼接
        }

        byte[] hash = sha256.digest();
        return new BigInteger(1, hash);
    }
    // 将一系列元素进行哈希，转化为Element类型
//    public Element HashtoElement(List<Element> elements) throws NoSuchAlgorithmException {
//        // 1. 初始化SHA-256
//        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
//        int bytes=100;
//        // 2. 遍历所有元素，转换为字节并拼接
//        byte[] concatenatedBytes = new byte[0];
//        for (Element element : elements) {
//            // 2.1 将Element转换为字节（仿to_binary256）
//            byte[] elementBytes = element.toBytes();  // 默认返回压缩格式的字节
//            // 2.2 可选：确保固定长度256位（32字节），不足补零
//            byte[] fixedLengthBytes = new byte[bytes];
//            System.arraycopy(elementBytes, 0, fixedLengthBytes,
//                    Math.max(0, bytes - elementBytes.length),
//                    Math.min(elementBytes.length, bytes));
//            // 2.3 拼接字节
//            byte[] newConcatenated = new byte[concatenatedBytes.length + fixedLengthBytes.length];
//            System.arraycopy(concatenatedBytes, 0, newConcatenated, 0, concatenatedBytes.length);
//            System.arraycopy(fixedLengthBytes, 0, newConcatenated, concatenatedBytes.length, fixedLengthBytes.length);
//            concatenatedBytes = newConcatenated;
//        }
//        // 3. 计算SHA-256哈希
//        byte[] hashBytes = sha256.digest(concatenatedBytes);
//        // 4. 将哈希结果转为无符号大整数（模拟Python的int.from_bytes）
//        return G.newElement().setFromHash(hashBytes, 0, hashBytes.length).getImmutable();
//    }
    public Element HashtoElement(List<Element> elements, Field G) throws NoSuchAlgorithmException {
        // 1. 初始化 SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // 2. 顺序更新每个元素的字节表示
        for (Element e : elements) {
            sha256.update(e.toBytes());
        }

        // 3. 计算最终哈希值
        byte[] hashBytes = sha256.digest();

        // 4. 将哈希映射到目标群 G 中
        Element h = G.newElement().setFromHash(hashBytes, 0, hashBytes.length).getImmutable();

        return h;
    }

    public Map<String,Object> make_pi_1(Element C1,Element upk,Element[] attri,Element r,Element usk) throws NoSuchAlgorithmException {
        //选取了两个随机数
        Element r_1=Zr.newRandomElement().getImmutable();
        Element usk_1=Zr.newRandomElement().getImmutable();
        //计算了承诺和公钥
        Element C1_1=g.duplicate().powZn(r_1).mul(h[0].powZn(usk_1));
        for(int i=0;i<attri.length;i++)
        {
            C1_1=C1_1.mul(h[i+1].powZn(attri[i]));
        }
        Element upk_1=g.powZn(usk_1);
        List<Element> elements=new ArrayList<>();
        elements.add(C1);
        elements.add(C1_1);
        elements.add(upk);
        elements.add(upk_1);
        //计算挑战
        BigInteger c=Hash(elements);
        //计算回应
        Element rr= r_1.sub(r.mul(c));
        Element rusk=usk_1.sub(usk.mul(c));
        Map<String,Object> zkpm1=new HashMap<>();
        zkpm1.put("c",c);
        zkpm1.put("rr",rr);
        zkpm1.put("rusk",rusk);
        Element upk_2=upk.duplicate().pow(c).mul(g.powZn(rusk));
        System.out.println("零知识证明pi_1生成");
        return zkpm1;
    }

    public Map<String,Object> requestVcert(List<String> attribute) {
        System.out.println("********************");
        System.out.println("请求可验证凭证阶段开始");
        long start = System.currentTimeMillis();
        String Attribute[]=new String[attribute.size()];
        for(int i=0;i<attribute.size();i++)
            Attribute[i]=attribute.get(i);
        Element[] attri=new Element[Attribute.length];
        for(int i=0;i<Attribute.length;i++)
        {
            byte[] bytes = Attribute[i].getBytes(StandardCharsets.UTF_8);
            attri[i] = Zr.newElement().setFromHash(bytes, 0, bytes.length).getImmutable();
        }
        Element r = Zr.newRandomElement().getImmutable();
        user.setR(r);
        Element usk=user.getUsk();
        Element C1 = g.duplicate().powZn(r).mul(h[0].powZn(usk));
        for(int i=0;i<attri.length;i++)
            C1=C1.mul(h[i+1].duplicate().powZn(attri[i]));
        Map<String, Object> zkpm1;
        try {
            zkpm1 = make_pi_1(C1, user.getUpk(), attri, r, user.getUsk());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Map<String, Object> req1 = new HashMap<>();
        req1.put("C1", C1);
        req1.put("upk", user.getUpk());
        req1.put("a", attri);
        req1.put("attribute",attribute);
        req1.put("zkpm1", zkpm1);
        long time=System.currentTimeMillis()-start;
        System.out.println("请求可验证凭证阶段所所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("请求可验证凭证阶段结束");
        System.out.println("********************");
        System.out.println();
        return req1;
    }
    public Map<String, Object> IssueVcert (Map<String,Object>req1){
        System.out.println("********************");
        System.out.println("发行可验证凭证阶段开始");
        long start = System.currentTimeMillis();
        //零知识证明验证
        Element C1=(Element) req1.get("C1");
        Element upk=(Element) req1.get("upk");
        Element[] attri=(Element[]) req1.get("a");
        List<String> attribute=(List<String>) req1.get("attribute");
        Map<String,Object> zkpm1=(Map<String,Object>)req1.get("zkpm1");
        BigInteger c=(BigInteger) zkpm1.get("c");
        Element rr=(Element) zkpm1.get("rr");
        Element rusk=(Element) zkpm1.get("rusk");
        BigInteger x=new BigInteger("1");
        Element C1_1=C1.duplicate().pow(c).mul(g.duplicate().powZn(rr)).mul(h[0].duplicate().powZn(rusk));
        for(int i=0;i<attri.length;i++)
        {
            C1_1=C1_1.mul(h[i+1].powZn(attri[i].mul(x.subtract(c))));
        }
        Element upk_1=upk.duplicate().pow(c).mul(g.duplicate().powZn(rusk));
        List<Element> elements=new ArrayList<>();
        elements.add(C1);
        elements.add(C1_1);
        elements.add(upk);
        elements.add(upk_1);
        BigInteger c_1;
        try {
            c_1=Hash(elements);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        if(c.equals(c_1))
            System.out.println("零知识证明pi_1通过");
        else
            System.out.println("零知识证明pi_1未通过");
        Element k=Zr.newRandomElement().getImmutable();
        Element K=g.duplicate().powZn(k).getImmutable();
        Element k_l=Zr.newRandomElement();
        List<Element> elements1=new ArrayList<>();
        elements1.add(C1);
        elements1.add(K);
        elements1.add(k_l);
        BigInteger e;
        try {
            e=Hash(elements1);
        } catch (NoSuchAlgorithmException e1) {
            throw new RuntimeException(e1);
        }
        Element S=k.duplicate().add(certifier.getCsk().mul(e));
        Map<String,Object> msg1=new HashMap<>();
        msg1.put("k_l",k_l);
        msg1.put("C1",C1);
        certifier.setRevealIdentity(k_l.toBigInteger(),attribute);
        List<Element> sign=new ArrayList<>();
        sign.add(K);
        sign.add(S);
        msg1.put("sign",sign);
        long time=(System.currentTimeMillis()-start);
        System.out.println("发行可验证凭证阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("发行可验证凭证阶段结束");
        System.out.println("********************");
        System.out.println();
        return msg1;
    }
    public void VerifyVCert(Map<String,Object> msg1){
        System.out.println("********************");
        System.out.println("验证可验证证书阶段开始");
        long start = System.currentTimeMillis();
        List<Element> sign=(List<Element>) msg1.get("sign");
        Element k_l=(Element) msg1.get("k_l");
        Element K=sign.get(0);
        Element S=sign.get(1);
        Element C1=(Element) msg1.get("C1");
        List<Element> elements1=new ArrayList<>();
        elements1.add(C1);
        elements1.add(K);
        elements1.add(k_l);
        BigInteger e;
        try {
            e=Hash(elements1);
        } catch (NoSuchAlgorithmException e1) {
            throw new RuntimeException(e1);
        }
        Element left=g.duplicate().powZn(S);
        Element right=K.duplicate().mul(certifier.getCpk().duplicate().pow(e));
        if(left.equals(right))
            System.out.println("可验证证书Vcert验证成功");
        else
            System.out.println("可验证证书Vcert验证失败");
        long time=(System.currentTimeMillis()-start);
        System.out.println("验证可验证证书阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("验证可验证证书阶段结束");
        System.out.println("********************");
    }

    public Map<String,Object> make_pi_2(Element C1,Element[] X,int len,Element H,Element[] attri,Element[] o) {
        Element[] a_1=new Element[len];
        Element[] o_1=new Element[len];
        Element r_1=Zr.newRandomElement().getImmutable();
        Element usk_1=Zr.newRandomElement().getImmutable();
        Element r=user.getR().getImmutable();
        Element usk=user.getUsk().getImmutable();
        for(int i=0;i<len;i++)
        {
            a_1[i]=Zr.newRandomElement().getImmutable();
            o_1[i]=Zr.newRandomElement().getImmutable();
        }
        Element C1_1=g.duplicate().powZn(r_1).mul(h[0].powZn(usk_1));
        for(int i=0;i<len;i++)
        {
            C1_1=C1_1.mul(h[i+1].duplicate().powZn(a_1[i]));
        }
        Element[] X_1=new Element[len];
        for(int i=0;i<len;i++)
        {
            X_1[i]=g.duplicate().powZn(o_1[i]).mul(H.duplicate().powZn(a_1[i]));
        }
        List<Element> elements=new ArrayList<>();
        elements.add(C1);
        elements.add(C1_1);
        for(int i=0;i<len;i++)
            elements.add(X[i]);
        for(int i=0;i<len;i++)
            elements.add(X_1[i]);
        BigInteger c2;
        try {
            c2=Hash(elements);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Element[] ra=new Element[len];
        Element[] ro=new Element[len];
        Element rr=r_1.sub(r.mul(c2));
        Element rusk=usk_1.sub(usk.mul(c2));
        for (int i=0;i<len;i++)
        {
            ra[i]=a_1[i].duplicate().sub(attri[i].duplicate().mul(c2));
            ro[i]=o_1[i].duplicate().sub(o[i].duplicate().mul(c2));
        }
        Map<String,Object> zkpm2=new HashMap<>();
        zkpm2.put("c2",c2);
        zkpm2.put("rr",rr);
        zkpm2.put("rusk",rusk);
        zkpm2.put("ra",ra);
        zkpm2.put("ro",ro);
        System.out.println("零知识证明pi_2生成");
        return zkpm2;
    }
    public Map<String,Object> prepare_credential_request(Map<String,Object> req1,Map<String,Object> msg1) {
        System.out.println("********************");
        System.out.println("准备凭证请求阶段开始");
        long start = System.currentTimeMillis();
        Element C1=(Element)req1.get("C1");
        Element[] attri=(Element[]) req1.get("a");
        int len=attri.length;
        List<Element> elements=new ArrayList<>();
        elements.add(C1);
        Element H;
        try {
            H=HashtoElement(elements,G);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Element[] o=new Element[len];
        Element[] X=new Element[len];
        for(int i=0;i<len;i++)
        {
            o[i]=Zr.newRandomElement().getImmutable();
            X[i]=g.duplicate().powZn(o[i]).mul(H.duplicate().powZn(attri[i])).getImmutable();
        }
        user.setO(o);
        Map<String,Object> zkpm2=make_pi_2(C1,X,len,H,attri,o);
        Element k_l= (Element) msg1.get("k_l");
        List<Element> sign=(List<Element>) msg1.get("sign");
        Map<String,Object> req2=new HashMap<>();
        req2.put("k_l",k_l);
        req2.put("C1",C1);
        req2.put("sign",sign);
        req2.put("X",X);
        req2.put("zkpm2",zkpm2);
        long time=(System.currentTimeMillis()-start);
        System.out.println("准备凭证请求阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("准备凭证请求阶段阶段结束");
        System.out.println("********************");
        System.out.println();
        return req2;
    }
    public Map<String,Object>[] partial_credentials_issuance(Map<String,Object> req2) {
        System.out.println("********************");
        System.out.println("部分凭证发行阶段开始");
        Element[] s_tilde=new Element[Inum];
        Map<String,Object>[] sigma=new Map[Inum];
        long start = System.currentTimeMillis();
        for(int i=0;i<Inum;i++) { //所有发行人执行下列操作
            System.out.println("第"+(i+1)+"个发行人执行如下操作:");
            Element k_l = (Element) req2.get("k_l");
            Element C1 = (Element) req2.get("C1");
            List<Element> sign = (List<Element>) req2.get("sign");
            Element K = sign.get(0);
            Element S = sign.get(1);
            Element[] X = (Element[]) req2.get("X");
            Map<String, Object> zkpm2 = (Map<String, Object>) req2.get("zkpm2");
            BigInteger c2 = (BigInteger) zkpm2.get("c2");
            Element rr = (Element) zkpm2.get("rr");
            Element rusk = (Element) zkpm2.get("rusk");
            Element[] ra = (Element[]) zkpm2.get("ra");
            Element[] ro = (Element[]) zkpm2.get("ro");
            int len = X.length;
            List<Element> elements=new ArrayList<>();
            elements.add(C1);
            Element H;
            try {
                H=HashtoElement(elements,G);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            Map<String,Object> msg=new HashMap<>();
            msg.put("sign",sign);
            msg.put("C1",C1);
            msg.put("k_l",k_l);
            //验证零知识证明pi_2
            Element C1_1 = C1.duplicate().pow(c2).mul(g.duplicate().powZn(rr)).mul(h[0].duplicate().powZn(rusk));
            for(int j=0;j<len;j++) {
                C1_1=C1_1.mul(h[j+1].powZn(ra[j]));
            }
            Element[] X_1=new Element[len];
            for(int j=0;j<len;j++){
                X_1[j] = X[j].duplicate().pow(c2).mul(g.duplicate().powZn(ro[j])).mul(H.duplicate().powZn(ra[j]));
            }
            List<Element> elements1=new ArrayList<>();
            elements1.add(C1);
            elements1.add(C1_1);
            for(int j=0;j<len;j++)
                elements1.add(X[j]);
            for(int j=0;j<len;j++)
                elements1.add(X_1[j]);
            BigInteger c;
            try {
                c=Hash(elements1);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            if(c2.equals(c)) {
                System.out.println("零知识证明pi_2通过");
            }else{
                System.out.println("零知识证明pi_2未通过");
                return null;
            }
            //可验证证书验证成功
            VerifyVCert(msg);
            Element iski = issuers[i].getIsk_i();
            Element[] r_ij = issuers[i].getr_ij();
            Element aski = issuers[i].getAsk_i();
            s_tilde[i]=H.duplicate().powZn(iski).mul(H.duplicate().powZn(aski.mul(k_l)));
            for(int j=0;j<len;j++)
                s_tilde[i]=s_tilde[i].mul(X[j].duplicate().powZn(r_ij[j]));
            sigma[i]=new HashMap<>();
            sigma[i].put("h",H);
            sigma[i].put("s_tilde",s_tilde[i]);
        }
        long time=(System.currentTimeMillis()-start);
        System.out.println("部分凭证发行阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("部分凭证发行阶段结束");
        System.out.println("********************");
        System.out.println();
        return sigma;
    }
    public Map<String, Object>[] unblind_credential(Map<String,Object>[] sigma_tilde){
        System.out.println("********************");
        System.out.println("解盲凭证阶段开始");
        long start = System.currentTimeMillis();
        Element[] o=user.getO();
        Map<String,Object>[] sigma=new Map[Inum];
        for(int i=0;i<Inum;i++)
        {
            sigma[i]=new HashMap<>();
            Element[] R_ij=issuers[i].getR_ij();
            Element h=(Element) sigma_tilde[i].get("h");
            Element s_tilde=(Element) sigma_tilde[i].get("s_tilde");
            Element s=s_tilde.duplicate();
            for(int j=0;j<o.length;j++)
            {
                s=s.mul(R_ij[j].duplicate().powZn(o[j].negate()));
            }
            sigma[i].put("h",h);
            sigma[i].put("s",s);
        }
        long time=(System.currentTimeMillis()-start);
        System.out.println("解盲阶段所花费的时间为:"+time+"ms");
        System.out.println("解盲阶段结束");
        System.out.println("********************");
        System.out.println();
        return sigma;
    }
    public Map<String,Object> credential_aggregation(Map<String, Object>[] sigma1,Boolean[] b,int q){
        System.out.println("********************");
        System.out.println("凭证聚合阶段开始");
        long start = System.currentTimeMillis();
        Map<String,Object> sigma=new HashMap<>();
        Element h= (Element) sigma1[0].get("h");
        Element s=G.newOneElement().getImmutable();
        //聚合凭证
        for(int i=0;i<Inum;i++){
            if(b[i]){ //发行人已发行
                s=s.mul((Element) sigma1[i].get("s"));
            }
        }
//        System.out.println("credential size:");
//        System.out.println("h:"+h.getLengthInBytes());
//        System.out.println("s:"+s.getLengthInBytes());
        sigma.put("h",h);
        sigma.put("s",s);
        //聚合公钥
        Element ipk=G_tilde.newOneElement().getImmutable();
        Element apk=G_tilde.newOneElement().getImmutable();
        for(int i=0;i<Inum;i++){
            Element ipki = issuers[i].getIpk_i();
            Element apki = issuers[i].getApk_i();
            if(b[i]){
                ipk=ipk.mul(ipki);
                apk=apk.mul(apki);
            }
        }
        //聚合关于属性的公钥
        Element[] R_tilde_j=new Element[q];
        for(int j=0;j<q;j++)
        {
            R_tilde_j[j]=G_tilde.newOneElement().getImmutable();
            for(int i=0;i<Inum;i++)
            {
                Element[] R_tilde_ij = issuers[i].getR_tilde_ij();
                if(b[i]){
                    R_tilde_j[j]=R_tilde_j[j].mul(R_tilde_ij[j]);
                }
            }
        }
        Map<String,Object> aggr=new HashMap<>();
        aggr.put("sigma",sigma);
        aggr.put("ipk",ipk);
        aggr.put("apk",apk);
        aggr.put("R_tilde_j",R_tilde_j);
        long time=(System.currentTimeMillis()-start);
        System.out.println("凭证聚合阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("凭证聚合阶段结束");
        System.out.println("********************");
        System.out.println();
        return aggr;
    }
    public Map<String,Object> open_share_computation(Map<String,Object> req1,int q,Map<String,Object> aggr,Map<String,Object> req2){
        System.out.println("********************");
        System.out.println("开放份额计算阶段开始");
        long start = System.currentTimeMillis();
        //获得属性
        Element[] attri1=(Element[]) req1.get("a");;
        //获得承诺C1,计算H
        Element C1=(Element) req1.get("C1");
        //获得聚合公钥
        Element[] R_tilde_j=(Element[]) aggr.get("R_tilde_j");
        BigInteger[] attri=new BigInteger[q];
        for(int i=0;i<q;i++)
            attri[i]= attri1[i].toBigInteger();
        ShamirSecretSharing[] shamirSecretSharings=new ShamirSecretSharing[q];
        //存储属性的拉格朗日参数
        BigInteger[][] polynomials=new BigInteger[q][Rthreshold];
        BigInteger[][] s=new BigInteger[Rnum][q];
        //对属性进行处理
        for(int i=0;i<q;i++) {
            shamirSecretSharings[i]=new ShamirSecretSharing(p,Zr);
            //对第i个属性进行处理
            polynomials[i] = shamirSecretSharings[i].generatePolynomial(Rthreshold-1, attri[i]);
            // System.out.println("----------");
            for(int j=0;j<Rnum;j++){
                //对于第j个撤销管理者
                BigInteger x=BigInteger.valueOf(j+1);
                BigInteger y=shamirSecretSharings[i].evaluatePolynomial(polynomials[i],x);
                s[j][i]=y; //代表属性的份额值
            }
        }
        List<Element> elements=new ArrayList<>();
        elements.add(C1);
        Element H;
        try {
            H=HashtoElement(elements,G);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Element[] mu=new Element[Rnum];
        Element[] rm=new Element[Rnum];
        Element[] U1=new Element[Rnum];
        Element[] U2=new Element[Rnum];
        for(int i=0;i<Rnum;i++){
            Element rpkm = revocationManagers[i].getRpk_m();
            //撤销管理者
            mu[i]=G_tilde.newOneElement().getImmutable();
            for(int j=0;j<q;j++){
                mu[i]=mu[i].mul(R_tilde_j[j].pow(s[i][j]));
            }
            rm[i]=Zr.newRandomElement().getImmutable();
            U1[i]=g_tilde.duplicate().powZn(rm[i]);
            U2[i]=rpkm.powZn(rm[i]).mul(mu[i]);
        }
        //对多项式参数的隐藏
        Element [][] H1=new Element[q][Rthreshold];
        for(int i=0;i<q;i++)
            for(int j=1;j<Rthreshold;j++)
                H1[i][j]=H.pow(polynomials[i][j]);
        Element[] X=(Element[]) req2.get("X");
        Element[] H2=new Element[Rnum];
        for(int i=0;i<Rnum;i++)
            H2[i]=H.powZn(rm[i]);
        Element[] Ro=new Element[q];
        Element[] o=user.getO();
        for(int i=0;i<q;i++){
            Ro[i]=G_tilde.newOneElement().getImmutable();
            Ro[i]=Ro[i].mul(R_tilde_j[i].powZn(o[i]));
        }
        Map<String, Object> zkpm3 = make_pi_3(U1, U2, H, X, R_tilde_j,  rm, s, q, H2, Ro,mu);
        Element k_l=(Element) req2.get("k_l");
        Element apk=(Element) aggr.get("apk");
        Map<String,Object> msg2=new HashMap<>();
        msg2.put("k_l",k_l);
        msg2.put("U1",U1);
        msg2.put("U2",U2);
        msg2.put("mu",mu);
        msg2.put("H",H);
        msg2.put("H1",H1);
        msg2.put("R_tilde_j",R_tilde_j);
        msg2.put("apk",apk);
        msg2.put("zkpm3",zkpm3);
        long time=(System.currentTimeMillis()-start);
        System.out.println("开放份额计算阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("开放份额计算阶段结束");
        System.out.println("********************");
        System.out.println();
        return msg2;
    }
    public  Map<String,Object> make_pi_3(Element[] U1,Element[] U2,Element H,Element[] X,Element[] R_tilde_j,Element[] rm,BigInteger[][] s,int q,Element[] H2,Element[] Ro,Element[] mu){
        //每个撤销管理者都需要进行零知识证明
        Element[] o=user.getO();
        Element[] rm_1=new Element[Rnum];
        Element[][] o_1=new Element[Rnum][q];
        BigInteger[][] s_1=new BigInteger[Rnum][q];
        Element[] U1_1=new Element[Rnum];
        Element[][] Ro_1=new Element[Rnum][q]; //对于每个撤销管理者，生成不同的
        Element[] H2_1=new Element[Rnum];
        Element[] U2_1=new Element[Rnum];
        BigInteger[] c=new BigInteger[Rnum];
        Element[] rrm=new Element[Rnum];
        Element[][] ro=new Element[Rnum][q];
        BigInteger [][] rs=new BigInteger[Rnum][q];
        Element[] mu_1=new Element[Rnum];
        //对于每个撤销管理者执行操作
        for(int i=0;i<Rnum;i++){
            Element rpkm = revocationManagers[i].getRpk_m();
            rm_1[i]=Zr.newRandomElement().getImmutable();
            for(int j=0;j<q;j++){
                o_1[i][j]=Zr.newRandomElement().getImmutable();
                s_1[i][j]=Zr.newRandomElement().toBigInteger();
            }
            U1_1[i]=g_tilde.duplicate().powZn(rm_1[i]);
            for(int j=0;j<q;j++)
                Ro_1[i][j]=R_tilde_j[j].powZn(o_1[i][j]);
            H2_1[i]=H.powZn(rm_1[i]);
            U2_1[i]=(rpkm.powZn(rm_1[i]));
            for(int j=0;j<q;j++) {
                U2_1[i] = U2_1[i].mul(R_tilde_j[j].pow(s_1[i][j].mod(p)));
            }
            List<Element> elements=new ArrayList<>();
            elements.add(U1[i]);
            elements.add(U2[i]);
            elements.add(U1_1[i]);
            elements.add(U2_1[i]);
            elements.add(H2[i]);
            elements.add(H2_1[i]);
            for(int j=0;j<q;j++)
                elements.add(Ro[j]);
            for(int j=0;j<q;j++)
                elements.add(Ro_1[i][j]);
            try {
                c[i]=Hash(elements);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            rrm[i]=rm_1[i].duplicate().sub(rm[i].mul(c[i]));
            for(int j=0;j<q;j++){
                ro[i][j]=o_1[i][j].duplicate().sub(o[j].mul(c[i]));
                rs[i][j]=s_1[i][j].subtract(s[i][j].multiply(c[i]).mod(p));
            }
        }
        Map<String,Object> zkpm3=new HashMap<>();
        zkpm3.put("Ro",Ro);
        zkpm3.put("H2",H2);
        zkpm3.put("c3",c);
        zkpm3.put("rrm",rrm);
        zkpm3.put("ro",ro);
        zkpm3.put("rs",rs);
        System.out.println("零知识证明pi_3生成");
        return zkpm3;
    }
    public Map<String,Object> witness_computation(Map<String,Object> req2,Map<String,Object> msg2,int q) {
        System.out.println("********************");
        System.out.println("见证计算阶段开始");
        long start = System.currentTimeMillis();
        Element k_l = (Element) msg2.get("k_l");
        Element[] U1 = (Element[]) msg2.get("U1");
        Element[] U2 = (Element[]) msg2.get("U2");
        Map<String, Object> zkpm3 = (Map<String, Object>) msg2.get("zkpm3");
        Element[] Ro = (Element[]) zkpm3.get("Ro");
        Element[] H2 = (Element[]) zkpm3.get("H2");
        BigInteger[] c=(BigInteger[]) zkpm3.get("c3");
        Element[] rrm = (Element[]) zkpm3.get("rrm");
        Element[][] ro = (Element[][]) zkpm3.get("ro");
        BigInteger[][] rs=(BigInteger[][]) zkpm3.get("rs");
        Element[] R_tilde_j=(Element[]) msg2.get("R_tilde_j");
        Element[] U1_1=new Element[Rnum];
        Element[][] Ro_1=new Element[Rnum][q]; //对于每个撤销管理者，生成不同的
        Element[] H2_1=new Element[Rnum];
        Element[] U2_1=new Element[Rnum];
        Element dpk;
        Element Delta;
        BigInteger[] c3=new BigInteger[Rnum];
        for (int i = 0; i < Rnum; i++) { //所有撤销管理者执行如下操作
            System.out.println("****************");
            System.out.println("第"+(i+1)+"个撤销管理者执行如下操作:");
            Element rpkm = revocationManagers[i].getRpk_m();
            Element C1 = (Element) req2.get("C1");
            List<Element> sign = (List<Element>) req2.get("sign");
            Element K = sign.get(0);
            Element S = sign.get(1);
            Element[] X = (Element[]) req2.get("X");
            Map<String, Object> zkpm2 = (Map<String, Object>) req2.get("zkpm2");
            BigInteger c2 = (BigInteger) zkpm2.get("c2");
            Element rr = (Element) zkpm2.get("rr");
            Element rusk = (Element) zkpm2.get("rusk");
            Element[] ra = (Element[]) zkpm2.get("ra");
            Element[] ro1 = (Element[]) zkpm2.get("ro");
            int len = X.length;
            List<Element> elements = new ArrayList<>();
            elements.clear();
            elements.add(C1);
            Element H;
            try {
                H = HashtoElement(elements,G);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            Map<String, Object> msg = new HashMap<>();
            msg.put("sign", sign);
            msg.put("C1", C1);
            msg.put("k_l", k_l);
            //验证零知识证明pi_2
            Element C1_1 = C1.duplicate().pow(c2).mul(g.duplicate().powZn(rr)).mul(h[0].duplicate().powZn(rusk));
            for (int j = 0; j < len; j++) {
                C1_1 = C1_1.mul(h[j + 1].powZn(ra[j]));
            }
            Element[] X_1 = new Element[len];
            for (int j = 0; j < len; j++) {
                X_1[j] = X[j].duplicate().pow(c2).mul(g.duplicate().powZn(ro1[j])).mul(H.duplicate().powZn(ra[j]));
            }
            List<Element> elements1 = new ArrayList<>();
            elements1.add(C1);
            elements1.add(C1_1);
            for (int j = 0; j < len; j++)
                elements1.add(X[j]);
            for (int j = 0; j < len; j++)
                elements1.add(X_1[j]);
            BigInteger c1;
            try {
                c1 = Hash(elements1);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            if (c2.equals(c1)) {
                System.out.println("零知识证明pi_2通过");
            } else {
                System.out.println("零知识证明pi_2未通过");
            }
            //可验证证书验证成功
            VerifyVCert(msg);
            //验证零知识证明pi_3
            U1_1[i]=U1[i].duplicate().pow(c[i]).mul(g_tilde.duplicate().powZn(rrm[i]));
            for(int j=0;j<q;j++)
                Ro_1[i][j]=Ro[j].duplicate().pow(c[i]).mul(R_tilde_j[j].duplicate().powZn(ro[i][j]));
            H2_1[i]=H2[i].duplicate().pow(c[i]).mul(H.duplicate().powZn(rrm[i]));
            U2_1[i]=U2[i].duplicate().pow(c[i].mod(p)).mul(rpkm.duplicate().powZn(rrm[i]));
            for(int j=0;j<q;j++)
                U2_1[i]=U2_1[i].mul(R_tilde_j[j].duplicate().pow(rs[i][j].mod(p)));
            List<Element> elements3=new ArrayList<>();
            elements3.add(U1[i]);
            elements3.add(U2[i]);
            elements3.add(U1_1[i]);
            elements3.add(U2_1[i]);
            elements3.add(H2[i]);
            elements3.add(H2_1[i]);
            for(int j=0;j<q;j++)
                elements3.add(Ro[j]);
            for(int j=0;j<q;j++)
                elements3.add(Ro_1[i][j]);
            try {
                c3[i]=Hash(elements3);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            if(c[i].equals(c3[i])) {
                System.out.println("零知识证明pi_3通过");
            }else{
                System.out.println("零知识证明pi_3未通过");
            }
            Element[][] H1=(Element[][]) msg2.get("H1");
            Element left=GT.newOneElement();
            Element right=GT.newOneElement();

            left =bp.pairing(H,U2[i]);
            for(int j=0;j<q;j++)
                left=left.mul(bp.pairing(g,Ro[j]));
            right=bp.pairing(H2[i],rpkm);
            for(int j=0;j<q;j++){
                Element middle=X[j];
                for(int k=1;k<Rthreshold;k++)
                {
                    BigInteger exp = (BigInteger.valueOf(i+1)) .mod(p).modPow(BigInteger.valueOf(k), p);
                    middle = middle.mul(H1[j][k].pow(exp));
                }
                right=right.mul(bp.pairing(middle,R_tilde_j[j]));
            }
            if(left.isEqual(right))
                System.out.println("零知识证明pi_3式子验证通过");
            else
                System.out.println("零知识证明pi_3式子验证未通过");

        }
        // Revocation handle Witness Generation
        BigInteger k=k_l.duplicate().toBigInteger();
        //添加撤销标识符k_l到累加器Delta中
        if(dta.getDelta()==null){ //说明k_l第一次添加到累加器中
            Delta=dta.eval(k);
        }else{ //说明k_l不是第一次添加到累加器中
            Map<String,Object>msg=dta.add(k);
            Delta= (Element) msg.get("Delta1");
        }
        Element Wit=dta.WitCreate(k);
        Element apk=(Element) msg2.get("apk");
        for(int i=0;i<Rnum;i++){

            Element rskm = revocationManagers[i].getRsk_m();
            Element mu_m=U2[i].mul(U1[i].powZn(rskm.negate()));
            Map<Integer, BigInteger> k_l_share = certifier.send_k_l(k, Rnum, Rthreshold);
            Element mu_m_1=mu_m.mul(apk.duplicate().pow(k_l_share.get(i+1)));
            revocationManagers[i].setRegm(k,mu_m_1);
        }
        Map<String,Object> msg3=new HashMap<>();
        msg3.put("k_l",k);
        msg3.put("Wit",Wit);
        msg3.put("Delta",Delta);
        long time=(System.currentTimeMillis()-start);
        System.out.println("见证计算阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("见证计算阶段结束");
        System.out.println("********************");
        System.out.println();
        return msg3;
    }
    public Map<String,Object> prove_cred(Map<String,Object> msg3,Map<String,Object> aggr,Boolean[] b,int q,Map<String,Object> req1){
        System.out.println("********************");
        System.out.println("展示凭证阶段开始");
        long start = System.currentTimeMillis();
        Map<String,Object> sigma=(Map<String, Object>) aggr.get("sigma");
        Element ipk=(Element) aggr.get("ipk");
        Element apk=(Element) aggr.get("apk");
        Element[] R_tilde_j=(Element[]) aggr.get("R_tilde_j");
        Element[] attri=(Element[]) req1.get("a");
        BigInteger k_l=(BigInteger) msg3.get("k_l");
        Element wit=(Element) msg3.get("Wit");
        Element Delta=(Element) msg3.get("Delta");
        Element h=(Element) sigma.get("h");
        Element s=(Element) sigma.get("s");
        Element r1=Zr.newRandomElement().getImmutable();
        Element r2=Zr.newRandomElement().getImmutable();
        //随机化凭证
        Element h_1=h.powZn(r2);
        Element s_1=s.powZn(r2);
        Element k=ipk.mul(apk.pow(k_l)).mul(g_tilde.duplicate().powZn(r1));
        for(int j=0;j<q;j++)
            k=k.mul(R_tilde_j[j].powZn(attri[j]));
        Element v=h_1.powZn(r1);
        //隐藏k_l和wit的过程中需要生成的随机数
        Element r=Zr.newRandomElement().getImmutable();
        Element tau1=Zr.newRandomElement().getImmutable();
        Element tau2=Zr.newRandomElement().getImmutable();
        Element C_k_l=g2.duplicate().powZn(r).mul(g_tilde.duplicate().pow(k_l));
        Element delta1=tau1.duplicate().mul(r);
        Element delta2=tau2.duplicate().mul(r);
        Element pi_I_1=g.duplicate().powZn(tau1).mul(g1.duplicate().powZn(tau2));
        Element pi_I_2= wit.duplicate().mul(g1.duplicate().powZn(tau1));
        //随机化凭证的零知识证明生成
        Element[] a_1=new Element[q];
        BigInteger k_l_1=Zr.newRandomElement().getImmutable().toBigInteger();
        Element r1_1=Zr.newRandomElement().getImmutable();
        for(int j=0;j<q;j++)
            a_1[j]=Zr.newRandomElement().getImmutable();
        Element k_1=ipk.mul(apk.pow(k_l_1)).mul(g_tilde.duplicate().powZn(r1_1));
        for(int j=0;j<q;j++)
            k_1=k_1.mul(R_tilde_j[j].powZn(a_1[j]));
        Element v_1=h_1.powZn(r1_1);
        List<Element> elements=new ArrayList<>();
        elements.add(k);
        elements.add(k_1);
        elements.add(v);
        elements.add(v_1);
        BigInteger c1;
        try {
            c1=Hash(elements);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Element[] ra=new Element[q];
        for(int j=0;j<q;j++)
            ra[j]=a_1[j].sub(attri[j].mul(c1));
        Element rr1=r1_1.sub(r1.mul(c1));
        BigInteger rk_l=(k_l_1.subtract(k_l.multiply(c1).mod(p))).mod(p);
        //隐藏k_l和wit的零知识证明生成
        Element r_1=Zr.newRandomElement().getImmutable();
        Element tau1_1=Zr.newRandomElement().getImmutable();
        Element tau2_1=Zr.newRandomElement().getImmutable();
        Element delta1_1=Zr.newRandomElement().getImmutable();
        Element delta2_1=Zr.newRandomElement().getImmutable();
        Element dpk=revocationManagers[0].getDpk();
        Element R1=g.duplicate().powZn(tau1_1).mul(g1.duplicate().powZn(tau2_1));
        Element R2=pi_I_1.duplicate().powZn(r_1).mul(g.duplicate().powZn(delta1_1.duplicate().negate())).mul(g1.duplicate().powZn(delta2_1.duplicate().negate()));
        Element R3=bp.pairing(g1,C_k_l.duplicate().mul(dpk)).powZn(tau1_1).mul(bp.pairing(g1,g2).powZn(delta1_1.duplicate().negate())).mul(bp.pairing(pi_I_2,g2).powZn(r_1));
        List<Element> elements1=new ArrayList<>();
        elements1.add(C_k_l);
        elements1.add(pi_I_1);
        elements1.add(pi_I_2);
        elements1.add(R1);
        elements1.add(R2);
        elements1.add(R3);
        BigInteger c2;
        try {
            c2=Hash(elements);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Element sr=r_1.add(r.mul(c2));
        Element stau1=tau1_1.add(tau1.mul(c2));
        Element stau2=tau2_1.add(tau2.mul(c2));
        Element sdelta1=delta1_1.add(delta1.mul(c2));
        Element sdelta2=delta2_1.add(delta2.mul(c2));
        Map<String,Object> zkpm4=new HashMap<>();
        zkpm4.put("c1",c1);
        zkpm4.put("ra",ra);
        zkpm4.put("rr1",rr1);
        zkpm4.put("rk_l",rk_l);
        zkpm4.put("c2",c2);
        zkpm4.put("sr",sr);
        zkpm4.put("stau1",stau1);
        zkpm4.put("stau2",stau2);
        zkpm4.put("sdelta1",sdelta1);
        zkpm4.put("sdelta2",sdelta2);
        zkpm4.put("R1",R1);
        zkpm4.put("R2",R2);
        zkpm4.put("R3",R3);
        Map<String,Object> msg4=new HashMap<>();
        msg4.put("R_tilde_j",R_tilde_j);
        msg4.put("ipk",ipk);
        msg4.put("apk",apk);
        msg4.put("b",b);
        msg4.put("h_1",h_1);
        msg4.put("s_1",s_1);
        msg4.put("k",k);
        msg4.put("v",v);
        msg4.put("C_k_l",C_k_l);
        msg4.put("delta1",delta1);
        msg4.put("delta2",delta2);
        msg4.put("pi_I_1",pi_I_1);
        msg4.put("pi_I_2",pi_I_2);
        msg4.put("zkpm4",zkpm4);
        msg4.put("Delta",Delta);
        long time=(System.currentTimeMillis()-start);
        System.out.println("展示凭证阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("展示凭证阶段结束");
        System.out.println("********************");
        System.out.println();
        return msg4;
    }
    public Map<String,Object> verify_cred(Map<String,Object> msg4,int q){
        System.out.println("********************");
        System.out.println("验证凭证阶段开始");
        long start = System.currentTimeMillis();
        Element[] R_tilde_j=(Element[]) msg4.get("R_tilde_j");
        Element ipk=(Element) msg4.get("ipk");
        Element apk=(Element) msg4.get("apk");
        Boolean[] b=(Boolean[]) msg4.get("b");
        Element h_1=(Element) msg4.get("h_1");
        Element s_1=(Element) msg4.get("s_1");
        Element k=(Element) msg4.get("k");
        Element v=(Element) msg4.get("v");
        Element C_k_l=(Element) msg4.get("C_k_l");
        Element delta1=(Element) msg4.get("delta1");
        Element delta2=(Element) msg4.get("delta2");
        Element pi_I_1=(Element) msg4.get("pi_I_1");
        Element pi_I_2=(Element) msg4.get("pi_I_2");
        Map<String,Object> zkpm4=(Map<String, Object>) msg4.get("zkpm4");
        BigInteger c1=(BigInteger) zkpm4.get("c1");
        BigInteger c2=(BigInteger) zkpm4.get("c2");
        Element[] ra=(Element[]) zkpm4.get("ra");
        Element rr1=(Element) zkpm4.get("rr1");
        BigInteger rk_l=(BigInteger) zkpm4.get("rk_l");
        Element sr=(Element) zkpm4.get("sr");
        Element stau1=(Element) zkpm4.get("stau1");
        Element stau2=(Element) zkpm4.get("stau2");
        Element sdelta1=(Element) zkpm4.get("sdelta1");
        Element sdelta2=(Element) zkpm4.get("sdelta2");
        Element R1=(Element) zkpm4.get("R1");
        Element R2=(Element) zkpm4.get("R2");
        Element R3=(Element) zkpm4.get("R3");
        Element Delta=(Element) msg4.get("Delta");
        if(h_1.isEqual(G.newOneElement())){
            System.out.println("h等于1");
        }else{
            System.out.println("h不等于1");
        }
        Element k_1=k.pow(c1).mul(ipk.pow((BigInteger.valueOf(1).subtract(c1)).mod(p))).mul(apk.pow(rk_l)).mul(g_tilde.powZn(rr1));
        for(int j=0;j<q;j++)
            k_1=k_1.mul(R_tilde_j[j].powZn(ra[j]));
        Element v_1=v.pow(c1).mul(h_1.powZn(rr1));
        List<Element> elements=new ArrayList<>();
        elements.add(k);
        elements.add(k_1);
        elements.add(v);
        elements.add(v_1);
        BigInteger c1_1;
        try {
            c1_1=Hash(elements);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        if(c1.equals(c1_1)){
            System.out.println("随机化凭证的零知识证明验证成功");
        }else{
            System.out.println("随机化凭证的零知识证明验证失败");
        }
        //关于k_l和wit的零知识证明
        List<Element> elements1=new ArrayList<>();
        elements1.add(C_k_l);
        elements1.add(pi_I_1);
        elements1.add(pi_I_2);
        elements1.add(R1);
        elements1.add(R2);
        elements1.add(R3);
        BigInteger c3;
        try {
            c3=Hash(elements);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Element dpk=revocationManagers[0].getDpk();
        Element R1_1=pi_I_1.duplicate().pow(c3.negate().mod(p)).mul(g.duplicate().powZn(stau1)).mul(g1.duplicate().powZn(stau2));
        Element R2_1=pi_I_1.duplicate().powZn(sr).mul(g.duplicate().powZn(sdelta1.duplicate().negate())).mul(g1.duplicate().powZn(sdelta2.duplicate().negate()));
        if(R1.isEqual(R1_1)){
            System.out.println("R1等于R1_1");
        }else{
            System.out.println("R1不等于R1_1");
        }
        if(R2.isEqual(R2_1)){
            System.out.println("R2等于R2_1");
        }else{
            System.out.println("R2不等于R2_1");
        }
        Element ans1=R3.duplicate().mul(bp.pairing(pi_I_2,C_k_l.duplicate().mul(dpk)).pow(c3));

        Element ans2=bp.pairing(g1.duplicate(),C_k_l.duplicate().mul(dpk).duplicate()).duplicate().powZn(stau1.duplicate()).mul(bp.pairing(g1.duplicate(),g2.duplicate()).duplicate().powZn(sdelta1.duplicate().negate())).duplicate().mul(bp.pairing(pi_I_2.duplicate(),g2.duplicate()).powZn(sr.duplicate())).duplicate().mul(bp.pairing(Delta.duplicate(),g_tilde.duplicate()).pow(c3));
        if(ans1.isEqual(ans2)){
            System.out.println("ans1等于ans2");
        }else{
            System.out.println("ans1不等于ans2");
        }
        //验证凭证正确性
        Element cr_left=bp.pairing(h_1,k);
        Element cr_right=bp.pairing(s_1.duplicate().mul(v),g_tilde);
        if(cr_left.isEqual(cr_right)){
            System.out.println("凭证验证成功，服务提供商提供服务");
        }else{
            System.out.println("凭证验证失败，服务提供商拒绝提供服务");
        }
        Map<String,Object> msg5=new HashMap<>();
        msg5.put("h_1",h_1);
        msg5.put("s_1",s_1);
        msg5.put("ipk",ipk);
        long time=(System.currentTimeMillis()-start);
        System.out.println("验证凭证阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("验证凭证阶段结束");
        System.out.println("********************");
        System.out.println();
        return msg5;
    }
    public void credential_revocation(Map<String,Object> msg5,Boolean[] t){
        System.out.println("********************");
        System.out.println("凭证撤销阶段开始");
        long start = System.currentTimeMillis();
        Element h_1=(Element) msg5.get("h_1");
        Element s_1=(Element) msg5.get("s_1");
        Element ipk=(Element) msg5.get("ipk");
        ShamirSecretSharing shamirSecretSharing=new ShamirSecretSharing(p,Zr);
        Map<BigInteger, Element> Regm = revocationManagers[0].getRegm();
        //获得了所有的k_l
        Set<BigInteger> k_ls=Regm.keySet();
        List<BigInteger> k_list=new ArrayList<>(k_ls);
        Map<BigInteger,Element[]> P_ks=new HashMap<>();
        for(int j=0;j<k_ls.size();j++){ //第j个k_l
            Element[] P_k=new Element[Rnum];
            for(int i=0;i<Rnum;i++){ //第i个撤销管理者
                //第i个撤销管理者的第j个k_l
                Element mu_m=revocationManagers[i].getmu_m(k_list.get(j));
                P_k[i]=bp.pairing(h_1,mu_m);
            }
            P_ks.put(k_list.get(j),P_k);
        }
        Map<Integer,BigInteger> shares=new HashMap<>();
        for(int i=1;i<=Rnum;i++)
            shares.put(i,BigInteger.valueOf(i));
        Map<Integer, BigInteger> coefficients = shamirSecretSharing.computeLagrangeCoefficients(shares);
        BigInteger ans=BigInteger.ONE;
        for(int i=0;i<k_list.size();i++){
            BigInteger k_l=k_list.get(i);
            Element[] P_k = P_ks.get(k_l);
            Element left=bp.pairing(h_1,ipk);
            for(int j=0;j<Rnum;j++)
                left=left.mul(P_k[j].pow(coefficients.get(j+1)));
            Element right=bp.pairing(s_1,g_tilde);
            if(left.isEqual(right)){
                System.out.println("寻找随机化后的凭证对应的撤销标识符k_l成功");
                ans=k_l;
                break;
            }
        }
        Map<String, Object> msg = dta.delete(ans);
        System.out.println("凭证撤销成功!!!");
        List<String> user_identity=certifier.getRevealIdentity(ans);
        System.out.println("-----------");
        System.out.println("认证者揭露用户的身份:");
        for(int i=0;i<user_identity.size();i++)
            System.out.println(user_identity.get(i));
        System.out.println("-------------");
        long time=(System.currentTimeMillis()-start);
        System.out.println("凭证撤销阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("凭证撤销阶段结束");
        System.out.println("********************");
        System.out.println();
    }
    public Map<String,Object> self_revocation(Map<String,Object> msg3,Map<String,Object> aggr,Boolean[] b,int q,Map<String,Object> req1){
        System.out.println("********************");
        System.out.println("请求自我撤销阶段开始");
        long start = System.currentTimeMillis();
        Map<String,Object> sigma=(Map<String, Object>) aggr.get("sigma");
        Element ipk=(Element) aggr.get("ipk");
        Element apk=(Element) aggr.get("apk");
        Element[] R_tilde_j=(Element[]) aggr.get("R_tilde_j");
        Element[] attri=(Element[]) req1.get("a");
        BigInteger k_l=(BigInteger) msg3.get("k_l");
        Element wit=(Element) msg3.get("Wit");
        Element Delta=(Element) msg3.get("Delta");
        Element h=(Element) sigma.get("h");
        Element s=(Element) sigma.get("s");
        Element r1=Zr.newRandomElement().getImmutable();
        Element r2=Zr.newRandomElement().getImmutable();
        //随机化凭证
        Element h_1=h.powZn(r2);
        Element s_1=s.powZn(r2);
        Element k=ipk.mul(apk.pow(k_l)).mul(g_tilde.duplicate().powZn(r1));
        for(int j=0;j<q;j++)
            k=k.mul(R_tilde_j[j].powZn(attri[j]));
        Element v=h_1.powZn(r1);
        Element[] a_1=new Element[q];
        Element r1_1=Zr.newRandomElement().getImmutable();
        for(int j=0;j<q;j++)
            a_1[j]=Zr.newRandomElement().getImmutable();
        Element k_1=ipk.mul(apk.pow(k_l)).mul(g_tilde.duplicate().powZn(r1_1));
        for(int j=0;j<q;j++)
            k_1=k_1.mul(R_tilde_j[j].powZn(a_1[j]));
        Element v_1=h_1.powZn(r1_1);
        List<Element> elements=new ArrayList<>();
        elements.add(k);
        elements.add(k_1);
        elements.add(v);
        elements.add(v_1);
        BigInteger c1;
        try {
            c1=Hash(elements);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Element[] ra=new Element[q];
        for(int j=0;j<q;j++)
            ra[j]=a_1[j].sub(attri[j].mul(c1));
        Element rr1=r1_1.sub(r1.mul(c1));
        Map<String,Object> msg6=new HashMap<>();
        msg6.put("R_tilde_j",R_tilde_j);
        msg6.put("ipk",ipk);
        msg6.put("apk",apk);
        msg6.put("b",b);
        msg6.put("h_1",h_1);
        msg6.put("s_1",s_1);
        msg6.put("k",k);
        msg6.put("v",v);
        msg6.put("k_l",k_l);
        msg6.put("wit",wit);
        msg6.put("Delta",Delta);
        Map<String,Object> zkpm6=new HashMap<>();
        zkpm6.put("c",c1);
        zkpm6.put("ra",ra);
        zkpm6.put("rr1",rr1);
        msg6.put("zkpm6",zkpm6);
        long time=(System.currentTimeMillis()-start);
        System.out.println("请求自我撤销阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("请求自我撤销阶段结束");
        System.out.println("********************");
        System.out.println();
        return msg6;
    }
    public void execute_self_revocation(Map<String,Object> msg6,Boolean[] t,int q){
        System.out.println("********************");
        System.out.println("执行自我撤销阶段开始");
        long start = System.currentTimeMillis();
        Element[] R_tilde_j=(Element[]) msg6.get("R_tilde_j");
        Element ipk=(Element) msg6.get("ipk");
        Element apk=(Element) msg6.get("apk");
        Boolean[] b=(Boolean[]) msg6.get("b");
        Element h_1=(Element) msg6.get("h_1");
        Element s_1=(Element) msg6.get("s_1");
        Element k=(Element) msg6.get("k");
        Element v=(Element) msg6.get("v");
        BigInteger k_l=(BigInteger) msg6.get("k_l");
        Element wit=(Element) msg6.get("wit");
        Element Delta=(Element) msg6.get("Delta");
        Map<String,Object> zkpm6=(Map<String, Object>) msg6.get("zkpm6");
        BigInteger c=(BigInteger) zkpm6.get("c");
        Element[] ra=(Element[]) zkpm6.get("ra");
        Element rr1=(Element) zkpm6.get("rr1");
        //随机化凭证的零知识证明
        if(h_1.isEqual(G.newOneElement())){
            System.out.println("h等于1");
        }else{
            System.out.println("h不等于1");
        }
        Element k_1=k.pow(c).mul(ipk.pow((BigInteger.valueOf(1).subtract(c)).mod(p))).mul(apk.pow((k_l.multiply(BigInteger.valueOf(1).subtract(c)).mod(p)).mod(p))).mul(g_tilde.powZn(rr1));
        for(int j=0;j<q;j++)
            k_1=k_1.mul(R_tilde_j[j].powZn(ra[j]));
        Element v_1=v.pow(c).mul(h_1.powZn(rr1));
        List<Element> elements=new ArrayList<>();
        elements.add(k);
        elements.add(k_1);
        elements.add(v);
        elements.add(v_1);
        BigInteger c_1;
        try {
            c_1=Hash(elements);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        if(c.equals(c_1)){
            System.out.println("随机化凭证的零知识证明验证成功");
        }else{
            System.out.println("随机化凭证的零知识证明验证失败");
        }
        Element cr_left=bp.pairing(h_1,k);
        Element cr_right=bp.pairing(s_1.duplicate().mul(v),g_tilde);
        if(cr_left.isEqual(cr_right)){
            System.out.println("凭证验证成功,可以继续执行撤销操作");
        }else{
            System.out.println("凭证验证失败，停止执行撤销操作");
        }
        Element dpk=revocationManagers[0].getDpk();
        Element left=bp.pairing(Delta,g_tilde);
        Element right=bp.pairing(wit,dpk.duplicate().mul(g_tilde.duplicate().pow(k_l)));
        if(left.isEqual(right)){
            System.out.println("撤销标识符k_l存在于累加器中，可以执行撤销操作");
        }else{
            System.out.println("撤销标识符k_l不存在于累加器中，停止执行撤销操作");
        }
        dta.delete(k_l);
        List<String> user_identity=certifier.getRevealIdentity(k_l);
        System.out.println("-----------");
        System.out.println("认证者揭露用户的身份:");
        for(int i=0;i<user_identity.size();i++)
            System.out.println(user_identity.get(i));
        System.out.println("-------------");
        long time=(System.currentTimeMillis()-start);
        System.out.println("执行自我撤销阶段所花费的时间为:"+time+"ms");
        totalTime+=time;
        System.out.println("执行自我撤销阶段结束");
        System.out.println("********************");
        System.out.println();
    }
    public static Boolean[] generateBooleanArray(int total, int requiredTrue) {
        if (requiredTrue < 0 || requiredTrue > total) {
            throw new IllegalArgumentException("Invalid requiredTrue value");
        }
        Boolean[] arr = new Boolean[total];
        Arrays.fill(arr, Boolean.FALSE);
        Random rand = new Random();
        int count=requiredTrue + (total > requiredTrue ? rand.nextInt(total - requiredTrue + 1) : 0);
        // 分配必要的true值
        for (int i = 0; i < count; i++) {
            int index;
            do {
                index = rand.nextInt(total);
            } while (arr[index]);
            arr[index] = true;
        }
        return arr;
    }
    public static void main(String[] args) {
        System.out.println("系统开始执行...");
        System.out.println();
        Scanner sc=new Scanner(System.in);
        //发行人和撤销管理者的数量和阈值在方案执行前就要确定
        int Inum=5;
        int Ithreshold=3;
        int Rnum=5;
        int Rthreshold=3;
//        System.out.println("设置发行人的数量");
//        Inum=sc.nextInt();
//        System.out.println("设置发行人的阈值");
//        Ithreshold=sc.nextInt();
//        System.out.println("设置撤销管理者的数量");
//        Rnum=sc.nextInt();
//        System.out.println("设置撤销管理者的阈值");
//        Rthreshold=sc.nextInt();
        scheme.setInum(Inum);
        scheme.setIthreshold(Ithreshold);
        DTA.setRnum(Rnum);
        DTA.setRthreshold(Rthreshold);
        List<String> attribute = new ArrayList<>();
        attribute.add("Alice");
        attribute.add("female");
        attribute.add("员工");
        attribute.add("23");
        attribute.add("3000");
        scheme scheme=new scheme();
        scheme.setTotalTime(0);
        scheme.Setup(attribute.size());
        scheme.KeyGen(attribute.size());
        Map<String, Object> req1 = scheme.requestVcert(attribute);
        Map<String, Object> msg1 = scheme.IssueVcert(req1);
        // scheme.VerifyVCert(msg1);
        Map<String, Object> req2 = scheme.prepare_credential_request(req1, msg1);
        Map<String, Object>[] sigma_tilde = scheme.partial_credentials_issuance(req2);
        Map<String, Object>[] sigma = scheme.unblind_credential(sigma_tilde);
        //发行人的集合
        Boolean[] b=generateBooleanArray(Inum,Ithreshold);
        Map<String, Object> aggr = scheme.credential_aggregation(sigma, b, attribute.size());
        Map<String, Object> msg2 = scheme.open_share_computation(req1, attribute.size(), aggr, req2);
        //撤销管理者的集合
        Boolean[] t=generateBooleanArray(Rnum,Rthreshold);
        Map<String, Object> msg3 = scheme.witness_computation(req2, msg2, attribute.size());
        Map<String, Object> msg4 = scheme.prove_cred(msg3, aggr, b, attribute.size(), req1);
        Map<String, Object> msg5 = scheme.verify_cred(msg4, attribute.size());
        scheme.credential_revocation(msg5,t);
        //   Map<String, Object> msg6 = scheme.self_revocation(msg3, aggr, b, attribute.size(), req1);
        //  scheme.execute_self_revocation(msg6,t,attribute.size());
        System.out.println("系统执行完毕!!!");
        System.out.println("匿名凭证系统所花费的时间为"+scheme.getTotalTime()+"ms");
    }
}
