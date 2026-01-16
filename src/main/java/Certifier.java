import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
public class Certifier {
    private Element csk;
    private Element cpk;
    Map<BigInteger, List<String>> data;
    public BigInteger p; //有限域的素数模数,属于Zp
    public Field Zr; //有限域
    //存储每次撤销管理者向认证者申请k_l的份额所对应的k_l
    public List<BigInteger> k_l_list=new ArrayList<>();
    //存储(k_l,k_l_shares)
    public Map<BigInteger,Map<Integer, BigInteger>> k_l_map=new HashMap<>();
    //存储(k_l,attributes)，存储撤销标识符和用户属性的数据库
    public Map<BigInteger,List<String>> revealList=new HashMap<>();

    //撤销标识符-属性数据库的处理函数
    public List<String> getRevealIdentity(BigInteger k_l) {
        return revealList.get(k_l);
    }
    public void setRevealIdentity(BigInteger k_l,List<String> attribute) {
        revealList.put(k_l,attribute);
    }

    //认证者的初始化操作
    public Certifier(BigInteger p, Field Zr) {
        this.p = p;
        this.Zr=Zr;
    }
    public Map<BigInteger, List<String>> getData() {
        return data;
    }
    public void setData(Map<BigInteger, List<String>> data) {
        this.data = data;
    }
    //关于认证者私钥的操作
    public Element getCsk() {
        return csk;
    }
    public void setCsk(Element csk) {
        this.csk = csk;
    }
    //关于认证者公钥的操作
    public Element getCpk() {
        return cpk;
    }
    public void setCpk(Element cpk) {
        this.cpk = cpk;
    }

    public Map<Integer, BigInteger> send_k_l(BigInteger k_l,int Rnum,int Rthreshold){
        ShamirSecretSharing shamirSecretSharing=new ShamirSecretSharing(p,Zr);
        for(int i=0;i<k_l_list.size();i++){
                if(k_l_list.get(i).equals(k_l)){
                    return k_l_map.get(k_l);
                }
        }
        Map<Integer, BigInteger> k_l_share = shamirSecretSharing.shareSecret(k_l, Rnum, Rthreshold);
        k_l_map.put(k_l,k_l_share);
        k_l_list.add(k_l);
        System.out.println("申请撤销标识符k_l的份额成功!!!");
        return k_l_share;
    }
}


