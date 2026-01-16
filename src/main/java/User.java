import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;

public class User {
    private Element usk;
    private Element upk;
    private List<String> attribute;
    private int q;
    private Element r;
    private Element[] o;

    public Element[] getO() {
        return o;
    }
    public void setO(Element[] o) {
        this.o = o;
    }

    public Element getR() {
        return r;
    }
    public void setR(Element r) {
        this.r = r;
    }

    public void setq(int q) {
        this.q = q;
    }
    public int getq() {
        return q;
    }

    public List<String> getAttribute() {
        return attribute;
    }
    public void setAttribute(List<String> attribute) {
        this.attribute = attribute;
    }

    public Element getUpk() {
        return upk;
    }
    public void setUpk(Element upk) {
        this.upk = upk;
    }

    public Element getUsk() {
        return usk;
    }
    public void setUsk(Element usk) {
        this.usk = usk;
    }


}
