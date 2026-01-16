import it.unisa.dia.gas.jpbc.Element;


public class Issuer {
    private Element isk_i;
    private Element[] r_ij;
    private Element ask_i;
    public Element ipk_i;
    public Element[] R_ij;
    public Element[] R_tilde_ij;
    public Element apk_i;

    public Element getAsk_i() {
        return ask_i;
    }
    public void setAsk_i(Element ask_i) {
        this.ask_i = ask_i;
    }

    public Element getApk_i() {
        return apk_i;
    }
    public void setApk_i(Element apk_i) {
        this.apk_i = apk_i;
    }

    public Element getIpk_i() {
        return ipk_i;
    }
    public void setIpk_i(Element ipk_i) {
        this.ipk_i = ipk_i;
    }

    public Element getIsk_i() {
        return isk_i;
    }
    public void setIsk_i(Element isk_i) {
        this.isk_i = isk_i;
    }

    public Element[] getr_ij() {
        return r_ij;
    }
    public void setr_ij(Element[] r_ij) {
        this.r_ij = r_ij;
    }

    public Element[] getR_tilde_ij() {
        return R_tilde_ij;
    }
    public void setR_tilde_ij(Element[] R_tilde_ij) {
        this.R_tilde_ij = R_tilde_ij;
    }

    public Element[] getR_ij() {
        return R_ij;
    }
    public void setR_ij(Element[] R_ij) {
        this.R_ij = R_ij;
    }
}
