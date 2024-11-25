namespace In.ProjectEKA.HipService.Common.Model;

public class ABHAScope
{
    public static readonly ABHAScope ABHA_ENROL = new ABHAScope("abha-enrol");
    public static readonly ABHAScope DL_FLOW = new ABHAScope("dl-flow");
    public static readonly ABHAScope MOBILE_VERIFY = new ABHAScope("mobile-verify");
    public static readonly ABHAScope EMAIL_VERIFY = new ABHAScope("email-verify");
    public static readonly ABHAScope ABHA_LOGIN = new ABHAScope("abha-login");
    public static readonly ABHAScope ABHA_ADDRESS_LOGIN = new ABHAScope("abha-address-login");
    public static readonly ABHAScope AADHAAR_VERIFY = new ABHAScope("aadhaar-verify");

    public string Value { get; private set; }

    private ABHAScope(string value)
    {
        Value = value;
    }

    public override string ToString()
    {
        return Value;
    }
}
