namespace In.ProjectEKA.HipService.Common.Model;

public class ABHALoginHint
{
    public static readonly ABHALoginHint AADHAAR = new ABHALoginHint("aadhaar");
    public static readonly ABHALoginHint MOBILE = new ABHALoginHint("mobile");
    public static readonly ABHALoginHint ABHA_NUMBER = new ABHALoginHint("abha-number");
    public static readonly ABHALoginHint ABHA_Address = new ABHALoginHint("abha-address");

    public string Value { get; private set; }

    private ABHALoginHint(string value)
    {
        Value = value;
    }

    public override string ToString()
    {
        return Value;
    }
}
