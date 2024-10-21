namespace In.ProjectEKA.HipService.Creation.Model;

public class ABHAAuthMethods
{
    public static readonly ABHAAuthMethods OTP = new ABHAAuthMethods("otp");

    public string Value { get; }

    private ABHAAuthMethods(string value)
    {
        Value = value;
    }

    public override string ToString()
    {
        return Value;
    }
}
