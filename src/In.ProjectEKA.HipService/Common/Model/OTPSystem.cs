namespace In.ProjectEKA.HipService.Common.Model;

public class OTPSystem
{
    public static readonly OTPSystem AADHAAR = new OTPSystem("aadhaar");
    public static readonly OTPSystem ABDM = new OTPSystem("abdm");

    public string Value { get; }

    private OTPSystem(string value)
    {
        Value = value;
    }

    public override string ToString()
    {
        return Value;
    }
}
