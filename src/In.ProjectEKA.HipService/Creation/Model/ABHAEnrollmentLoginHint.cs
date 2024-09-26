namespace In.ProjectEKA.HipService.Creation.Model;

public class ABHAEnrollmentLoginHint
{
    public static readonly ABHAEnrollmentLoginHint AADHAAR = new ABHAEnrollmentLoginHint("aadhaar");
    public static readonly ABHAEnrollmentLoginHint MOBILE = new ABHAEnrollmentLoginHint("mobile");

    public string Value { get; private set; }

    private ABHAEnrollmentLoginHint(string value)
    {
        Value = value;
    }

    public override string ToString()
    {
        return Value;
    }
}
