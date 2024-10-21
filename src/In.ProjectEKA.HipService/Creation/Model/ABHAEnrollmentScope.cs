namespace In.ProjectEKA.HipService.Creation.Model;

public class ABHAEnrollmentScope
{
    public static readonly ABHAEnrollmentScope ABHA_ENROL = new ABHAEnrollmentScope("abha-enrol");
    public static readonly ABHAEnrollmentScope DL_FLOW = new ABHAEnrollmentScope("dl-flow");
    public static readonly ABHAEnrollmentScope MOBILE_VERIFY = new ABHAEnrollmentScope("mobile-verify");
    public static readonly ABHAEnrollmentScope EMAIL_VERIFY = new ABHAEnrollmentScope("email-verify");

    public string Value { get; private set; }

    private ABHAEnrollmentScope(string value)
    {
        Value = value;
    }

    public override string ToString()
    {
        return Value;
    }
}
