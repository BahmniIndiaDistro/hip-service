namespace In.ProjectEKA.HipLibrary.Patient.Model
{
    using Hl7.Fhir.Model;

    public class CareBundle
    {
        public CareBundle(string careContextReference, string bundleForThisCcr)
        {
            CareContextReference = careContextReference;
            BundleForThisCcr = bundleForThisCcr;
        }

        public string CareContextReference { get; }

        public string BundleForThisCcr { get; }
    }
}