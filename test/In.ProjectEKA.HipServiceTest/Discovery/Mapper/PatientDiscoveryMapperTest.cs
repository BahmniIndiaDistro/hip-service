using System.Collections.Generic;
using System.Linq;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Discovery.Mapper;
using Xunit;

namespace In.ProjectEKA.HipServiceTest.Discovery.Mapper
{
    public class PatientDiscoveryMapperTest
    {
        [Fact]
        public void ShouldReturnNullWhenPatientEnquiryIsNull()
        {
            var result = PatientDiscoveryMapper.Map(null);
            Assert.Null(result);
        }

        [Fact]
        public void ShouldExcludeCareContextsFromMappingWhenHiTypeIsNotFound()
        {
            var patientEnquiryRepresentation = new PatientEnquiryRepresentation(
                "ref123",
                "display123",
                new List<CareContextRepresentation>
                {
                    new CareContextRepresentation("ref1", "display1","VISIT", null),
                    new CareContextRepresentation("ref2", "display2","VISIT",new List<HiType> ())
                },new List<string>());



            var result = PatientDiscoveryMapper.Map(patientEnquiryRepresentation);

            Assert.NotNull(result);
            Assert.Empty(result);
        }

        [Fact]
        public void ShouldMapCareContextsByHiType()
        {
            var patientEnquiryRepresentation = new PatientEnquiryRepresentation(
                "ref123",
                "display123",
                new List<CareContextRepresentation>
                {
                    new CareContextRepresentation("ref1", "display1","VISIT", new List<HiType> { HiType.Prescription, HiType.DiagnosticReport}),
                    new CareContextRepresentation("ref2", "display2","VISIT",new List<HiType> { HiType.Prescription})
                },new List<string>());
            

            var result = PatientDiscoveryMapper.Map(patientEnquiryRepresentation);

            Assert.NotNull(result);
            Assert.Equal(2, result.Count);
            Assert.Contains(result, r => r.HiType == HiType.Prescription.ToString());
            Assert.Equal(2, result.Find(r => r.HiType == HiType.Prescription.ToString()).Count);
            Assert.Contains(result, r => r.HiType == HiType.DiagnosticReport.ToString());
            Assert.Equal(1, result.Find(r => r.HiType == HiType.DiagnosticReport.ToString()).Count);
        }

        
    }
}