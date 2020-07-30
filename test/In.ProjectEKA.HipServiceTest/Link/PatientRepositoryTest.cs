using System.Collections.Generic;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.OpenMrs;
using Moq;
using Xunit;
using OpenMrsPatient = Hl7.Fhir.Model.Patient;
using OpenMrsPatientName = Hl7.Fhir.Model.HumanName;
using OpenMrsGender = Hl7.Fhir.Model.AdministrativeGender;
using FluentAssertions;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipServiceTest.Link
{
    [Collection("Patient Repository Tests")]
    public class PatientRepositoryTest
    {
        private Mock<IPatientDal> patientDal = new Mock<IPatientDal>();

        public PatientRepositoryTest()
        {
            patientDal.Setup(e => e.LoadPatientAsync(It.IsAny<string>()))
                .Returns(Task.FromResult(
                    new OpenMrsPatient() {
                        Name = new List<OpenMrsPatientName>{ new OpenMrsPatientName {Text = "test"} },
                        Gender = OpenMrsGender.Female,
                        BirthDate = "1981"
                    }
                ));
        }

        [Fact]
        private async void PatientRepositoryPatientWith_ReturnHIPPatient()
        {
            var patientId = "someid";
            var repo = new OpenMrsPatientRepository(patientDal.Object);

            var patient = await repo.PatientWithAsync(patientId);

            patientDal.Verify( x => x.LoadPatientAsync(patientId), Times.Once);
            patient.ValueOr(new Patient()).Name.Should().Be("test");
            patient.ValueOr(new Patient()).Gender.Should().Be(Gender.F);
            patient.ValueOr(new Patient()).YearOfBirth.Should().Be(1981);
        }
    }
}