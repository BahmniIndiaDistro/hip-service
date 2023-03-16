using System.Net;
using System.Net.Http;
using In.ProjectEKA.HipService.DataFlow;
using In.ProjectEKA.HipService.OpenMrs;
using Moq;

namespace In.ProjectEKA.HipServiceTest.DataFlow
{
    using FluentAssertions;
    using Xunit;

    [Collection("Collect Tests")]
    public class OpenMrsPatientDataTest
    {
        private static readonly Mock<IOpenMrsClient> OpenMrsClientMock = new Mock<IOpenMrsClient>();

        private readonly OpenMrsPatientData openMrsPatientData =
            new OpenMrsPatientData(OpenMrsClientMock.Object);


        [Fact]
        private void ShouldReturnDataForPrescriptionForVisit()
        {
            var patientUuid = "12";
            var careContextReference = "VISIT:1234";
            var fromDate = "2020-01-01";
            var toDate = "2020-12-12";
            var hiType = "prescription";
            var pathForPrescription =
                "ws/rest/v1/hip/prescriptions/visit/?patientId=12&visitUuid=1234&fromDate=2020-01-01&toDate=2020-12-13";

            OpenMrsClientMock
                .Setup(x => x.GetAsync(pathForPrescription))
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(
                        "{\"prescriptions\": [{\"careContext\":{},\"bundle\":{\"resourceType\": \"Bundle\"}}]}")
                })
                .Verifiable();
            var response = openMrsPatientData.GetPatientData(patientUuid, careContextReference, toDate, fromDate, hiType);
            response.Result.Should().BeEquivalentTo("{\"resourceType\": \"Bundle\"}");
        }

        [Fact]
        private void ShouldReturnDataForPrescriptionForProgram()
        {
            var patientUuid = "12";
            var grantedContext = "HIV Program(ID Number:45)";
            var fromDate = "2020-01-01";
            var toDate = "2020-12-12";
            var hiType = "prescription";
            var pathForPrescription =
                "ws/rest/v1/hip/prescriptions/program/?patientId=12&programName=HIV+Program&" +
                "programEnrollmentId=45&fromDate=2020-01-01&toDate=2020-12-12";

            OpenMrsClientMock
                .Setup(x => x.GetAsync(pathForPrescription))
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(
                        "{\"prescriptions\": [{\"careContext\":{},\"bundle\":{\"resourceType\": \"Bundle\"}}]}")
                })
                .Verifiable();
            var response = openMrsPatientData.GetPatientData(patientUuid, grantedContext, toDate, fromDate, hiType);
            response.Result.Should().BeEquivalentTo("{\"resourceType\": \"Bundle\"}");
        }

        [Fact]
        private void ShouldReturnDataForDiagnosticReportForVisit()
        {
            var patientUuid = "12";
            var careContextReference = "VISIT:1234";
            var fromDate = "2020-01-01";
            var toDate = "2020-12-12";
            var hiType = "diagnosticreport";
            var pathForPrescription =
                "ws/rest/v1/hip/diagnosticReports/visit/?patientId=12&visitUuid=1234&fromDate=2020-01-01&toDate=2020-12-13";

            OpenMrsClientMock
                .Setup(x => x.GetAsync(pathForPrescription))
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(
                        "{\"diagnosticReports\": [{\"careContext\":{},\"bundle\":{\"resourceType\": \"Bundle\"}}]}")
                })
                .Verifiable();
            var response = openMrsPatientData.GetPatientData(patientUuid, careContextReference, toDate, fromDate, hiType);
            response.Result.Should().BeEquivalentTo("{\"resourceType\": \"Bundle\"}");
        }

        [Fact]
        private void ShouldReturnDataForDiagnosticReportForProgram()
        {
            var patientUuid = "12";
            var grantedContext = "HIV Program(ID Number:45)";
            var fromDate = "2020-01-01";
            var toDate = "2020-12-12";
            var hiType = "diagnosticreport";
            var pathForPrescription =
                "ws/rest/v1/hip/diagnosticReports/program/?patientId=12&programName=HIV+Program&" +
                "programEnrollmentId=45&fromDate=2020-01-01&toDate=2020-12-12";

            OpenMrsClientMock
                .Setup(x => x.GetAsync(pathForPrescription))
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(
                        "{\"diagnosticReports\": [{\"careContext\":{},\"bundle\":{\"resourceType\": \"Bundle\"}}]}")
                })
                .Verifiable();
            var response = openMrsPatientData.GetPatientData(patientUuid, grantedContext, toDate, fromDate, hiType);
            response.Result.Should().BeEquivalentTo("{\"resourceType\": \"Bundle\"}");
        }
    }
}