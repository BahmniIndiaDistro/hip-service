using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
using In.ProjectEKA.HipService.OpenMrs;
using Moq;
using Xunit;

namespace In.ProjectEKA.HipServiceTest.OpenMrs
{
    [Collection("OpenMrs Care Context Repository Tests")]
    public class OpenMrsCareContextRepositoryTest
    {
        private readonly Mock<IOpenMrsClient> openmrsClientMock;
        private readonly OpenMrsCareContextRepository careContextRepository;

        public OpenMrsCareContextRepositoryTest()
        {
            openmrsClientMock = new Mock<IOpenMrsClient>();
            careContextRepository = new OpenMrsCareContextRepository(openmrsClientMock.Object);
        }

        [Fact]
        public async Task ShouldReturnCombinedListOfCareContexts()
        {
            var path = Endpoints.OpenMrs.OnCareContextPath;
            OpenMrsClientReturnsCareContexts(path, ProgramEnrollmentSampleFull);

            //Given
            Mock<OpenMrsCareContextRepository> careContextRepository =
                new Mock<OpenMrsCareContextRepository>(openmrsClientMock.Object);
            careContextRepository.CallBase = true;

            //When
            var combinedCareContexts =
                (await careContextRepository.Object.GetCareContexts(null)).ToList();

            //Then
            combinedCareContexts.Count().Should().Be(1);
            combinedCareContexts[0].ReferenceNumber.Should().Be("VISIT:1234");
            combinedCareContexts[0].Display.Should().Be("Visit on March 15 2023");
        }

        [Fact]
        public async Task ShouldReturnEmptyListWhenNoCareContextsFound()
        {
            var path = Endpoints.OpenMrs.OnCareContextPath;
            OpenMrsClientReturnsCareContexts(path, EmptySample);

            //Given
            Mock<OpenMrsCareContextRepository> careContextRepository =
                new Mock<OpenMrsCareContextRepository>(openmrsClientMock.Object);
            careContextRepository.CallBase = true;

            //When
            var combinedCareContexts =
                (await careContextRepository.Object.GetCareContexts(null)).ToList();

            //Then
            combinedCareContexts.Count().Should().Be(0);
        }

        private void OpenMrsClientReturnsCareContexts(string path, string response)
        {
            openmrsClientMock
                .Setup(x => x.GetAsync(path))
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(response)
                })
                .Verifiable();
        }

        string ProgramEnrollmentSampleFull = @"[{
            ""careContextType"": ""VISIT_TYPE"",
            ""careContextName"": ""Visit on March 15 2023"",
            ""careContextReference"": ""VISIT:1234"",
            ""hiTypes"": [""Prescription"",""OPConsultation""]}]";


        private const string EmptySample = @"[]
        ";
    }
}