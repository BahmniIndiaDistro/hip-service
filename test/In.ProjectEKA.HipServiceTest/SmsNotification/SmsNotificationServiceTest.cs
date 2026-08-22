using FluentAssertions;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.OpenMrs;
using In.ProjectEKA.HipService.SmsNotification;
using In.ProjectEKA.HipService.SmsNotification.Model;
using In.ProjectEKA.HipService.UserAuth;
using Moq;
using Xunit;

namespace In.ProjectEKA.HipServiceTest.SmsNotification
{
    public class SmsNotificationServiceTest
    {
        public SmsNotificationServiceTest()
        {
            UserAuthMap.HealthIdToPhoneNumber.Clear();
            UserAuthMap.HealthIdToLatestVisitUuid.Clear();
        }

        [Fact]
        public void SmsNotifyRequest_should_use_latest_healthId_for_phone_to_resolve_visit_facility()
        {
            var healthId = "patient@sbx";
            var visitUuid = "visit-uuid-123";
            var phoneNo = "+919876543210";

            UserAuthMap.UpdateHealthIdToPhoneNumber(phoneNo, healthId);
            UserAuthMap.HealthIdToLatestVisitUuid[healthId] = visitUuid;

            var openMrsClient = new Mock<IOpenMrsClient>();
            var bahmniConfiguration = new BahmniConfiguration(openMrsClient.Object)
            {
                Id = "HIP_ID_123",
                Name = "HIP_NAME"
            };
            var smsNotificationService = new SmsNotificationService();

            var result = smsNotificationService.SmsNotifyRequest(
                new SmsNotifyRequest(phoneNo),
                bahmniConfiguration);

            result.Item1.Should().NotBeNull();
            result.Item2.Should().BeNull();
            result.Item1.notification.phoneNo.Should().Be(phoneNo);
        }
    }
}
