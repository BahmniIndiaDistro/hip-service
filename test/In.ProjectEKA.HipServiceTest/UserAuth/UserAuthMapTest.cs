using System;
using FluentAssertions;
using In.ProjectEKA.HipService.UserAuth;
using Xunit;

namespace In.ProjectEKA.HipServiceTest.UserAuth
{
    public class UserAuthMapTest
    {
        public UserAuthMapTest()
        {
            UserAuthMap.HealthIdToPhoneNumber.Clear();
            UserAuthMap.HealthIdToLatestVisitUuid.Clear();
        }

        [Theory]
        [InlineData("+919876543210", "9876543210")]
        [InlineData("919876543210", "9876543210")]
        [InlineData("9876543210", "9876543210")]
        public void NormalizePhoneNumber_should_strip_country_code(string input, string expected)
        {
            UserAuthMap.NormalizePhoneNumber(input).Should().Be(expected);
        }

        [Fact]
        public void UpdateHealthIdToPhoneNumber_should_store_composite_phone_entry()
        {
            UserAuthMap.UpdateHealthIdToPhoneNumber("+919876543210", "patient@sbx");

            UserAuthMap.HealthIdToPhoneNumber.Should().ContainKey("patient@sbx");
            var entry = UserAuthMap.HealthIdToPhoneNumber["patient@sbx"][0];
            entry.Should().Contain(UserAuthMap.PhoneTimestampSeparator);
            UserAuthMap.ExtractPhoneNumber(entry).Should().Be("9876543210");
            UserAuthMap.ExtractTimestamp(entry).Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        }

        [Fact]
        public void UpdateHealthIdToPhoneNumber_should_append_multiple_entries_for_same_healthId()
        {
            UserAuthMap.UpdateHealthIdToPhoneNumber("9876543210", "patient@sbx");
            UserAuthMap.UpdateHealthIdToPhoneNumber("9123456789", "patient@sbx");

            UserAuthMap.HealthIdToPhoneNumber["patient@sbx"].Should().HaveCount(2);
        }

        [Fact]
        public void GetLatestPhoneNumber_should_return_most_recently_updated_phone()
        {
            var olderTimestamp = DateTime.UtcNow.AddHours(-1).ToString("O");
            var newerTimestamp = DateTime.UtcNow.ToString("O");

            UserAuthMap.HealthIdToPhoneNumber["patient@sbx"] = new System.Collections.Generic.List<string>
            {
                $"9876543210{UserAuthMap.PhoneTimestampSeparator}{olderTimestamp}",
                $"9123456789{UserAuthMap.PhoneTimestampSeparator}{newerTimestamp}"
            };

            UserAuthMap.GetLatestPhoneNumber("patient@sbx").Should().Be("9123456789");
        }

        [Fact]
        public void GetHealthIdByPhoneNumber_should_return_matching_healthId()
        {
            UserAuthMap.HealthIdToPhoneNumber["patient@sbx"] = new System.Collections.Generic.List<string>
            {
                $"9876543210{UserAuthMap.PhoneTimestampSeparator}{DateTime.UtcNow:O}"
            };

            UserAuthMap.GetHealthIdByPhoneNumber("+919876543210").Should().Be("patient@sbx");
        }

        [Fact]
        public void GetHealthIdByPhoneNumber_should_return_latest_healthId_when_phone_is_mapped_to_multiple()
        {
            var olderTimestamp = DateTime.UtcNow.AddHours(-1).ToString("O");
            var newerTimestamp = DateTime.UtcNow.ToString("O");

            UserAuthMap.HealthIdToPhoneNumber["old-patient@sbx"] = new System.Collections.Generic.List<string>
            {
                $"9876543210{UserAuthMap.PhoneTimestampSeparator}{olderTimestamp}"
            };
            UserAuthMap.HealthIdToPhoneNumber["new-patient@sbx"] = new System.Collections.Generic.List<string>
            {
                $"9876543210{UserAuthMap.PhoneTimestampSeparator}{newerTimestamp}"
            };

            UserAuthMap.GetHealthIdByPhoneNumber("9876543210").Should().Be("new-patient@sbx");
        }

        [Fact]
        public void GetHealthIdByPhoneNumber_should_return_null_when_phone_is_not_mapped()
        {
            UserAuthMap.GetHealthIdByPhoneNumber("9999999999").Should().BeNull();
        }
    }
}
