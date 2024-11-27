using System;
using System.ComponentModel.DataAnnotations;


namespace In.ProjectEKA.HipService.Patient.Model
{
    public class ShareProfileRequest
    {
        public string Intent { get; }

        public ShareProfileMetadata Metadata { get; }
        [Required] public Profile Profile { get; }

        public ShareProfileRequest(string intent, ShareProfileMetadata metadata, Profile profile)
        {
            Intent = intent;
            Metadata = metadata;
            Profile = profile;
        }
    }

    public class ShareProfileMetadata
    {
        public string HipId { get; }
        public string Context { get; }
        public string HprId { get; }
        public string Latitude { get; }
        public string Longitude { get; }

        public ShareProfileMetadata(string hipId, string context, string hprId, string latitude, string longitude)
        {
            HipId = hipId;
            Context = context;
            HprId = hprId;
            Latitude = latitude;
            Longitude = longitude;
        }
    }
}