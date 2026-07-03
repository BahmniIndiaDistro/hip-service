using System;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.Logger;
using In.ProjectEKA.HipService.OpenMrs;
using Newtonsoft.Json.Linq;

namespace In.ProjectEKA.HipService.Common.Model
{
    public class BahmniConfiguration
    {
        private readonly HfrIdCache _hfrIdCache;
        private readonly FacilityNameCache _facilityNameCache;
        private readonly IOpenMrsClient _openMrsClient;

        public BahmniConfiguration(IOpenMrsClient openMrsClient)
        {
            _openMrsClient = openMrsClient;
            _hfrIdCache = new HfrIdCache();
            _facilityNameCache = new FacilityNameCache();
        }

        public string Id { get; set; }

        public string Name { get; set; }

        /// <summary>
        /// Gets HFR ID for a specific visit UUID from cache
        /// </summary>
        /// <param name="visitUuid">Visit UUID</param>
        /// <returns>HFR ID for the visit, or default Id if not found</returns>
        public string GetHfrIdByVisitUuid(string visitUuid)
        {
            if (string.IsNullOrEmpty(visitUuid))
                return Id;

            return _hfrIdCache.GetHfrId(visitUuid);
        }

        public string GetDefaultHfrId()
        {
            return Id;
        }

        /// <summary>
        /// Sets HFR ID for a specific visit UUID in cache
        /// </summary>
        /// <param name="visitUuid">Visit UUID</param>
        /// <param name="hfrId">HFR ID to store</param>
        public void SetHfrIdForVisit(string visitUuid, string hfrId)
        {
            _hfrIdCache.SetHfrId(visitUuid, hfrId);
        }

        /// <summary>
        /// Gets facility name for a specific visit UUID from cache
        /// </summary>
        /// <param name="visitUuid">Visit UUID</param>
        /// <returns>Facility name for the visit, or default Name if not found</returns>
        public string GetFacilityNameByVisitUuid(string visitUuid)
        {
            if (string.IsNullOrEmpty(visitUuid))
                return Name;

            return _facilityNameCache.GetFacilityName(visitUuid);
        }

        public string GetDefaultFacilityName()
        {
                return Name;
        }

        /// <summary>
        /// Sets facility name for a specific visit UUID in cache
        /// </summary>
        /// <param name="visitUuid">Visit UUID</param>
        /// <param name="facilityName">Facility name to store</param>
        public void SetFacilityNameForVisit(string visitUuid, string facilityName)
        {
            if (!string.IsNullOrEmpty(facilityName))
            {
                _facilityNameCache.SetFacilityName(visitUuid, facilityName);
            }
        }

        /// <summary>
        /// Gets the HFR ID cache instance
        /// </summary>
        public HfrIdCache HfrIdCache => _hfrIdCache;

        /// <summary>
        /// Gets the facility name cache instance
        /// </summary>
        public FacilityNameCache FacilityNameCache => _facilityNameCache;

        /// <summary>
        /// Extracts visit UUID from care context reference number.
        /// Care context reference format is typically "patientId:visitUuid".
        /// </summary>
        public string ExtractVisitUuidFromReference(string careContextReference)
        {
            if (string.IsNullOrEmpty(careContextReference))
                return null;

            var parts = careContextReference.Split(':');
            if (parts.Length >= 2)
            {
                return parts[1];
            }
            return careContextReference;
        }

        public async Task<string> SetHfrIdForVisitAsync(string visitUuid)
        {
            try
            {
                if (string.IsNullOrEmpty(visitUuid))
                {
                    Log.Error("SetHfrIdForVisitAsync: visitUuid is null or empty");
                    return null;
                }
                Log.Information($"SetHfrIdForVisitAsync: Retrieving HFR ID for visit UUID: {visitUuid}");
                var visitPath = $"ws/rest/v1/visit/{visitUuid}";
                var visitResponse = await _openMrsClient.GetAsync(visitPath);
                if (visitResponse == null || !visitResponse.IsSuccessStatusCode)
                {
                    Log.Error($"SetHfrIdForVisitAsync: Failed to retrieve visit {visitUuid} from OpenMRS. Status: {visitResponse?.StatusCode}");
                    return null;
                }
                var visitContent = await visitResponse.Content.ReadAsStringAsync();
                var visitJson = JObject.Parse(visitContent);
                var locationRef = visitJson["location"]?["uuid"]?.ToString();
                if (string.IsNullOrEmpty(locationRef))
                {
                    Log.Error($"SetHfrIdForVisitAsync: Visit {visitUuid} does not have a location");
                    return null;
                }
                Log.Information($"SetHfrIdForVisitAsync: Visit location UUID: {locationRef}");
                var locationPath = $"ws/rest/v1/location/{locationRef}?v=full";
                var locationResponse = await _openMrsClient.GetAsync(locationPath);
                if (locationResponse == null || !locationResponse.IsSuccessStatusCode)
                {
                    Log.Error($"SetHfrIdForVisitAsync: Failed to retrieve location {locationRef} from OpenMRS. Status: {locationResponse?.StatusCode}");
                    return null;
                }
                var locationContent = await locationResponse.Content.ReadAsStringAsync();
                var locationJson = JObject.Parse(locationContent);
                string hfrId = null;
                string facilityName = null;
                var attributes = locationJson["attributes"] as JArray;
                if (attributes != null)
                {
                    foreach (var attribute in attributes)
                    {
                        var attributeType = attribute["attributeType"]?["display"]?.ToString() ??
                                          attribute["attributeType"]?["name"]?.ToString();
                        if (attributeType != null)
                        {
                            if (attributeType.Equals("ABDM HFR ID", StringComparison.OrdinalIgnoreCase) ||
                                 attributeType.Contains("HFR ID", StringComparison.OrdinalIgnoreCase))
                            {
                                hfrId = attribute["value"]?.ToString();
                                if (!string.IsNullOrEmpty(hfrId))
                                {
                                    Log.Information($"SetHfrIdForVisitAsync: Found HFR ID: {hfrId} for location {locationRef}");
                                }
                            }
                            if (attributeType.Equals("ABDM HFR Name", StringComparison.OrdinalIgnoreCase) ||
                                attributeType.Contains("HFR Name", StringComparison.OrdinalIgnoreCase))
                            {
                                facilityName = attribute["value"]?.ToString();
                                if (!string.IsNullOrEmpty(facilityName))
                                {
                                    Log.Information($"SetHfrIdForVisitAsync: Found ABDM HFR Name: {facilityName} for location {locationRef}");
                                }
                            }
                        }
                    }
                }
                if (string.IsNullOrEmpty(hfrId))
                {
                    Log.Information($"SetHfrIdForVisitAsync: WARNING - HFR ID not found in location {locationRef} attributes");
                    return null;
                }
                SetHfrIdForVisit(visitUuid, hfrId);
                Log.Information($"SetHfrIdForVisitAsync: Successfully stored HFR ID {hfrId} for visit UUID {visitUuid}");

                SetFacilityNameForVisit(visitUuid, facilityName);
                Log.Information($"SetHfrIdForVisitAsync: Successfully stored facility name {facilityName} for visit UUID {visitUuid}");
                return hfrId;
            }
            catch (Exception ex)
            {
                Log.Error(ex, $"SetHfrIdForVisitAsync: Error processing request: {ex.Message}");
                return null;
            }
        }
    }
}
