using System;
using System.Collections.Concurrent;

namespace In.ProjectEKA.HipService.Common.Model
{
    /// <summary>
    /// Thread-safe in-memory cache for storing facility name per visit UUID
    /// </summary>
    public class FacilityNameCache
    {
        private readonly ConcurrentDictionary<string, string> _visitUuidToFacilityName = new ConcurrentDictionary<string, string>();

        /// <summary>
        /// Stores facility name for a given visit UUID
        /// </summary>
        public void SetFacilityName(string visitUuid, string facilityName)
        {
            if (string.IsNullOrEmpty(visitUuid))
                throw new ArgumentException("Visit UUID cannot be null or empty", nameof(visitUuid));
            if (string.IsNullOrEmpty(facilityName))
                throw new ArgumentException("Facility name cannot be null or empty", nameof(facilityName));

            _visitUuidToFacilityName.AddOrUpdate(visitUuid, facilityName, (key, oldValue) => facilityName);
        }

        /// <summary>
        /// Gets facility name for a given visit UUID
        /// </summary>
        /// <returns>Facility name if found, null otherwise</returns>
        public string GetFacilityName(string visitUuid)
        {
            if (string.IsNullOrEmpty(visitUuid))
                return null;

            _visitUuidToFacilityName.TryGetValue(visitUuid, out var facilityName);
            return facilityName;
        }

        /// <summary>
        /// Gets facility name for a given visit UUID, or returns default facility name if not found
        /// </summary>
        public string GetFacilityNameOrDefault(string visitUuid, string defaultFacilityName)
        {
            var facilityName = GetFacilityName(visitUuid);
            return facilityName ?? defaultFacilityName;
        }

        /// <summary>
        /// Removes facility name for a given visit UUID
        /// </summary>
        public bool RemoveFacilityName(string visitUuid)
        {
            if (string.IsNullOrEmpty(visitUuid))
                return false;

            return _visitUuidToFacilityName.TryRemove(visitUuid, out _);
        }

        /// <summary>
        /// Clears all cached facility names
        /// </summary>
        public void Clear()
        {
            _visitUuidToFacilityName.Clear();
        }

        /// <summary>
        /// Gets the count of cached entries
        /// </summary>
        public int Count => _visitUuidToFacilityName.Count;
    }
}
