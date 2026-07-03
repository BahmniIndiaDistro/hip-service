using System;
using System.Collections.Concurrent;

namespace In.ProjectEKA.HipService.Common.Model
{
    /// <summary>
    /// Thread-safe in-memory cache for storing HFR ID per visit UUID
    /// </summary>
    public class HfrIdCache
    {
        private readonly ConcurrentDictionary<string, string> _visitUuidToHfrId = new ConcurrentDictionary<string, string>();

        /// <summary>
        /// Stores HFR ID for a given visit UUID
        /// </summary>
        public void SetHfrId(string visitUuid, string hfrId)
        {
            if (string.IsNullOrEmpty(visitUuid))
                throw new ArgumentException("Visit UUID cannot be null or empty", nameof(visitUuid));
            if (string.IsNullOrEmpty(hfrId))
                throw new ArgumentException("HFR ID cannot be null or empty", nameof(hfrId));

            _visitUuidToHfrId.AddOrUpdate(visitUuid, hfrId, (key, oldValue) => hfrId);
        }

        /// <summary>
        /// Gets HFR ID for a given visit UUID
        /// </summary>
        /// <returns>HFR ID if found, null otherwise</returns>
        public string GetHfrId(string visitUuid)
        {
            if (string.IsNullOrEmpty(visitUuid))
                return null;

            _visitUuidToHfrId.TryGetValue(visitUuid, out var hfrId);
            return hfrId;
        }

        /// <summary>
        /// Gets HFR ID for a given visit UUID, or returns default HFR ID if not found
        /// </summary>
        public string GetHfrIdOrDefault(string visitUuid, string defaultHfrId)
        {
            var hfrId = GetHfrId(visitUuid);
            return hfrId ?? defaultHfrId;
        }

        /// <summary>
        /// Removes HFR ID for a given visit UUID
        /// </summary>
        public bool RemoveHfrId(string visitUuid)
        {
            if (string.IsNullOrEmpty(visitUuid))
                return false;

            return _visitUuidToHfrId.TryRemove(visitUuid, out _);
        }

        /// <summary>
        /// Clears all cached HFR IDs
        /// </summary>
        public void Clear()
        {
            _visitUuidToHfrId.Clear();
        }

        /// <summary>
        /// Gets the count of cached entries
        /// </summary>
        public int Count => _visitUuidToHfrId.Count;
    }
}
