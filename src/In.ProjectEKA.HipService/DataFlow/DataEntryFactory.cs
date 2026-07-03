namespace In.ProjectEKA.HipService.DataFlow
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;

    using System.Text;
    using Common;
    using Encryptor;
    using HipLibrary.Patient.Model;
    using Hl7.Fhir.Serialization;
    using In.ProjectEKA.HipService.Logger;

    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Options;
    using Model;
    using Optional;

    public class DataEntryFactory
    {
        private const int MbInBytes = 1000000;
        private static readonly FhirJsonSerializer Serializer = new FhirJsonSerializer();
        private static readonly string FhirMediaType = "application/fhir+json";
        private readonly IOptions<DataFlowConfiguration> dataFlowConfiguration;
        private readonly IEncryptor encryptor;
        private readonly IOptions<HipConfiguration> hipConfiguration;
        private readonly IServiceScopeFactory serviceScopeFactory;

        public DataEntryFactory()
        {
        }

        public DataEntryFactory(
            IServiceScopeFactory serviceScopeFactory,
            IOptions<DataFlowConfiguration> dataFlowConfiguration,
            IOptions<HipConfiguration> hipConfiguration,
            IEncryptor encryptor)
        {
            this.serviceScopeFactory = serviceScopeFactory;
            this.dataFlowConfiguration = dataFlowConfiguration;
            this.hipConfiguration = hipConfiguration;
            this.encryptor = encryptor;
        }

        public virtual Option<EncryptedEntries> Process(Entries entries,
            HipLibrary.Patient.Model.KeyMaterial dataRequestKeyMaterial, string transactionId)
        {
            var keyPair = EncryptorHelper.GenerateKeyPair(dataRequestKeyMaterial.Curve,
                dataRequestKeyMaterial.CryptoAlg);
            var randomKey = EncryptorHelper.GenerateRandomKey();
            // Log.Information($"DhPublicKey randomKey details: {randomKey}");

            var processedEntries = new List<Entry>();
            var careBundles = entries.CareBundles;
            foreach (var careBundle in careBundles)
            {
                var contentBundle = careBundle.BundleForThisCcr;
                string checksum = "";
                if (contentBundle != null)
                {
                    checksum = "iplit-md5";
                }
                var encryptData =
                    encryptor.EncryptData(dataRequestKeyMaterial,
                        keyPair,
                        contentBundle, randomKey);
                if (!encryptData.HasValue)
                    return Option.None<EncryptedEntries>();

                encryptData.MatchSome(content =>
                {
                    var entry = IsLinkable(content)
                        ? StoreComponentAndGetLink(ComponentEntry(content, careBundle.CareContextReference, checksum),
                            careBundle.CareContextReference, checksum)
                        : ComponentEntry(content, careBundle.CareContextReference, checksum);
                    processedEntries.Add(entry);
                });
            }

            var keyStructure = new KeyStructure(dataRequestKeyMaterial.DhPublicKey.Expiry,
                dataRequestKeyMaterial.DhPublicKey.Parameters, EncryptorHelper.GetPublicKey(keyPair));
            var keyMaterial = new KeyMaterial(dataRequestKeyMaterial.CryptoAlg,
                dataRequestKeyMaterial.Curve,
                keyStructure, randomKey);
            return Option.Some(new EncryptedEntries(processedEntries.AsEnumerable(), keyMaterial));
        }
 
        private Entry StoreComponentAndGetLink(Entry componentEntry, string careContextReference, string checksum)
        {
            var linkId = Guid.NewGuid().ToString();
            var token = Guid.NewGuid().ToString();
            var linkEntry = LinkEntry(linkId, token, careContextReference, checksum);
            StoreComponentEntry(linkId, componentEntry, token);
            return linkEntry;
        }

        private Entry EntryWith(string content, string link, string careContextReference, string checksum)
        {
            return new Entry(content??link, FhirMediaType, checksum, careContextReference);
        }

        private Entry LinkEntry(string linkId, string token, string careContextReference, string checksum)
        {
            var link = $"{hipConfiguration.Value.Url}/health-information/{linkId}?token={token}";
            return EntryWith(null, link, careContextReference, checksum);
        }

        private Entry ComponentEntry(string serializedBundle, string careContextReference, string checksum)
        {
            return EntryWith(serializedBundle, null, careContextReference, checksum);
        }

        private bool IsLinkable(string serializedBundle)
        {
            var byteCount = Encoding.Unicode.GetByteCount(serializedBundle);
            return byteCount >= DataSizeLimitInBytes();
        }

        private int DataSizeLimitInBytes()
        {
            return dataFlowConfiguration.Value.DataSizeLimitInMbs * MbInBytes;
        }

        private void StoreComponentEntry(string linkId, Entry entry, string token)
        {
            using var serviceScope = serviceScopeFactory.CreateScope();
            var healthInformationRepository = serviceScope.ServiceProvider.GetService<IHealthInformationRepository>();
            healthInformationRepository.Add(new HealthInformation(linkId, entry, DateTime.Now.ToUniversalTime(), token));
        }
    }
}
