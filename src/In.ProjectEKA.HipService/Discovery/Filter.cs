using System.Collections.Immutable;
using In.ProjectEKA.HipService.Logger;

namespace In.ProjectEKA.HipService.Discovery
{
    using System.Collections.Generic;
    using System.Linq;
    using HipLibrary.Patient.Model;
    using Ranker;
    using static Ranker.RankBuilder;
    using static Matcher.DemographicMatcher;

    public static class Filter
    {
        private static readonly Dictionary<IdentifierType, IdentifierTypeExt> IdentifierTypeExtensions =
            new Dictionary<IdentifierType, IdentifierTypeExt>
            {
                {IdentifierType.MOBILE, IdentifierTypeExt.Mobile},
                {IdentifierType.MR, IdentifierTypeExt.Mr},
                {IdentifierType.ABHA_NUMBER, IdentifierTypeExt.NdhmHealthNumber},
                {IdentifierType.abhaAddress, IdentifierTypeExt.HealthId}
            };

        private static PatientWithRank<Patient> RankPatient(Patient patient, DiscoveryRequest request)
        {
            return RanksFor(request, patient).Aggregate((rank, withRank) => rank + withRank);
        }

        private static IEnumerable<PatientWithRank<Patient>> RanksFor(DiscoveryRequest request, Patient patient)
        {
            static IRanker<Patient> GetValueOrDefault(IdentifierTypeExt type)
            {
                return Ranks?.GetValueOrDefault(type, new EmptyRanker()) ?? new EmptyRanker();
            }

            return From(request)
                .Select(identifier => GetValueOrDefault(identifier.Type).Rank(patient, identifier.Value));
        }

        private static IEnumerable<IdentifierExt> From(DiscoveryRequest request)
        {
            static IdentifierExt ToExtension(Identifier identifier)
            {
                return new IdentifierExt(
                    IdentifierTypeExtensions.GetValueOrDefault(identifier.Type, IdentifierTypeExt.Empty),
                    identifier.Value);
            }

            var verifiedIdentifiers = request.Patient.VerifiedIdentifiers ?? new List<Identifier>();
            var unVerifiedIdentifiers = request.Patient.UnverifiedIdentifiers ?? new List<Identifier>();
            return verifiedIdentifiers
                .Select(ToExtension)
                .Concat(unVerifiedIdentifiers.Select(ToExtension))
                .Append(new IdentifierExt(IdentifierTypeExt.Name, request.Patient.Name))
                .Append(new IdentifierExt(IdentifierTypeExt.Gender, request.Patient.Gender.ToString()));
        }

        public static IEnumerable<PatientEnquiryRepresentation> DemographicRecords(IEnumerable<Patient> patients, DiscoveryRequest request)
        {
            var temp = patients
                .AsEnumerable()
                .Where(ExpressionFor(request.Patient.Name, request.Patient.YearOfBirth, request.Patient.Gender))
                .Select(patientInfo => RankPatient(patientInfo, request))
                .GroupBy(rankedPatient => rankedPatient.Rank.Score)
                .OrderByDescending(rankedPatient => rankedPatient.Key)
                .Take(1)
                .SelectMany(group => group.Select(rankedPatient =>
                {
                    var careContexts = rankedPatient.Patient.CareContexts ?? new List<CareContextRepresentation>();

                    var careContextRepresentations = careContexts
                        .Select(program =>
                            new CareContextRepresentation(
                                program.ReferenceNumber,
                                program.Display,
                                program.Type,
                                program.HiTypes))
                        .ToList();

                    Log.Information("rankedPatient.Patient.Identifier ~~~~~~~~~~~~~~~~~~~~> " + rankedPatient.Patient.Identifier);
                    Log.Information("rankedPatient.Patient.Name ~~~~~~~~~~~~~~~~~~~~> " + rankedPatient.Patient.Name);
                    Log.Information("careContextRepresentations ~~~~~~~~~~~~~~~~~~~~> " + careContextRepresentations);
                    Log.Information("careContextRepresentations.Count ~~~~~~~~~~~~~~~~~~~~> " + careContextRepresentations.Count);
                    Log.Information("rankedPatient.Meta.Select(meta => meta.Field)) ~~~~~~~~~~~~~~~~~~~~> " + rankedPatient.Meta.Select(meta => meta.Field));
                    // Log.Information("rankedPatient.Meta ~~~~~~~~~~~~~~~~~~~~> " + rankedPatient.Meta.GetEnumerator());

                    return new PatientEnquiryRepresentation(
                        rankedPatient.Patient.Identifier,
                        $"{rankedPatient.Patient.Name}",
                        careContextRepresentations,
                        rankedPatient.Meta.Select(meta => meta.Field));
                }));
            return temp;
        }

        public static IEnumerable<PatientEnquiryRepresentation> HealthIdRecords(IEnumerable<Patient> patients,
            DiscoveryRequest request)
        {
            var patient = patients.First();
            var careContexts = patient.CareContexts ?? new List<CareContextRepresentation>();
            var careContextRepresentations = careContexts
                .Select(program =>
                    new CareContextRepresentation(
                        program.ReferenceNumber,
                        program.Display,
                        program.Type,
                        program.HiTypes)).ToList();
            Log.Information("rankedPatient.Patient.Identifier ~~~~~~~~~~~~~~~~~~~~> " + patient.Identifier);
            Log.Information("rankedPatient.Patient.Name ~~~~~~~~~~~~~~~~~~~~> " + patient.Name);
            Log.Information("careContextRepresentations ~~~~~~~~~~~~~~~~~~~~> " + careContextRepresentations);
            Log.Information("careContextRepresentations.Count ~~~~~~~~~~~~~~~~~~~~> " + careContextRepresentations.Count);
            var enumerable = new [] {
                new PatientEnquiryRepresentation(
                    patient.Identifier,
                    request.Patient.Name,
                    careContextRepresentations,
                    Enumerable.Empty<string>()
                ) };
            return enumerable;
        }

        internal enum IdentifierTypeExt
        {
            Mobile,
            Name,
            Mr,
            Gender,
            Empty,
            NdhmHealthNumber,
            HealthId
        }

        private class IdentifierExt
        {
            public IdentifierExt(IdentifierTypeExt type, string value)
            {
                Type = type;
                Value = value;
            }

            public IdentifierTypeExt Type { get; }
            public string Value { get; }
        }
    }
}