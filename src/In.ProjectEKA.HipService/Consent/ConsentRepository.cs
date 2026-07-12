using System.Linq;

namespace In.ProjectEKA.HipService.Consent
{
    using System.Threading.Tasks;
    using Common.Model;
    using Database;
    using Microsoft.EntityFrameworkCore;
    using Model;

    public class ConsentRepository : IConsentRepository
    {
        private readonly ConsentContext consentContext;

        public ConsentRepository(ConsentContext consentContext)
        {
            this.consentContext = consentContext;
        }

        public async Task AddAsync(Consent consent)
        {
            await consentContext.ConsentArtefact.AddAsync(consent);
            await consentContext.SaveChangesAsync();
        }

        public async Task UpdateAsync(string consentArtefactId, ConsentStatus status)
        {
            var consentArtefact = await consentContext.ConsentArtefact
                .FirstOrDefaultAsync(c => c.ConsentArtefactId == consentArtefactId);
            if (consentArtefact == null)
                return;
            consentArtefact.Status = status;
            await consentContext.SaveChangesAsync();
        }

        public async Task<Consent> GetFor(string consentArtefactId)
        {
            return await consentContext.ConsentArtefact
                .FirstOrDefaultAsync(x => x.ConsentArtefactId == consentArtefactId);
        }

        public async Task DeleteConsentArtefact(string healthId)
        {
            var consents = consentContext.ConsentArtefact.AsEnumerable()
                .Where(b => b.ConsentArtefact.Patient.Id.Equals(healthId))
                .ToList();
            foreach (var consent in consents)
            {
                consentContext.Remove(consent);
            }

            await consentContext.SaveChangesAsync();
        }
    }
}