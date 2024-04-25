using System.Net.Http;
using System.Threading.Tasks;

namespace In.ProjectEKA.HipService.OpenMrs
{
    public interface IOpenMrsClient
    {
        Task<HttpResponseMessage> GetAsync(string openMrsUrl);

        Task<HttpResponseMessage> PostAsync(string openMrsUrl, string jsonContent);
    }
}