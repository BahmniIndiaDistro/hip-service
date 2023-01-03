using System.Threading.Tasks;
using In.ProjectEKA.HipService.Creation.Model;

namespace In.ProjectEKA.HipService.Creation
{
    public interface ICreationService
    {
        public Task<string> EncryptText(string text);
        public AadhaarOTPGenerationResponse AadhaarOTPGenerationResponse(string response);

        public string getTransactionId();
    }
}