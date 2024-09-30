using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model;

public class Tokens
{
    public string Token { get; }
    public int ExpiresIn { get; }
    public string RefreshToken { get; }
    public int RefreshExpiresIn { get; }

    [JsonConstructor]
    public Tokens(string token, int expiresIn, string refreshToken, int refreshExpiresIn)
    {
        Token = token;
        ExpiresIn = expiresIn;
        RefreshToken = refreshToken;
        RefreshExpiresIn = refreshExpiresIn;
    }
}