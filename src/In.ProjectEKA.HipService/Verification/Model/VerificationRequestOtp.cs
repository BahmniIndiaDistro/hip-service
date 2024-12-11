using System;

namespace In.ProjectEKA.HipService.Verification.Model;

public class VerificationRequestOtp
{
    public string Identifier { get; }
    
    public IdentifierType IdentifierType { get; }
    public AuthMode? AuthMethod { get; }

    public VerificationRequestOtp(string identifier, IdentifierType identifierType, AuthMode authMethod)
    {
        Identifier = identifier;
        IdentifierType = identifierType;
        AuthMethod = authMethod;
    }
}