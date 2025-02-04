namespace In.ProjectEKA.HipService.Link.Model;

public class GenerateLinkTokenRequest
{
    public string AbhaAddress { get; }
    public string Name { get; }
    public string Gender { get; }
    public string YearOfBirth { get; }

    public GenerateLinkTokenRequest(string abhaAddress, string name, string gender, string yearOfBirth)
    {
        AbhaAddress = abhaAddress;
        Name = name;
        Gender = gender;
        YearOfBirth = yearOfBirth;
    }
}