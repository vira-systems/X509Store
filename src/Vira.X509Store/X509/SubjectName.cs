namespace Vira.X509Store.X509;

internal class SubjectName
{
    public string Name { get; set; } = null!;

    public string Value { get; set; } = null!;

    public int Order => (int)Enum.Parse<SubjectDns>(Name, true);
}
