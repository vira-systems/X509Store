namespace Vira.X509Store.Pkcs11;

// Public numeric codes for mapped PKCS#11 conditions
public static class Pkcs11ErrorCodes
{
    public const int Unknown = 0;
    public const int UserTypeInvalid = 1001;
    public const int PinIncorrect = 1002;
    public const int PinLocked = 1003;
    public const int UserAlreadyLoggedIn = 1004;
    public const int UserNotLoggedIn = 1005;
    public const int UserPinNotInitialized = 1006;
    public const int DeviceError = 1007;
}