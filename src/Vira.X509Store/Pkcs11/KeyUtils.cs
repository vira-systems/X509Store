using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Vira.X509Store.Pkcs11;

/// <summary>
/// PKCS#11 key utility class
/// </summary>
public class KeyUtils
{
    /// <summary>
    /// Finds handles of all key objects present on token
    /// </summary>
    /// <param name="session">PKCS#11 session for finding operation</param>
    /// <param name="keyClass">Value of CKA_CLASS attribute used in search template</param>
    /// <returns>Handle of key object present on token or null</returns>
    public static List<IObjectHandle> FindAllKeys(ISession session, CKO keyClass)
    {
        var factory = session.Factories.ObjectAttributeFactory;
        var searchTemplate = new List<IObjectAttribute>()
        {
            factory.Create(CKA.CKA_CLASS, keyClass),
            factory.Create(CKA.CKA_TOKEN, true),
        };

        return session.FindAllObjects(searchTemplate);
    }

    /// <summary>
    /// Finds handle of key object present on token
    /// </summary>
    /// <param name="session">PKCS#11 session for finding operation</param>
    /// <param name="keyClass">Value of CKA_CLASS attribute used in search template</param>
    /// <param name="ckaId">Value of CKA_ID attribute used in search template</param>
    /// <returns>Handle of key object present on token or null</returns>
    public static IObjectHandle? FindKey(ISession? session, CKO keyClass, byte[] ckaId)
    {
        if (session == null)
            return null;

        var factory = session.Factories.ObjectAttributeFactory;
        var searchTemplate = new List<IObjectAttribute>()
        {
            factory.Create(CKA.CKA_CLASS, keyClass),
            factory.Create(CKA.CKA_TOKEN, true),
            factory.Create(CKA.CKA_ID, ckaId),
        };

        return session.FindAllObjects(searchTemplate).FirstOrDefault();
    }

    /// <summary>
    /// Finds public/private key object present on token
    /// </summary>
    /// <param name="session">PKCS#11 session for finding operation</param>
    /// <param name="keyClass">Value of CKA_CLASS attribute used in search template</param>
    /// <param name="ckaId">Value of CKA_ID attribute used in search template</param>
    /// <returns>Pkcs11KeyInfo of key object present on token or null</returns>
    /// <exception cref="NotSupportedException"></exception>
    public static KeyInfo? FindKeyInfo(ISession session, CKO keyClass, byte[] ckaId)
    {
        var keyHandle = FindKey(session, keyClass, ckaId);
        if (keyHandle == null)
            return null;
        
        var keyAttributes = keyClass switch
        {
            CKO.CKO_PUBLIC_KEY => GetDefaultPublicKeyAttribute(),
            CKO.CKO_PRIVATE_KEY => GetDefaultPrivateKeyAttribute(),
            _ => throw new NotSupportedException("Only CKO_PUBLIC_KEY and CKO_PRIVATE_KEY are supported."),
        };
        var keySize = session.GetObjectSize(keyHandle);
        var keyObjectAttributes = session.GetAttributeValue(keyHandle, keyAttributes);
        return new KeyInfo(keyHandle, keyObjectAttributes, keySize);
    }

    public static KeyPairInfo FindKeyPairInfo(ISession session, byte[] ckaId)
    {
        var privateKeyInfo = FindKeyInfo(session, CKO.CKO_PRIVATE_KEY, ckaId);
        var publicKeyInfo = FindKeyInfo(session, CKO.CKO_PUBLIC_KEY, ckaId);
        return new KeyPairInfo
        {
            PrivateKeyInfo = privateKeyInfo,
            PublicKeyInfo = publicKeyInfo,
        };
    }

    /// <summary>
    /// Gets value of CKA_ALWAYS_AUTHENTICATE attribute of private key object
    /// </summary>
    /// <param name="session">PKCS#11 session for finding operation</param>
    /// <param name="privKeyHandle">Handle of private key object</param>
    /// <returns>Value of CKA_ALWAYS_AUTHENTICATE</returns>
    public static bool GetCkaAlwaysAuthenticateValue(ISession? session, IObjectHandle privKeyHandle)
    {
        if (session == null)
            return false;

        try
        {
            var objectAttributes = session.GetAttributeValue(privKeyHandle, [CKA.CKA_ALWAYS_AUTHENTICATE]);
            return objectAttributes[0].GetValueAsBool();
        }
        catch
        {
            // When CKA_ALWAYS_AUTHENTICATE cannot be read we can assume its value is CK_FALSE
            return false;
        }
    }

    public static List<CKA> GetDefaultPrivateKeyAttribute()
    {
        return
        [
            CKA.CKA_CLASS,
            // Common Storage Object Attributes
            CKA.CKA_TOKEN,
            CKA.CKA_PRIVATE,
            CKA.CKA_MODIFIABLE,
            CKA.CKA_LABEL,
            // Common Key Attributes
            CKA.CKA_KEY_TYPE,
            CKA.CKA_ID,
            CKA.CKA_START_DATE,
            CKA.CKA_END_DATE,
            CKA.CKA_DERIVE,
            CKA.CKA_LOCAL,
            CKA.CKA_ALLOWED_MECHANISMS,
            // Common Private Key Attributes
            CKA.CKA_SUBJECT,
            CKA.CKA_SENSITIVE,
            CKA.CKA_DECRYPT,
            CKA.CKA_SIGN,
            CKA.CKA_SIGN_RECOVER,
            CKA.CKA_UNWRAP,
            CKA.CKA_EXTRACTABLE,
            CKA.CKA_ALWAYS_SENSITIVE,
            CKA.CKA_NEVER_EXTRACTABLE,
            CKA.CKA_WRAP_WITH_TRUSTED,
            CKA.CKA_UNWRAP_TEMPLATE,
            CKA.CKA_ALWAYS_AUTHENTICATE,
        ];
    }

    public static List<CKA> GetDefaultPublicKeyAttribute()
    {
        return
        [
            CKA.CKA_CLASS,
            // Common Storage Object Attributes
            CKA.CKA_TOKEN,
            CKA.CKA_PRIVATE,
            CKA.CKA_MODIFIABLE,
            CKA.CKA_LABEL,
            // Common Key Attributes
            CKA.CKA_KEY_TYPE,
            CKA.CKA_ID,
            CKA.CKA_START_DATE,
            CKA.CKA_END_DATE,
            CKA.CKA_DERIVE,
            CKA.CKA_LOCAL,
            CKA.CKA_ALLOWED_MECHANISMS,
            // Common Public Key Attributes
            CKA.CKA_SUBJECT,
            CKA.CKA_ENCRYPT,
            CKA.CKA_VERIFY,
            CKA.CKA_VERIFY_RECOVER,
            CKA.CKA_WRAP,
            CKA.CKA_TRUSTED,
            CKA.CKA_WRAP_TEMPLATE,
        ];
    }

    public static List<CKA> GetDefaultEcPublicKeyAttribute()
    {
        var publicKeyAttributes = GetDefaultPublicKeyAttribute();
        //Add EC Public Key Attributes
        publicKeyAttributes.AddRange([CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT]);
        return publicKeyAttributes;
    }

    public static List<CKA> GetDefaultRsaPublicKeyAttribute()
    {
        var publicKeyAttributes = GetDefaultPublicKeyAttribute();
        //Add RSA Public Key Attributes
        publicKeyAttributes.AddRange([CKA.CKA_MODULUS_BITS, CKA.CKA_PUBLIC_EXPONENT]);
        return publicKeyAttributes;
    }

    //public static List<IObjectAttribute> CreateDefaultPublicKeyAttribute(ISession session, CKK keyType, string alias, byte[] ckaId)
    //{
    //    var factory = session.Factories.ObjectAttributeFactory;
    //    var attributes = new List<IObjectAttribute>
    //    {
    //        factory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
    //        // Common Storage Object Attributes
    //        factory.Create(CKA.CKA_TOKEN, true),
    //        factory.Create(CKA.CKA_PRIVATE, false),
    //        factory.Create(CKA.CKA_MODIFIABLE, true),
    //        factory.Create(CKA.CKA_LABEL, alias),
    //        // Common Key Attributes
    //        factory.Create(CKA.CKA_KEY_TYPE, keyType),
    //        factory.Create(CKA.CKA_ID, ckaId),
    //        factory.Create(CKA.CKA_DERIVE, false),
    //        // Common Public Key Attributes
    //        factory.Create(CKA.CKA_ENCRYPT, true),
    //        factory.Create(CKA.CKA_VERIFY, true),
    //        factory.Create(CKA.CKA_VERIFY_RECOVER, true),
    //        factory.Create(CKA.CKA_WRAP, true),
    //        factory.Create(CKA.CKA_TRUSTED, false),
    //    };

    //    return attributes;
    //}

    public static List<IObjectAttribute> CreateDefaultEcPublicKeyAttribute(ISession session, CKK keyType, string alias, byte[] ckaId, byte[] ecParams)
    {
        var factory = session.Factories.ObjectAttributeFactory;
        var attributes = new List<IObjectAttribute>
        {
            factory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Common Storage Object Attributes
            factory.Create(CKA.CKA_TOKEN, true),
            factory.Create(CKA.CKA_PRIVATE, false),
            factory.Create(CKA.CKA_MODIFIABLE, true),
            factory.Create(CKA.CKA_LABEL, alias),
            // Common Key Attributes
            factory.Create(CKA.CKA_KEY_TYPE, keyType),
            factory.Create(CKA.CKA_ID, ckaId),
            factory.Create(CKA.CKA_DERIVE, false),
            // Common Public Key Attributes
            factory.Create(CKA.CKA_ENCRYPT, true),
            factory.Create(CKA.CKA_VERIFY, true),
            factory.Create(CKA.CKA_VERIFY_RECOVER, true),
            factory.Create(CKA.CKA_WRAP, true),
            factory.Create(CKA.CKA_TRUSTED, false),
            //EC Public Key Attributes
            factory.Create(CKA.CKA_EC_PARAMS, ecParams),
        };

        return attributes;
    }

    public static List<IObjectAttribute> CreateDefaultRsaPublicKeyAttribute(ISession session, CKK keyType, string alias, byte[] ckaId, ulong keyLength)
    {
        var factory = session.Factories.ObjectAttributeFactory;
        var exponent = new byte[] { 0x01, 0x00, 0x01 };
        var attributes = new List<IObjectAttribute>
        {
            factory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Common Storage Object Attributes
            factory.Create(CKA.CKA_TOKEN, true),
            factory.Create(CKA.CKA_PRIVATE, false),
            factory.Create(CKA.CKA_MODIFIABLE, true),
            factory.Create(CKA.CKA_LABEL, alias),
            // Common Key Attributes
            factory.Create(CKA.CKA_KEY_TYPE, keyType),
            factory.Create(CKA.CKA_ID, ckaId),
            factory.Create(CKA.CKA_DERIVE, false),
            // Common Public Key Attributes
            factory.Create(CKA.CKA_ENCRYPT, true),
            factory.Create(CKA.CKA_VERIFY, true),
            factory.Create(CKA.CKA_VERIFY_RECOVER, true),
            factory.Create(CKA.CKA_WRAP, true),
            factory.Create(CKA.CKA_TRUSTED, false),
            //RSA Public Key Attributes
            factory.Create(CKA.CKA_MODULUS_BITS, keyLength),
            factory.Create(CKA.CKA_PUBLIC_EXPONENT, exponent),
        };

        return attributes;
    }

    public static List<IObjectAttribute> CreateDefaultPrivateKeyAttribute(ISession session, CKK keyType, string alias, byte[] ckaId)
    {
        var factory = session.Factories.ObjectAttributeFactory;
        var attributes = new List<IObjectAttribute>
        {
            factory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Common Storage Object Attributes
            factory.Create(CKA.CKA_TOKEN, true),
            factory.Create(CKA.CKA_PRIVATE, true),
            factory.Create(CKA.CKA_MODIFIABLE, true),
            factory.Create(CKA.CKA_LABEL, alias),
            // Common Key Attributes
            factory.Create(CKA.CKA_KEY_TYPE, keyType),
            factory.Create(CKA.CKA_ID, ckaId),
            factory.Create(CKA.CKA_DERIVE, true),
            // Common Private Key Attributes
            factory.Create(CKA.CKA_SENSITIVE, true),
            factory.Create(CKA.CKA_DECRYPT, true),
            factory.Create(CKA.CKA_SIGN, true),
            factory.Create(CKA.CKA_SIGN_RECOVER, true),
            factory.Create(CKA.CKA_UNWRAP, true),
            factory.Create(CKA.CKA_EXTRACTABLE, true),
            factory.Create(CKA.CKA_WRAP_WITH_TRUSTED, false),
            factory.Create(CKA.CKA_ALWAYS_AUTHENTICATE, false),
        };

        return attributes;
    }
}
