function Test-Nano
{
    $EditionId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID').EditionId

    return (($EditionId -eq "ServerStandardNano") -or
            ($EditionId -eq "ServerDataCenterNano") -or
            ($EditionId -eq "NanoServer") -or
            ($EditionId -eq "ServerTuva"))
}


$ncryptDll = "ncrypt.dll"
$crypt32Dll = "crypt32.dll"

if (-not (Test-Nano))
{
    Write-Verbose "Not running on Nano, using default Win32 binaries."
    $securityDll = "advapi32.dll"
    $capiDll = "advapi32.dll"
    $references = @()
    $PrepareConstrainedRegions = "RuntimeHelpers.PrepareConstrainedRegions();"
}
else
{
    Write-Verbose "Running on Nano, using API sets."
    $securityDll = "api-ms-win-security-base-l1-2-0"
    $capiDll = "api-ms-win-security-cryptoapi-l1-1-0"
    $PrepareConstrainedRegions = "";
    $references =   "System.Security.Cryptography.X509Certificates.dll", `
                    "System.Security.Cryptography.Cng.dll", `
                    "System.IO.FileSystem.AccessControl.dll", `
                    "System.Runtime.Handles.dll", `
                    "System.Security.AccessControl.dll", `
                    "Microsoft.Win32.Primitives.dll" | % { Join-Path "C:\Windows\system32\DotNetCore\v1.0\" $_ }
}

$source = @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Contoso
{
    public static class CryptoTriage
    {
        private const string NCRYPT = "$ncryptDll";
        private const string CRYPT32 = "$crypt32Dll";
        private const string APIMSWINSECURITYBASE = "$securityDll";
        private const string APIMSWINSECURITYCRYPTOAPI = "$capiDll";

        internal const string NCRYPT_SECURITY_DESCR_PROPERTY = "Security Descr";

        [Flags]
        public enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
            UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
            PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
        }

        [Flags]
        private enum CryptAcquireKeyFlagControl : uint
        {
            CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x00010000,
            CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000,
        }

        [Flags]
        public enum CryptAcquireKeyFlags : uint
        {
            CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001,
            CRYPT_ACQUIRE_USE_PROV_INFO_FLAG = 0x00000002,
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 0x00000004,
            CRYPT_ACQUIRE_NO_HEALING = 0x00000008,
            CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040,
        }

        [Flags]
        public enum CryptAcquireNCryptKeyFlags : uint
        {
            CRYPT_ACQUIRE_CACHE_FLAG = CryptAcquireKeyFlags.CRYPT_ACQUIRE_CACHE_FLAG | CryptAcquireKeyFlagControl.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            CRYPT_ACQUIRE_USE_PROV_INFO_FLAG = CryptAcquireKeyFlags.CRYPT_ACQUIRE_USE_PROV_INFO_FLAG | CryptAcquireKeyFlagControl.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG = CryptAcquireKeyFlags.CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CryptAcquireKeyFlagControl.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            CRYPT_ACQUIRE_NO_HEALING = CryptAcquireKeyFlags.CRYPT_ACQUIRE_NO_HEALING | CryptAcquireKeyFlagControl.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            CRYPT_ACQUIRE_SILENT_FLAG = CryptAcquireKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG | CryptAcquireKeyFlagControl.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
        }

        public enum ErrorCode
        {
            Success = 0,                                            // ERROR_SUCCESS
            BadSignature = unchecked((int)0x80090006),              // NTE_BAD_SIGNATURE
            NotFound = unchecked((int)0x80090011),                  // NTE_NOT_FOUND
            KeyDoesNotExist = unchecked((int)0x80090016),           // NTE_BAD_KEYSET
            BufferTooSmall = unchecked((int)0x80090028),            // NTE_BUFFER_TOO_SMALL
            NoMoreItems = unchecked((int)0x8009002a),               // NTE_NO_MORE_ITEMS
            NotSupported = unchecked((int)0x80090029)               // NTE_NOT_SUPPORTED
        }

        public enum KeySpec : uint
        {
            NONE = 0x0,
            AT_KEYEXCHANGE = 0x1,
            AT_SIGNATURE = 2,
            CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF
        }

        public enum ProvParam : uint
        {
            PP_ENUMALGS = 1,
            PP_ENUMCONTAINERS = 2,
            PP_IMPTYPE = 3,
            PP_NAME = 4,
            PP_VERSION = 5,
            PP_CONTAINER = 6,
            PP_CHANGE_PASSWORD = 7,
            PP_KEYSET_SEC_DESCR = 8,    // get/set security descriptor of keyset
            PP_CERTCHAIN = 9,           // for retrieving certificates from tokens
            PP_KEY_TYPE_SUBTYPE = 10,
            PP_PROVTYPE = 16,
            PP_KEYSTORAGE = 17,
            PP_APPLI_CERT = 18,
            PP_SYM_KEYSIZE = 19,
            PP_SESSION_KEYSIZE = 20,
            PP_UI_PROMPT = 21,
            PP_ENUMALGS_EX = 22,
            PP_ENUMMANDROOTS = 25,
            PP_ENUMELECTROOTS = 26,
            PP_KEYSET_TYPE = 27,
            PP_ADMIN_PIN = 31,
            PP_KEYEXCHANGE_PIN = 32,
            PP_SIGNATURE_PIN = 33,
            PP_SIG_KEYSIZE_INC = 34,
            PP_KEYX_KEYSIZE_INC = 35,
            PP_UNIQUE_CONTAINER = 36,
            PP_SGC_INFO = 37,
            PP_USE_HARDWARE_RNG = 38,
            PP_KEYSPEC = 39,
            PP_ENUMEX_SIGNING_PROT = 40,
            PP_CRYPT_COUNT_KEY_USE = 41,
        }

        [DllImport(APIMSWINSECURITYBASE, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent,
            ref IntPtr pDacl,
            [MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted);

        [DllImport(NCRYPT, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern ErrorCode NCryptGetProperty(
            SafeHandle hObject,
            [MarshalAs(UnmanagedType.LPWStr)] string pszProperty,
            SafeSecurityDescriptorPtr pbOutput,
            uint cbOutput,
            ref uint pcbResult,
            SECURITY_INFORMATION dwFlags);

        [DllImport(NCRYPT, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern ErrorCode NCryptSetProperty(
            SafeHandle hObject,
            [MarshalAs(UnmanagedType.LPWStr)] string pszProperty,
            [MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
            uint cbInput,
            SECURITY_INFORMATION dwFlags);

        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptAcquireCertificatePrivateKey(
            IntPtr pCert,
            CryptAcquireKeyFlags dwFlags,
            IntPtr pvParameters,
            out SafeCryptProviderHandle phCryptProvOrNCryptKey,
            out KeySpec pdwKeySpec,
            out bool pfCallerFreeProvOrNCryptKey);

        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptAcquireCertificatePrivateKey(
            IntPtr pCert,
            CryptAcquireNCryptKeyFlags dwFlags,
            IntPtr pvParameters,
            out SafeNCryptKeyHandle phCryptProvOrNCryptKey,
            out KeySpec pdwKeySpec,
            out bool pfCallerFreeProvOrNCryptKey);

        [DllImport(APIMSWINSECURITYCRYPTOAPI, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptContextAddRef(
            SafeCryptProviderHandle hProv,
            IntPtr pdwReserved,
            uint dwFlags);

        [DllImport(APIMSWINSECURITYCRYPTOAPI, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptReleaseContext(
            IntPtr hProv,
            uint dwFlags);

        [DllImport(APIMSWINSECURITYCRYPTOAPI, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptGetProvParam(
            SafeHandle hProv,
            ProvParam dwParam,
            SafeSecurityDescriptorPtr pbData,
            ref uint pdwDataLen,
            SECURITY_INFORMATION dwFlags);

        [DllImport(APIMSWINSECURITYCRYPTOAPI, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptSetProvParam(
            SafeHandle hProv,
            ProvParam dwParam,
            [MarshalAs(UnmanagedType.LPArray)] byte[] pbData,
            SECURITY_INFORMATION dwFlags);

        public static TriageHandle TriageAcquireKeyHandle(X509Certificate2 certificate)
        {
            SafeNCryptKeyHandle ncryptKeyHandle = null;
            SafeCryptProviderHandle cspHandle = null;
            KeySpec keySpec;
            bool ownHandle = true;

            if (!CryptAcquireCertificatePrivateKey(
                    certificate.Handle,
                    CryptAcquireKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG,
                    IntPtr.Zero,
                    out cspHandle,
                    out keySpec,
                    out ownHandle))
            {
                Win32Exception cspException = new Win32Exception(Marshal.GetLastWin32Error());

                if (!CryptAcquireCertificatePrivateKey(
                        certificate.Handle,
                        CryptAcquireNCryptKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG,
                        IntPtr.Zero,
                        out ncryptKeyHandle,
                        out keySpec,
                        out ownHandle))
                {
                    throw new AggregateException(
                        new Win32Exception(Marshal.GetLastWin32Error()),
                        cspException);
                }
            }

            if (!ownHandle)
            {
                throw new NotSupportedException("Must be able to take ownership of the certificate private key handle.");
            }

            if (ncryptKeyHandle != null)
            {
                return new CngTriageHandle(ncryptKeyHandle);
            }
            else if (cspHandle != null)
            {
                if (keySpec != KeySpec.AT_KEYEXCHANGE && keySpec != KeySpec.AT_SIGNATURE)
                {
                    throw new NotSupportedException("Only exchange or signature key pairs are supported.");
                }

                return new CapiTriageHandle(cspHandle);
            }
            else
            {
                throw new NotSupportedException("The certificate private key cannot be accessed.");
            }
        }

        public static void AssertSuccess(this ErrorCode code)
        {
            if (code != ErrorCode.Success)
            {
                throw new Win32Exception((int)code);
            }
        }

        public class SafeCryptProviderHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private static SafeCryptProviderHandle nullHandle = new SafeCryptProviderHandle();

            public SafeCryptProviderHandle()
                : base(true)
            {
            }

            public SafeCryptProviderHandle(IntPtr handle)
                : base(true)
            {
                this.SetHandle(handle);
            }

            public static SafeCryptProviderHandle Null
            {
                get
                {
                    return nullHandle;
                }
            }

            internal SafeCryptProviderHandle Duplicate()
            {
                if (this.IsInvalid || this.IsClosed)
                {
                    throw new InvalidOperationException();
                }

                // in the window between the call to CryptContextAddRef and when the raw handle value is assigned
                // into the new safe handle, there's a second reference to the original safe handle that the CLR does
                // not know about, so we need to bump the reference count around this entire operation to ensure
                // that we don't have the original handle closed underneath us.
                bool acquired = false;
                try
                {
                    this.DangerousAddRef(ref acquired);
                    IntPtr underlyingHandle = this.DangerousGetHandle();
                    SafeCryptProviderHandle duplicate = new SafeCryptProviderHandle();
                    int lastError = 0;

                    // atomically add reference and set handle on the duplicate
                    $PrepareConstrainedRegions
                    try
                    {
                    }
                    finally
                    {
                        if (!CryptContextAddRef(this, IntPtr.Zero, 0))
                        {
                            lastError = Marshal.GetLastWin32Error();
                        }
                        else
                        {
                            duplicate.SetHandle(underlyingHandle);
                        }
                    }

                    if (lastError != 0)
                    {
                        duplicate.Dispose();
                        throw new Win32Exception(lastError);
                    }

                    return duplicate;
                }
                finally
                {
                    if (acquired)
                    {
                        this.DangerousRelease();
                    }
                }
            }

            protected override bool ReleaseHandle()
            {
                return CryptReleaseContext(this.handle, 0);
            }
        }

        public class SafeSecurityDescriptorPtr : SafeHandleZeroOrMinusOneIsInvalid
        {
            private static SafeSecurityDescriptorPtr nullHandle = new SafeSecurityDescriptorPtr();

            private int size = -1;

            public SafeSecurityDescriptorPtr()
                : base(true)
            {
            }

            public SafeSecurityDescriptorPtr(uint size)
                : base(true)
            {
                this.size = (int)size;
                this.SetHandle(Marshal.AllocHGlobal(this.size));
            }

            public SafeSecurityDescriptorPtr(IntPtr handle)
                : base(true)
            {
                this.SetHandle(handle);
            }

            public static SafeSecurityDescriptorPtr Null
            {
                get
                {
                    return nullHandle;
                }
            }

            public IntPtr GetDacl()
            {
                IntPtr pDacl = IntPtr.Zero;
                bool daclPresent = false;
                bool daclDefaulted = false;

                if (!GetSecurityDescriptorDacl(
                        this.handle,
                        out daclPresent,
                        ref pDacl,
                        out daclDefaulted))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (!daclPresent)
                {
                    return IntPtr.Zero;
                }
                else
                {
                    return pDacl;
                }
            }

            public byte[] GetBinaryForm()
            {
                if (size < 0)
                {
                    throw new NotSupportedException();
                }

                byte[] buffer = new byte[size];
                Marshal.Copy(this.handle, buffer, 0, buffer.Length);

                return buffer;
            }

            protected override bool ReleaseHandle()
            {
                try
                {
                    Marshal.FreeHGlobal(this.handle);
                    return true;
                }
                catch
                {
                    // semantics of this function are to never throw an exception so we must eat the underlying error and
                    // return false.
                    return false;
                }
            }
        }

        public abstract class TriageHandle : IDisposable
        {
            public TriageHandle()
            {
            }

            public abstract FileSecurity Acl
            {
                get;
                set;
            }

            public abstract bool IsValid
            {
                get;
            }

            public abstract void Dispose();
        }

        public class CapiTriageHandle : TriageHandle
        {
            public CapiTriageHandle(SafeCryptProviderHandle handle) : base()
            {
                this.Handle = handle;
            }

            public override bool IsValid
            {
                get
                {
                    return this.Handle != null && !this.Handle.IsInvalid && !this.Handle.IsClosed;
                }
            }

            public override FileSecurity Acl
            {
                get
                {
                    uint securityDescriptorSize = 0;
                    if (!CryptGetProvParam(
                            this.Handle,
                            ProvParam.PP_KEYSET_SEC_DESCR,
                            SafeSecurityDescriptorPtr.Null,
                            ref securityDescriptorSize,
                            SECURITY_INFORMATION.DACL_SECURITY_INFORMATION))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }

                    SafeSecurityDescriptorPtr securityDescriptorBuffer = new SafeSecurityDescriptorPtr(securityDescriptorSize);

                    if (!CryptGetProvParam(
                            this.Handle,
                            ProvParam.PP_KEYSET_SEC_DESCR,
                            securityDescriptorBuffer,
                            ref securityDescriptorSize,
                            SECURITY_INFORMATION.DACL_SECURITY_INFORMATION))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }

                    using (securityDescriptorBuffer)
                    {
                        FileSecurity acl = new FileSecurity();
                        acl.SetSecurityDescriptorBinaryForm(securityDescriptorBuffer.GetBinaryForm());
                        return acl;
                    }
                }

                set
                {
                    if (!CryptSetProvParam(
                        this.Handle,
                        ProvParam.PP_KEYSET_SEC_DESCR,
                        value.GetSecurityDescriptorBinaryForm(),
                        SECURITY_INFORMATION.DACL_SECURITY_INFORMATION))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }
            }

            protected SafeCryptProviderHandle Handle
            {
                get;
                set;
            }

            public override void Dispose()
            {
                this.Handle.Dispose();
            }
        }

        public class CngTriageHandle : TriageHandle
        {
            public CngTriageHandle(SafeNCryptHandle handle) : base()
            {
                this.Handle = handle;
            }

            public override bool IsValid
            {
                get
                {
                    return this.Handle != null && !this.Handle.IsInvalid && !this.Handle.IsClosed;
                }
            }

            public override FileSecurity Acl
            {
                get
                {
                    uint securityDescriptorSize = 0;
                    NCryptGetProperty(
                        this.Handle,
                        NCRYPT_SECURITY_DESCR_PROPERTY,
                        SafeSecurityDescriptorPtr.Null,
                        0,
                        ref securityDescriptorSize,
                        SECURITY_INFORMATION.DACL_SECURITY_INFORMATION).AssertSuccess();

                    SafeSecurityDescriptorPtr securityDescriptorBuffer = new SafeSecurityDescriptorPtr(securityDescriptorSize);

                    NCryptGetProperty(
                        this.Handle,
                        NCRYPT_SECURITY_DESCR_PROPERTY,
                        securityDescriptorBuffer,
                        securityDescriptorSize,
                        ref securityDescriptorSize,
                        SECURITY_INFORMATION.DACL_SECURITY_INFORMATION).AssertSuccess();

                    using (securityDescriptorBuffer)
                    {
                        FileSecurity acl = new FileSecurity();
                        acl.SetSecurityDescriptorBinaryForm(securityDescriptorBuffer.GetBinaryForm());
                        return acl;
                    }
                }

                set
                {
                    byte[] sd = value.GetSecurityDescriptorBinaryForm();
                    NCryptSetProperty(
                        this.Handle,
                        NCRYPT_SECURITY_DESCR_PROPERTY,
                        sd,
                        (uint)sd.Length,
                        SECURITY_INFORMATION.DACL_SECURITY_INFORMATION).AssertSuccess();
                }
            }

            protected SafeNCryptHandle Handle
            {
                get;
                set;
            }

            public override void Dispose()
            {
                this.Handle.Dispose();
            }
        }
    }
}
"@

if (-not $global:ContosoCertificateManagementCompiled)
{
    Write-Verbose "Loading certificate management p/invoke shim."
    Add-Type -TypeDefinition $source -Language CSharp -ReferencedAssemblies $references -ErrorAction Stop
    $global:ContosoCertificateManagementCompiled = $true
}
else
{
    Write-Warning "Certificate management class was already loaded.  If you made any changes, you will need to close and re-open PowerShell to successfully import the new module."
}


function Add-AccessRule
{
    <#
    .SYNOPSIS
    Adds a file access rule to a file security descriptor.

    .DESCRIPTION
    Accepts a file access rule or constructs a new access rule from the provided parameters and appends it to an existing file security descriptor.  Leaves the original security descriptor intact and returns an updated copy.

    .PARAMETER SD
    An existing file security descriptor.  Can be retrieved from certificates by accessing the Acl property.

    .PARAMETER UserAccount
    A string identifying a user or group principal that will be controled by this access rule.

    .PARAMETER FileSystemRights
    The rights to be granted to the UserAccount by this access rule.

    .PARAMETER AccessControlType
    Whether this is an allow or deny access rule.

    .PARAMETER Rule
    A pre-created file system access rule.

    .EXAMPLE
    $certificate.Acl = $certificate.Acl | Add-AccessRule "Administrator" FullControl Allow

    Adds a rule granting the local administrator full control of the $certificate's private key.

    .EXAMPLE
    $sd = Add-AccessRule -UserAccount "Everyone" -FileSystemRights Read -AccessControlType Deny -SD $sd

    Appends a rule to an existing security descriptor ($sd) that denys all users read access.
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$true,Position=3,Mandatory=$true)]
        [ValidateNotNull()]
        [System.Security.AccessControl.FileSecurity] $SD,

        [Parameter(Position=0,Mandatory=$true,ParameterSetName="ctor")]
        [ValidateNotNullOrEmpty()]
        [string] $UserAccount,

        [Parameter(Position=1,Mandatory=$true,ParameterSetName="ctor")]
        [ValidateNotNullOrEmpty()]
        [System.Security.AccessControl.FileSystemRights] $FileSystemRights,

        [Parameter(Position=2,Mandatory=$true,ParameterSetName="ctor")]
        [ValidateNotNullOrEmpty()]
        [System.Security.AccessControl.AccessControlType] $AccessControlType,

        [Parameter(Mandatory=$true,ParameterSetName="obj")]
        [ValidateNotNullOrEmpty()]
        [System.Security.AccessControl.FileSystemAccessRule] $Rule
    )

    if (-not $Rule)
    {
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule $UserAccount,$FileSystemRights,$AccessControlType -ErrorAction Stop
    }

    # perform a deep clone of the input SD to prevent side effects
    $newSD = New-Object System.Security.AccessControl.FileSecurity
    $newSD.SetSecurityDescriptorBinaryForm($SD.GetSecurityDescriptorBinaryForm())

    # add the new rule
    $newSD.AddAccessRule($Rule)
    Write-Output $newSD
}