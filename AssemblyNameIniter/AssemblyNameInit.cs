/*
 * Created by SharpDevelop.
 * User: Mihai
 * Date: 3/9/2017
 * Time: 8:01 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.IO;
using System.Reflection;
using System.Globalization;
using System.Configuration.Assemblies;
using System.Security.Cryptography;

namespace AssemblyNameIniter
{
	/// <summary>
	/// Description of AssemblyNameInit.
	/// </summary>
	public class AssemblyNameInit
	{

public static AssemblyName GetAssemblyName(string filename)
{
FileStream input = new FileStream(filename, FileMode.Open, System.IO.FileAccess.Read, FileShare.ReadWrite);
BinaryReader reader = new BinaryReader(input);
AssemblyName asm_name = null;
asm_name = GetAssemblyName(reader);
reader.Close();
input.Close();
return asm_name;
}

public static AssemblyName GetAssemblyName(byte[] filebytes)
{
MemoryStream input = new MemoryStream(filebytes);
BinaryReader reader = new BinaryReader(input);
AssemblyName asm_name = GetAssemblyName(reader);
reader.Close();
input.Close();

return asm_name;
}
		
public static AssemblyName GetAssemblyName(BinaryReader reader)
{
AssemblyName asm_name = null;
MetadataReader mr = new MetadataReader();
if (mr.Initialize(reader))
asm_name = GetAssemblyName(mr);

mr = null;
return asm_name;
}
		
		public static AssemblyName GetAssemblyName(MetadataReader mr)
		{
// sanity checks:
if (!IsMrValid(mr)) return null;

AssemblyName asm_name = new AssemblyName();
asm_name.Name = GetSimpleName(mr);
asm_name.SetPublicKey(GetPublicKey(mr));
asm_name.SetPublicKeyToken(GetPublicKeyToken(mr));
asm_name.Version = GetVersion(mr);
asm_name.CultureInfo = GetLocale(mr);
asm_name.HashAlgorithm = GetHashAlgorithm(mr);
asm_name.VersionCompatibility = GetVersionCompatibility(mr);
asm_name.Flags = GetFlags(mr);
asm_name.KeyPair = GetKeyPair(mr);
asm_name.ProcessorArchitecture = ComputeProcArchIndex(mr);
// Take care also on CodeBase!

return asm_name;
				
		}
		
public static bool IsMrValid(MetadataReader mr)
{
if (mr==null) return false;
if (mr.tablesize==null||mr.tables==null) return false;
if (mr.tablesize.Length<=0|mr.tables.Length<=0) return false;
if (mr.TableLengths==null||mr.TableLengths.Length<=0) return false;

 // If "Assembly" table lenght is <=0:
 if (mr.TableLengths[0x20]<=0) return false;
 
 return true; // mr seems valid
}
		
public static string GetSimpleName(MetadataReader mr)
{
// sanity checks:
if (!IsMrValid(mr)) return null;

long NameOffset=mr.tables[0x20].members[0][7];
if (NameOffset == 0) return "";
string AsmName = mr.ReadName((int)NameOffset);
return AsmName;
}

public static byte[] GetPublicKey(MetadataReader mr)
{
// sanity checks:
if (!IsMrValid(mr)) return null;

long PublicKeyOffset = mr.tables[0x20].members[0][6];
if (PublicKeyOffset == 0) return null;
long PKTOffset=mr.BlobOffset+PublicKeyOffset;
	
mr.binary_reader.BaseStream.Position=PKTOffset;
byte[] keeper = new byte[2];
byte firstbyte = mr.binary_reader.ReadByte();
keeper[1]=(byte)(firstbyte&0x07F);
if ((firstbyte&0x080)!=0)
keeper[0]=mr.binary_reader.ReadByte();
else
Array.Reverse(keeper);
short PKlenght = BitConverter.ToInt16(keeper,0);
byte[] PK=mr.binary_reader.ReadBytes(PKlenght);
return PK;
}


public static byte[] GetPublicKeyToken(MetadataReader mr)
{
// sanity checks:
if (!IsMrValid(mr)) return null;

byte[] PK = GetPublicKey(mr);
if (PK==null) return null;

AssemblyHashAlgorithm hash_algo = GetHashAlgorithm(mr);

byte[] hash=null;
if (hash_algo==AssemblyHashAlgorithm.SHA1)
{
SHA1CryptoServiceProvider cryptoTransformSHA1 = new SHA1CryptoServiceProvider();
hash = cryptoTransformSHA1.ComputeHash(PK);
}
else if (hash_algo==AssemblyHashAlgorithm.MD5)
{
MD5CryptoServiceProvider cryptoTransformMD5 = new MD5CryptoServiceProvider();
hash = cryptoTransformMD5.ComputeHash(PK);
}

byte[] publicKeyToken = new Byte[8];
Array.Copy(hash, hash.Length - publicKeyToken.Length, publicKeyToken, 0, publicKeyToken.Length);
Array.Reverse(publicKeyToken, 0, publicKeyToken.Length);

return publicKeyToken;
}

public static Version GetVersion(MetadataReader mr)
{
// sanity checks:
if (!IsMrValid(mr)) return null;

int major = (int)mr.tables[0x20].members[0][1];
int minor = (int)mr.tables[0x20].members[0][2];
int build = (int)mr.tables[0x20].members[0][3];
int revision = (int)mr.tables[0x20].members[0][4];
Version ver = new Version(major, minor, build, revision);
return ver;
}

public static CultureInfo GetLocale(MetadataReader mr)
{
// sanity checks:
if (!IsMrValid(mr)) return null;

long CultureOffset=mr.tables[0x20].members[0][8];
if (CultureOffset == 0) return CultureInfo.InvariantCulture;
string Culturename = mr.ReadName((int)CultureOffset);
CultureInfo culture_info = new CultureInfo(Culturename);
return culture_info;
}

public static AssemblyHashAlgorithm GetHashAlgorithm(MetadataReader mr)
{
// sanity checks:
if (!IsMrValid(mr)) return AssemblyHashAlgorithm.SHA1;  // default is SHA1

int HashAlgId_int = (int)mr.tables[0x20].members[0][0];  // HashAlgId
AssemblyHashAlgorithm converted = (AssemblyHashAlgorithm)HashAlgId_int;

return converted;
}

public static AssemblyVersionCompatibility GetVersionCompatibility(MetadataReader mr)
{
return AssemblyVersionCompatibility.SameMachine;
}

public static AssemblyNameFlags GetFlags(MetadataReader mr)
{
// sanity checks:
if (!IsMrValid(mr)) return AssemblyNameFlags.None;

int Asmflags_int = (int)mr.tables[0x20].members[0][5];  // Flags
AssemblyNameFlags asm_flags = (AssemblyNameFlags)Asmflags_int;
return asm_flags;

}

public static StrongNameKeyPair GetKeyPair(MetadataReader mr)
{
// sanity checks:
if (!IsMrValid(mr)) return null;

try
{
FileStream oKeyPairFileStream = File.OpenRead("FileName");
System.Reflection.StrongNameKeyPair oKeyPairFile = new StrongNameKeyPair(oKeyPairFileStream);
oKeyPairFileStream.Close();
return oKeyPairFile;
}
catch(Exception exc)
{
return null;
}

}

public static int GetMDStreamVersion(MetadataReader mr)
{
if (mr==null) return 0;
// sanity checks - only check if is NET
if (mr.inh.ioh.MetaDataDirectory.RVA==0) return 0;
if (mr.inh.ioh.MetaDataDirectory.Size<=0) return 0;

int stream_version = mr.tableheader.MajorVersion*0x10000+mr.tableheader.MinorVersion;
return stream_version;
}

public static ProcessorArchitecture ComputeProcArchIndex(MetadataReader mr)
{
if (mr==null) return ProcessorArchitecture.None;
// sanity checks - only check if is NET
if (mr.inh.ioh.MetaDataDirectory.RVA==0) return ProcessorArchitecture.None;
if (mr.inh.ioh.MetaDataDirectory.Size<=0) return ProcessorArchitecture.None;

int md_stream_version = GetMDStreamVersion(mr);
if (md_stream_version==0) return ProcessorArchitecture.None;
	
    if (md_stream_version > 0x10000)
    {
		// PortableExecutableKinds.PE32Plus = IL Libary
		if ((mr.netdir.Flags & (int)PortableExecutableKinds.PE32Plus) == (int)PortableExecutableKinds.PE32Plus)
        {
			if (mr.inh.ifh.Machine == (ushort)ImageFileMachine.I386)
            {
                if ((mr.netdir.Flags & (int)PortableExecutableKinds.ILOnly) == (int)PortableExecutableKinds.ILOnly)
                {
                    return ProcessorArchitecture.MSIL;
                }
            }
            else
            {
                if (mr.inh.ifh.Machine == (ushort)ImageFileMachine.IA64)
                {
                    return ProcessorArchitecture.IA64;
                }
                if (mr.inh.ifh.Machine == (ushort)ImageFileMachine.AMD64)
                {
                    return ProcessorArchitecture.Amd64;
                }
            }
        }
        else if (mr.inh.ifh.Machine == (ushort)ImageFileMachine.I386)
        {
        	if (((mr.netdir.Flags & (int)PortableExecutableKinds.Required32Bit) != (int)PortableExecutableKinds.Required32Bit) && ((mr.netdir.Flags & (int)PortableExecutableKinds.ILOnly) == (int)PortableExecutableKinds.ILOnly))
            {
                return ProcessorArchitecture.MSIL;
            }
            return ProcessorArchitecture.X86;
        }
    }
    return ProcessorArchitecture.None;

}

	

		public static AssemblyName[] GetAsmRefsAssemblyName(MetadataReader mr)
		{
		AssemblyName[] asm_refs = new AssemblyName[AsmRefsCount(mr)];
		for (int i=0;i<asm_refs.Length;i++)
		asm_refs[i] = GetAsmRefAssemblyName(mr, i);
		return asm_refs;
		}
		
		
public static AssemblyName[] GetAsmRefsAssemblyName(string filename)
{
FileStream input = new FileStream(filename, FileMode.Open, System.IO.FileAccess.Read, FileShare.ReadWrite);
BinaryReader reader = new BinaryReader(input);
AssemblyName[] asm_refs = GetAsmRefsAssemblyName(reader);
reader.Close();
input.Close();
return asm_refs;
}

public static AssemblyName[] GetAsmRefsAssemblyName(byte[] filebytes)
{
MemoryStream input = new MemoryStream(filebytes);
BinaryReader reader = new BinaryReader(input);
AssemblyName[] asm_refs = GetAsmRefsAssemblyName(reader);
reader.Close();
input.Close();

return asm_refs;
}
		
public static AssemblyName[] GetAsmRefsAssemblyName(BinaryReader reader)
{
AssemblyName[] asm_refs = null;
MetadataReader mr = new MetadataReader();
if (mr.Initialize(reader))
asm_refs = GetAsmRefsAssemblyName(mr);

mr = null;
return asm_refs;
}

public static bool IsMrAsmRefsValid(MetadataReader mr)
{
if (mr==null) return false;
if (mr.tablesize==null||mr.tables==null) return false;
if (mr.tablesize.Length<=0|mr.tables.Length<=0) return false;
if (mr.TableLengths==null||mr.TableLengths.Length<=0) return false;

 // If "AssemblyRefs" table lenght is <=0:
 //if (mr.TableLengths[0x23]<=0) return false;
 return true; // mr seems valid
}
 

public static int AsmRefsCount(MetadataReader mr)
{
if (!IsMrAsmRefsValid(mr)) return 0;
	    
return mr.TableLengths[0x23];
}

public static AssemblyName GetAsmRefAssemblyName(MetadataReader mr, int index)
{
// sanity checks:
if (!IsMrAsmRefsValid(mr)) return null;

if (index>=mr.TableLengths[0x23]) return null;  // out of AssemblyRef count

AssemblyName asm_name = new AssemblyName();
asm_name.Name = GetAsmRefSimpleName(mr, index);
asm_name.SetPublicKey(null);
asm_name.SetPublicKeyToken(GetAsmRefPublicKeyToken(mr, index));
asm_name.Version = GetAsmRefVersion(mr, index);
asm_name.CultureInfo = GetAsmRefLocale(mr, index);
asm_name.Flags = GetAsmRefFlags(mr, index);

return asm_name;
				
}

public static string GetAsmRefSimpleName(MetadataReader mr, int index)
{
// sanity checks:
if (!IsMrAsmRefsValid(mr)) return null;

if (index>=mr.TableLengths[0x23]) return null;  // out of AssemblyRef count

long NameOffset=mr.tables[0x23].members[index][6];
if (NameOffset == 0) return "";
string AsmRefName = mr.ReadName((int)NameOffset);
return AsmRefName;
}

public static byte[] GetAsmRefPublicKeyToken(MetadataReader mr, int index)
{
// sanity checks:
if (!IsMrAsmRefsValid(mr)) return null;

if (index>=mr.TableLengths[0x23]) return null;  // out of AssemblyRef count

long PublicKeyOffset = mr.tables[0x23].members[index][5];
if (PublicKeyOffset == 0) return null;
long PKTOffset=mr.BlobOffset+PublicKeyOffset;

mr.binary_reader.BaseStream.Position=PKTOffset;
byte[] keeper = new byte[2];
byte firstbyte = mr.binary_reader.ReadByte();
keeper[1]=(byte)(firstbyte&0x07F);
if ((firstbyte&0x080)!=0)
keeper[0]=mr.binary_reader.ReadByte();
else
Array.Reverse(keeper);

short PKlenght = BitConverter.ToInt16(keeper,0);
byte[] PK=mr.binary_reader.ReadBytes(PKlenght);
return PK;
}

public static Version GetAsmRefVersion(MetadataReader mr, int index)
{
// sanity checks:
if (!IsMrAsmRefsValid(mr)) return null;

if (index>=mr.TableLengths[0x23]) return null;  // out of AssemblyRef count

int major = (int)mr.tables[0x23].members[index][0];
int minor = (int)mr.tables[0x23].members[index][1];
int build = (int)mr.tables[0x23].members[index][2];
int revision = (int)mr.tables[0x23].members[index][3];
Version ver = new Version(major, minor, build, revision);
return ver;
}

public static CultureInfo GetAsmRefLocale(MetadataReader mr, int index)
{
// sanity checks:
if (!IsMrAsmRefsValid(mr)) return null;

if (index>=mr.TableLengths[0x23]) return null;  // out of AssemblyRef count

long CultureOffset=mr.tables[0x23].members[index][7];
if (CultureOffset == 0) return CultureInfo.InvariantCulture;
string Culturename = mr.ReadName((int)CultureOffset);
CultureInfo culture_info = new CultureInfo(Culturename);
return culture_info;
}

public static AssemblyNameFlags GetAsmRefFlags(MetadataReader mr, int index)
{
// sanity checks:
if (!IsMrAsmRefsValid(mr)) return AssemblyNameFlags.None;

if (index>=mr.TableLengths[0x23]) return AssemblyNameFlags.None;  // out of AssemblyRef count

int Asmflags_int = (int)mr.tables[0x23].members[index][4];  // Flags
AssemblyNameFlags asm_flags = (AssemblyNameFlags)Asmflags_int;
return asm_flags;

}

 

public static void SetCodeBase(AssemblyName asmname, string codebase)
{
	if (asmname==null) return;
	
	asmname.CodeBase = codebase;
		
}


 

 

	}
}
