/*
 * Created by SharpDevelop.
 * User: Mihai
 * Date: 3/9/2017
 * Time: 7:46 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.IO;
using System.Reflection;

namespace AssemblyNameIniter
{
	class Program
	{
		public static void Main(string[] args)
		{

string filename = "D:\\asaNU\\Simple_MSIL_Decryptor.exe";
AssemblyName asm_name1 = AssemblyName.GetAssemblyName(filename);
//AssemblyName name1 = AssemblyName.GetAssemblyName(filename);
MetadataReader mr = new MetadataReader();
FileStream input = new FileStream(filename, FileMode.Open, System.IO.FileAccess.Read, FileShare.ReadWrite);
BinaryReader reader = new BinaryReader(input);
if (mr.Initialize(reader))
{
AssemblyName asm_name = AssemblyNameInit.GetAssemblyName(mr);
AssemblyNameInit.SetCodeBase(asm_name, filename);
AssemblyName[] asm_refs = AssemblyNameInit.GetAsmRefsAssemblyName(mr);
Assembly asm = Assembly.Load(asm_name);

Console.WriteLine(asm.ManifestModule.MDStreamVersion.ToString("X8"));
Console.ReadLine();

}

reader.Close();
input.Close();
mr = null;


			
			Console.WriteLine("Hello World!");
			
			// TODO: Implement Functionality Here
			
			Console.Write("Press any key to continue . . . ");
			Console.ReadKey(true);
		}
	}
}