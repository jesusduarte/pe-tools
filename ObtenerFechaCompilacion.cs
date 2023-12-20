using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DosHeader
{
    public UInt16 MagicNumber;      // e_magic
    public UInt16 BytesOnLastPage;  // e_cblp
    public UInt16 PagesInFile;      // e_cp
    public UInt16 Relocations;      // e_crlc
    public UInt16 HeaderSize;       // e_cparhdr
    public UInt16 MinMemory;        // e_minalloc
    public UInt16 MaxMemory;        // e_maxalloc
    public UInt16 InitialSS;        // e_ss
    public UInt16 InitialSP;        // e_sp
    public UInt16 Checksum;         // e_csum
    public UInt16 InitialIP;        // e_ip
    public UInt16 InitialCS;        // e_cs
    public UInt16 RelocationTable;  // e_lfarlc
    public UInt16 OverlayNumber;    // e_ovno
    public UInt16 Reserved1;        // e_res_0
    public UInt16 Reserved2;        // e_res_1
    public UInt16 Reserved3;        // e_res_2
    public UInt16 Reserved4;        // e_res_3
    public UInt16 OEMID;            // e_oemid
    public UInt16 OEMInfo;          // e_oeminfo
    public UInt16 Reserved5;        // e_res2_0
    public UInt16 Reserved6;        // e_res2_1
    public UInt16 Reserved7;        // e_res2_2
    public UInt16 Reserved8;        // e_res2_3
    public UInt16 Reserved9;        // e_res2_4
    public UInt16 Reserved10;       // e_res2_5
    public UInt16 Reserved11;       // e_res2_6
    public UInt16 Reserved12;       // e_res2_7
    public UInt16 Reserved13;       // e_res2_8
    public UInt16 Reserved14;       // e_res2_9
    public UInt32 PeHeaderOffset;   // e_lfanew
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct PeHeaders
{
    public UInt32 Signature;
    public IMAGE_FILE_HEADER FileHeader;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IMAGE_FILE_HEADER
{
    public UInt16 Machine;
    public UInt16 NumberOfSections;
    public UInt32 TimeDateStamp;
    public UInt32 PointerToSymbolTable;
    public UInt32 NumberOfSymbols;
    public UInt16 SizeOfOptionalHeader;
    public UInt16 Characteristics;
}

class Program
{
    static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: ObtenerFechaCompilacionPE.exe <executable_path>");
            return;
        }

        string filePath = args[0];

        if (!File.Exists(filePath))
        {
            Console.WriteLine("The specified file does not exist.");
            return;
        }

        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            DosHeader dosHeader = new DosHeader();

            // Read the DOS header (first 64 bytes of the file)
            byte[] dosHeaderBytes = new byte[Marshal.SizeOf(typeof(DosHeader))];
            fs.Read(dosHeaderBytes, 0, dosHeaderBytes.Length);
            GCHandle dosHandle = GCHandle.Alloc(dosHeaderBytes, GCHandleType.Pinned);
            dosHeader = (DosHeader)Marshal.PtrToStructure(dosHandle.AddrOfPinnedObject(), typeof(DosHeader));
            dosHandle.Free();

            // Check if the "MZ" signature is present in the DOS header
            if (dosHeader.MagicNumber == 0x5A4D) // "MZ" in little-endian
            {
                // Go to the offset of the PE signature (e_lfanew)
                fs.Seek(dosHeader.PeHeaderOffset, SeekOrigin.Begin);

                // Read the PE headers into the struct
                PeHeaders peHeaders = new PeHeaders();
                byte[] peHeadersBytes = new byte[Marshal.SizeOf(typeof(PeHeaders))];
                fs.Read(peHeadersBytes, 0, peHeadersBytes.Length);
                GCHandle peHandle = GCHandle.Alloc(peHeadersBytes, GCHandleType.Pinned);
                peHeaders = (PeHeaders)Marshal.PtrToStructure(peHandle.AddrOfPinnedObject(), typeof(PeHeaders));
                peHandle.Free();

                // Print the Timestamp and Number of Sections from the PE headers
                Console.WriteLine($"Timestamp Header: 0x{peHeaders.FileHeader.TimeDateStamp:X}");
                Console.WriteLine($"Number of Sections: {peHeaders.FileHeader.NumberOfSections}");

                // Convert the timestamp to DateTime
                DateTime compilationDate = UnixTimeStampToDateTime(peHeaders.FileHeader.TimeDateStamp);
                Console.WriteLine($"Compilation Date: {compilationDate}");
            }
            else
            {
                Console.WriteLine("MZ signature not found in the DOS header.");
            }
        }
    }

    static DateTime UnixTimeStampToDateTime(uint unixTimeStamp)
    {
        // Convert the Unix timestamp to DateTime
        DateTime unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        return unixEpoch.AddSeconds(unixTimeStamp).ToLocalTime();
    }
}
