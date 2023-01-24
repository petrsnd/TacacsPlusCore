using System;
using System.Runtime.InteropServices;

namespace Petrsnd.TacacsPlusCore.Utils
{
    public static class StructConverter
    {
        public static byte[] StructToBytes<T>(T structure) where T : struct
        {
            var size = Marshal.SizeOf(structure);
            var bytes = new byte[size];

            var ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(structure, ptr, true);
            Marshal.Copy(ptr, bytes, 0, size);
            Marshal.FreeHGlobal(ptr);

            var type = typeof(T);
            SwapEndianness(ref bytes, type);

            return bytes;
        }

        public static T BytesToStruct<T>(byte[] bytes) where T : struct
        {
            var structure = default(T);
            var size = Marshal.SizeOf(typeof(T));
            var ptr = Marshal.AllocHGlobal(size);

            var type = typeof(T);
            SwapEndianness(ref bytes, type);
            Marshal.Copy(bytes, 0, ptr, size);
            // swap again here to restore endianness? Just don't use the buffer again

            structure = (T)Marshal.PtrToStructure(ptr, structure.GetType());
            Marshal.FreeHGlobal(ptr);

            return structure;
        }

        private static void SwapEndianness(ref byte[] bytes, Type type)
        {
            if (BitConverter.IsLittleEndian)
            {
                foreach (var field in type.GetFields())
                {
                    var fieldType = field.FieldType;
                    if (field.IsStatic || fieldType == typeof(string) || fieldType == typeof(byte[]))
                        continue;
                    if (fieldType.IsEnum)
                        fieldType = Enum.GetUnderlyingType(fieldType);
                    var offset = Marshal.OffsetOf(type, field.Name).ToInt32();
                    if (Marshal.SizeOf(fieldType) > 1)
                        Array.Reverse(bytes, offset, Marshal.SizeOf(fieldType));
                }
            }
        }
    }
}
