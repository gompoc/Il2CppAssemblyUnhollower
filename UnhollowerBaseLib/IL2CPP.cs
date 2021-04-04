using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using UnhollowerBaseLib.Attributes;
using UnhollowerBaseLib.Runtime;
using UnhollowerRuntimeLib;

namespace UnhollowerBaseLib
{
    public static unsafe class IL2CPP
    {
        private static Dictionary<string, IntPtr> ourImagesMap = new Dictionary<string, IntPtr>();
        
        static IL2CPP()
        {
            var domain = il2cpp_domain_get();
            if (domain == IntPtr.Zero)
            {
                LogSupport.Error("No il2cpp domain found; sad!");
                return;
            }
            uint assembliesCount = 0;
            var assemblies = il2cpp_domain_get_assemblies(domain, ref assembliesCount);
            for (var i = 0; i < assembliesCount; i++)
            {
                var image = il2cpp_assembly_get_image(assemblies[i]);
                var name = Marshal.PtrToStringAnsi(il2cpp_image_get_name(image));
                ourImagesMap[name] = image;
            }
        }

        public static IntPtr GetIl2CppClass(string assemblyName, string namespaze, string className)
        {
            if (!ourImagesMap.TryGetValue(assemblyName, out var image))
            {
                LogSupport.Error($"Assembly {assemblyName} is not registered in il2cpp");
                return IntPtr.Zero;
            }
            
            var clazz = il2cpp_class_from_name(image, namespaze, className);
            return clazz;
        }

        public static IntPtr GetIl2CppField(IntPtr clazz, string fieldName)
        {
            if(clazz == IntPtr.Zero) return IntPtr.Zero;

            var field = il2cpp_class_get_field_from_name(clazz, fieldName);
            if (field == IntPtr.Zero)
                LogSupport.Error($"Field {fieldName} was not found on class {Marshal.PtrToStringAnsi(il2cpp_class_get_name(clazz))}");
            return field;
        }

        public static IntPtr GetIl2CppMethodByToken(IntPtr clazz, int token)
        {
            if (clazz == IntPtr.Zero)
                return NativeStructUtils.GetMethodInfoForMissingMethod(token.ToString());
            
            IntPtr iter = IntPtr.Zero;
            IntPtr method;
            while ((method = il2cpp_class_get_methods(clazz, ref iter)) != IntPtr.Zero)
            {
                if (il2cpp_method_get_token(method) == token)
                    return method;
            }
            
            var className = Marshal.PtrToStringAnsi(il2cpp_class_get_name(clazz));
            LogSupport.Trace($"Unable to find method {className}::{token}");
            
            return NativeStructUtils.GetMethodInfoForMissingMethod(className + "::" + token);
        }

        public static IntPtr GetIl2CppMethod(IntPtr clazz, bool isGeneric, string methodName, string returnTypeName, params string[] argTypes)
        {
            if(clazz == IntPtr.Zero) return NativeStructUtils.GetMethodInfoForMissingMethod(methodName + "(" + string.Join(", ", argTypes) + ")");

            returnTypeName = Regex.Replace(returnTypeName, "\\`\\d+", "").Replace('/', '.').Replace('+', '.');
            for (var index = 0; index < argTypes.Length; index++)
            {
                var argType = argTypes[index];
                argTypes[index] = Regex.Replace(argType, "\\`\\d+", "").Replace('/', '.').Replace('+', '.');
            }

            var methodsSeen = 0;
            var lastMethod = IntPtr.Zero;
            IntPtr iter = IntPtr.Zero;
            IntPtr method;
            while ((method = il2cpp_class_get_methods(clazz, ref iter)) != IntPtr.Zero)
            {
                if(Marshal.PtrToStringAnsi(il2cpp_method_get_name(method)) != methodName)
                    continue;
                
                if(il2cpp_method_get_param_count(method) != argTypes.Length)
                    continue;
                
                if(il2cpp_method_is_generic(method) != isGeneric) 
                    continue;

                var returnType = il2cpp_method_get_return_type(method);
                var returnTypeNameActual = Marshal.PtrToStringAnsi(il2cpp_type_get_name(returnType));
                if (returnTypeNameActual != returnTypeName)
                    continue;
                
                methodsSeen++;
                lastMethod = method;

                var badType = false;
                for (var i = 0; i < argTypes.Length; i++)
                {
                    var paramType = il2cpp_method_get_param(method, (uint) i);
                    var typeName = Marshal.PtrToStringAnsi(il2cpp_type_get_name(paramType));
                    if (typeName != argTypes[i])
                    {
                        badType = true;
                        break;
                    }
                }
                
                if(badType) continue;

                return method;
            }

            var className = Marshal.PtrToStringAnsi(il2cpp_class_get_name(clazz));

            if (methodsSeen == 1)
            {
                LogSupport.Trace($"Method {className}::{methodName} was stubbed with a random matching method of the same name");
                LogSupport.Trace($"Stubby return type/target: {Marshal.PtrToStringAnsi(il2cpp_type_get_name(il2cpp_method_get_return_type(lastMethod)))} / {returnTypeName}");
                LogSupport.Trace("Stubby parameter types/targets follow:");
                for (var i = 0; i < argTypes.Length; i++)
                {
                    var paramType = il2cpp_method_get_param(lastMethod, (uint) i);
                    var typeName = Marshal.PtrToStringAnsi(il2cpp_type_get_name(paramType));
                    LogSupport.Trace($"    {typeName} / {argTypes[i]}");
                }
                
                return lastMethod;
            }
            
            LogSupport.Trace($"Unable to find method {className}::{methodName}; signature follows");
            LogSupport.Trace($"    return {returnTypeName}");
            foreach (var argType in argTypes) LogSupport.Trace($"    {argType}");
            LogSupport.Trace("Available methods of this name follow:");
            iter = IntPtr.Zero;
            while ((method = il2cpp_class_get_methods(clazz, ref iter)) != IntPtr.Zero)
            {
                if(Marshal.PtrToStringAnsi(il2cpp_method_get_name(method)) != methodName)
                    continue;

                var nParams = il2cpp_method_get_param_count(method);
                LogSupport.Trace("Method starts");
                LogSupport.Trace($"     return {Marshal.PtrToStringAnsi(il2cpp_type_get_name(il2cpp_method_get_return_type(method)))}");
                for (var i = 0; i < nParams; i++)
                {
                    var paramType = il2cpp_method_get_param(method, (uint) i);
                    var typeName = Marshal.PtrToStringAnsi(il2cpp_type_get_name(paramType));
                    LogSupport.Trace($"    {typeName}");
                }
                
                return method;
            }

            return NativeStructUtils.GetMethodInfoForMissingMethod(className + "::" + methodName + "(" + string.Join(", ", argTypes) + ")");
        }

        public static string Il2CppStringToManaged(IntPtr il2CppString)
        {
            if (il2CppString == IntPtr.Zero) return null;
            
            var length = il2cpp_string_length(il2CppString);
            var chars = il2cpp_string_chars(il2CppString);
            
            return new string(chars, 0, length);
        }

        public static IntPtr ManagedStringToIl2Cpp(string str)
        {
            if(str == null) return IntPtr.Zero;
            
            fixed (char* chars = str)
                return il2cpp_string_new_utf16(chars, str.Length);
        }

        public static IntPtr Il2CppObjectBaseToPtr(Il2CppObjectBase obj)
        {
            return obj?.Pointer ?? IntPtr.Zero;
        }
        
        public static IntPtr Il2CppObjectBaseToPtrNotNull(Il2CppObjectBase obj)
        {
            return obj?.Pointer ?? throw new NullReferenceException();
        }

        public static IntPtr GetIl2CppNestedType(IntPtr enclosingType, string nestedTypeName)
        {
            if(enclosingType == IntPtr.Zero) return IntPtr.Zero;
            
            IntPtr iter = IntPtr.Zero;
            IntPtr nestedTypePtr;
            if (il2cpp_class_is_inflated(enclosingType))
            {
                LogSupport.Trace("Original class was inflated, falling back to reflection");
                
                return RuntimeReflectionHelper.GetNestedTypeViaReflection(enclosingType, nestedTypeName);
            }
            while((nestedTypePtr = il2cpp_class_get_nested_types(enclosingType, ref iter)) != IntPtr.Zero)
            {
                if (Marshal.PtrToStringAnsi(il2cpp_class_get_name(nestedTypePtr)) == nestedTypeName)
                    return nestedTypePtr;
            }
            
            LogSupport.Error($"Nested type {nestedTypeName} on {Marshal.PtrToStringAnsi(il2cpp_class_get_name(enclosingType))} not found!");
            
            return IntPtr.Zero;
        }

        public static void ThrowIfNull(object arg)
        {
            if (arg == null)
                throw new NullReferenceException();
        }

        public static T ResolveICall<T>(string signature) where T : Delegate
        {
            
            var icallPtr = il2cpp_resolve_icall(signature);
            if (icallPtr == IntPtr.Zero)
            {
                LogSupport.Trace($"ICall {signature} not resolved");
                return GenerateDelegateForMissingICall<T>(signature);
            }

            return Marshal.GetDelegateForFunctionPointer<T>(icallPtr);
        }

        private static T GenerateDelegateForMissingICall<T>(string signature) where T: Delegate
        {
            var invoke = typeof(T).GetMethod("Invoke")!;
            
            var trampoline = new DynamicMethod("(missing icall delegate) " + typeof(T).FullName, MethodAttributes.Static, CallingConventions.Standard, invoke.ReturnType, invoke.GetParameters().Select(it => it.ParameterType).ToArray(), typeof(IL2CPP), true);
            var bodyBuilder = trampoline.GetILGenerator();

            bodyBuilder.Emit(OpCodes.Ldstr, $"ICall with signature {signature} was not resolved");
            bodyBuilder.Emit(OpCodes.Newobj, typeof(Exception).GetConstructor(new[]{ typeof(string)})!);
            bodyBuilder.Emit(OpCodes.Throw);

            return (T) trampoline.CreateDelegate(typeof(T));
        }

        private static readonly MethodInfo UnboxMethod = typeof(Il2CppObjectBase).GetMethod(nameof(Il2CppObjectBase.Unbox));
        private static readonly MethodInfo CastMethod = typeof(Il2CppObjectBase).GetMethod(nameof(Il2CppObjectBase.Cast));
        public static T PointerToValueGeneric<T>(IntPtr objectPointer, bool isFieldPointer, bool valueTypeWouldBeBoxed)
        {
            if (isFieldPointer)
            {
                if (il2cpp_class_is_valuetype(Il2CppClassPointerStore<T>.NativeClassPtr))
                    objectPointer = il2cpp_value_box(Il2CppClassPointerStore<T>.NativeClassPtr, objectPointer);
                else
                    objectPointer = *(IntPtr*) objectPointer;
            }
            
            if (!valueTypeWouldBeBoxed && il2cpp_class_is_valuetype(Il2CppClassPointerStore<T>.NativeClassPtr))
                objectPointer = il2cpp_value_box(Il2CppClassPointerStore<T>.NativeClassPtr, objectPointer);

            if (typeof(T) == typeof(string))
                return (T) (object) Il2CppStringToManaged(objectPointer);

            if (objectPointer == IntPtr.Zero)
                return default;
            
            var nativeObject = new Il2CppObjectBase(objectPointer);
            if (typeof(T).IsValueType)
                return (T) UnboxMethod.MakeGenericMethod(typeof(T)).Invoke(nativeObject, new object[0]);
            return (T) CastMethod.MakeGenericMethod(typeof(T)).Invoke(nativeObject, new object[0]);
        }

        public static string RenderTypeName<T>(bool addRefMarker = false)
        {
            return RenderTypeName(typeof(T), addRefMarker);
        }

        public static string RenderTypeName(Type t, bool addRefMarker = false)
        {
            if (addRefMarker) return RenderTypeName(t) + "&";
            if (t.IsArray) return RenderTypeName(t.GetElementType()) + "[]";
            if (t.IsByRef) return RenderTypeName(t.GetElementType()) + "&";
            if (t.IsPointer) return RenderTypeName(t.GetElementType()) + "*";
            if (t.IsGenericParameter) return t.Name;

            if (t.IsGenericType)
            {
                if (t.TypeHasIl2CppArrayBase())
                    return RenderTypeName(t.GetGenericArguments()[0]) + "[]";
                
                var builder = new StringBuilder();
                builder.Append(t.GetGenericTypeDefinition().FullNameObfuscated().TrimIl2CppPrefix());
                builder.Append('<');
                var genericArguments = t.GetGenericArguments();
                for (var i = 0; i < genericArguments.Length; i++)
                {
                    if (i != 0) builder.Append(',');
                    builder.Append(RenderTypeName(genericArguments[i]));
                }
                builder.Append('>');
                return builder.ToString();
            }

            if (t == typeof(Il2CppStringArray))
                return "System.String[]";

            return t.FullNameObfuscated().TrimIl2CppPrefix();
        }

        private static string FullNameObfuscated(this Type t)
        {
            var obfuscatedNameAnnotations = t.GetCustomAttribute<ObfuscatedNameAttribute>();
            if (obfuscatedNameAnnotations == null) return t.FullName;
            return obfuscatedNameAnnotations.ObfuscatedName;
        }

        private static string TrimIl2CppPrefix(this string s)
        {
            return s.StartsWith("Il2Cpp") ? s.Substring("Il2Cpp".Length) : s;
        }

        private static bool TypeHasIl2CppArrayBase(this Type type)
        {
            if (type == null) return false;
            if (type.IsConstructedGenericType) type = type.GetGenericTypeDefinition();
            if (type == typeof(Il2CppArrayBase<>)) return true;
            return TypeHasIl2CppArrayBase(type.BaseType);
        }

        // IL2CPP Functions
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_init(IntPtr domain_name);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_init_utf16(IntPtr domain_name);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_shutdown();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_set_config_dir(IntPtr config_path);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_set_data_dir(IntPtr data_path);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_set_temp_dir(IntPtr temp_path);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_set_commandline_arguments(int argc, IntPtr argv, IntPtr basedir);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_set_commandline_arguments_utf16(int argc, IntPtr argv, IntPtr basedir);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_set_config_utf16(IntPtr executablePath);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_set_config(IntPtr executablePath);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_set_memory_callbacks(IntPtr callbacks);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_get_corlib();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_add_internal_call(IntPtr name, IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_resolve_icall([MarshalAs(UnmanagedType.LPStr)] string name);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_alloc(uint size);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_free(IntPtr ptr);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_array_class_get(IntPtr element_class, uint rank);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_array_length(IntPtr array);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_array_get_byte_length(IntPtr array);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_array_new(IntPtr elementTypeInfo, ulong length);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_array_new_specific(IntPtr arrayTypeInfo, ulong length);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_array_new_full(IntPtr array_class, ref ulong lengths, ref ulong lower_bounds);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_bounded_array_class_get(IntPtr element_class, uint rank, bool bounded);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_array_element_size(IntPtr array_class);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_assembly_get_image(IntPtr assembly);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_enum_basetype(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_is_generic(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_is_inflated(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_is_assignable_from(IntPtr klass, IntPtr oklass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_is_subclass_of(IntPtr klass, IntPtr klassc, bool check_interfaces);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_has_parent(IntPtr klass, IntPtr klassc);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_from_il2cpp_type(IntPtr type);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_from_name(IntPtr image, [MarshalAs(UnmanagedType.LPStr)] string namespaze, [MarshalAs(UnmanagedType.LPStr)] string name);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_from_system_type(IntPtr type);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_element_class(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_events(IntPtr klass, ref IntPtr iter);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_fields(IntPtr klass, ref IntPtr iter);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_nested_types(IntPtr klass, ref IntPtr iter);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_interfaces(IntPtr klass, ref IntPtr iter);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_properties(IntPtr klass, ref IntPtr iter);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_property_from_name(IntPtr klass, IntPtr name);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_field_from_name(IntPtr klass, [MarshalAs(UnmanagedType.LPStr)] string name);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_methods(IntPtr klass, ref IntPtr iter);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_method_from_name(IntPtr klass, [MarshalAs(UnmanagedType.LPStr)] string name, int argsCount);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_name(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_namespace(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_parent(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_declaring_type(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_class_instance_size(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_class_num_fields(IntPtr enumKlass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_is_valuetype(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_class_value_size(IntPtr klass, ref uint align);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_is_blittable(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_class_get_flags(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_is_abstract(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_is_interface(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_class_array_element_size(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_from_type(IntPtr type);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_type(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_class_get_type_token(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_has_attribute(IntPtr klass, IntPtr attr_class);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_has_references(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_class_is_enum(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_image(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_class_get_assemblyname(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_class_get_rank(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_class_get_bitmap_size(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_class_get_bitmap(IntPtr klass, ref uint bitmap);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_stats_dump_to_file(IntPtr path);
        // [MethodImpl(MethodImplOptions.InternalCall)]
        //public extern static ulong il2cpp_stats_get_value(IL2CPP_Stat stat);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_domain_get();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_domain_assembly_open(IntPtr domain, IntPtr name);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr* il2cpp_domain_get_assemblies(IntPtr domain, ref uint size);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_exception_from_name_msg(IntPtr image, IntPtr name_space, IntPtr name, IntPtr msg);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_get_exception_argument_null(IntPtr arg);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_format_exception(IntPtr ex, void* message, int message_size);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_format_stack_trace(IntPtr ex, void* output, int output_size);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_unhandled_exception(IntPtr ex);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_field_get_flags(IntPtr field);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_field_get_name(IntPtr field);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_field_get_parent(IntPtr field);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_field_get_offset(IntPtr field);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_field_get_type(IntPtr field);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_field_get_value(IntPtr obj, IntPtr field, void* value);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_field_get_value_object(IntPtr field, IntPtr obj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_field_has_attribute(IntPtr field, IntPtr attr_class);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_field_set_value(IntPtr obj, IntPtr field, void* value);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_field_static_get_value(IntPtr field, void* value);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_field_static_set_value(IntPtr field, void* value);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_field_set_value_object(IntPtr instance, IntPtr field, IntPtr value);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_gc_collect(int maxGenerations);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_gc_collect_a_little();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_gc_disable();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_gc_enable();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_gc_is_disabled();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern long il2cpp_gc_get_used_size();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern long il2cpp_gc_get_heap_size();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_gc_wbarrier_set_field(IntPtr obj, out IntPtr targetAddress, IntPtr gcObj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_gchandle_new(IntPtr obj, bool pinned);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_gchandle_new_weakref(IntPtr obj, bool track_resurrection);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_gchandle_get_target(uint gchandle);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_gchandle_free(uint gchandle);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_unity_liveness_calculation_begin(IntPtr filter, int max_object_count, IntPtr callback, IntPtr userdata, IntPtr onWorldStarted, IntPtr onWorldStopped);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_unity_liveness_calculation_end(IntPtr state);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_unity_liveness_calculation_from_root(IntPtr root, IntPtr state);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_unity_liveness_calculation_from_statics(IntPtr state);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_method_get_return_type(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_method_get_declaring_type(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_method_get_name(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_method_get_from_reflection(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_method_get_object(IntPtr method, IntPtr refclass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_method_is_generic(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_method_is_inflated(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_method_is_instance(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_method_get_param_count(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_method_get_param(IntPtr method, uint index);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_method_get_class(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_method_has_attribute(IntPtr method, IntPtr attr_class);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_method_get_flags(IntPtr method, ref uint iflags);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_method_get_token(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_method_get_param_name(IntPtr method, uint index);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_profiler_install(IntPtr prof, IntPtr shutdown_callback);
        // [MethodImpl(MethodImplOptions.InternalCall)]
        // public extern static void il2cpp_profiler_set_events(IL2CPP_ProfileFlags events);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_profiler_install_enter_leave(IntPtr enter, IntPtr fleave);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_profiler_install_allocation(IntPtr callback);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_profiler_install_gc(IntPtr callback, IntPtr heap_resize_callback);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_profiler_install_fileio(IntPtr callback);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_profiler_install_thread(IntPtr start, IntPtr end);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_property_get_flags(IntPtr prop);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_property_get_get_method(IntPtr prop);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_property_get_set_method(IntPtr prop);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_property_get_name(IntPtr prop);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_property_get_parent(IntPtr prop);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_object_get_class(IntPtr obj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_object_get_size(IntPtr obj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_object_get_virtual_method(IntPtr obj, IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_object_new(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_object_unbox(IntPtr obj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_value_box(IntPtr klass, IntPtr data);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_monitor_enter(IntPtr obj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_monitor_try_enter(IntPtr obj, uint timeout);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_monitor_exit(IntPtr obj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_monitor_pulse(IntPtr obj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_monitor_pulse_all(IntPtr obj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_monitor_wait(IntPtr obj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_monitor_try_wait(IntPtr obj, uint timeout);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern unsafe IntPtr il2cpp_runtime_invoke(IntPtr method, IntPtr obj, void** param, ref IntPtr exc);
        [MethodImpl(MethodImplOptions.InternalCall)]
        // param can be of Il2CppObject*
        public static extern unsafe IntPtr il2cpp_runtime_invoke_convert_args(IntPtr method, IntPtr obj, void** param, int paramCount, ref IntPtr exc);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_runtime_class_init(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_runtime_object_init(IntPtr obj);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_runtime_object_init_exception(IntPtr obj, ref IntPtr exc);
        // [MethodImpl(MethodImplOptions.InternalCall)]
        // public extern static void il2cpp_runtime_unhandled_exception_policy_set(IL2CPP_RuntimeUnhandledExceptionPolicy value);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_string_length(IntPtr str);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern unsafe char* il2cpp_string_chars(IntPtr str);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_string_new(string str);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_string_new_len(string str, uint length);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_string_new_utf16(char* text, int len);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_string_new_wrapper(string str);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_string_intern(string str);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_string_is_interned(string str);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_thread_current();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_thread_attach(IntPtr domain);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_thread_detach(IntPtr thread);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern unsafe void** il2cpp_thread_get_all_attached_threads(ref uint size);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_is_vm_thread(IntPtr thread);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_current_thread_walk_frame_stack(IntPtr func, IntPtr user_data);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_thread_walk_frame_stack(IntPtr thread, IntPtr func, IntPtr user_data);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_current_thread_get_top_frame(IntPtr frame);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_thread_get_top_frame(IntPtr thread, IntPtr frame);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_current_thread_get_frame_at(int offset, IntPtr frame);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_thread_get_frame_at(IntPtr thread, int offset, IntPtr frame);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_current_thread_get_stack_depth();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_thread_get_stack_depth(IntPtr thread);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_type_get_object(IntPtr type);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern int il2cpp_type_get_type(IntPtr type);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_type_get_class_or_element_class(IntPtr type);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_type_get_name(IntPtr type);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_type_is_byref(IntPtr type);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_type_get_attrs(IntPtr type);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_type_equals(IntPtr type, IntPtr otherType);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_type_get_assembly_qualified_name(IntPtr type);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_image_get_assembly(IntPtr image);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_image_get_name(IntPtr image);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_image_get_filename(IntPtr image);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_image_get_entry_point(IntPtr image);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern uint il2cpp_image_get_class_count(IntPtr image);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_image_get_class(IntPtr image, uint index);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_capture_memory_snapshot();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_free_captured_memory_snapshot(IntPtr snapshot);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_set_find_plugin_callback(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_register_log_callback(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_debugger_set_agent_options(IntPtr options);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_is_debugger_attached();
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern unsafe void il2cpp_unity_install_unitytls_interface(void* unitytlsInterfaceStruct);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_custom_attrs_from_class(IntPtr klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_custom_attrs_from_method(IntPtr method);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_custom_attrs_get_attr(IntPtr ainfo, IntPtr attr_klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool il2cpp_custom_attrs_has_attr(IntPtr ainfo, IntPtr attr_klass);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern IntPtr il2cpp_custom_attrs_construct(IntPtr cinfo);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void il2cpp_custom_attrs_free(IntPtr ainfo);
    }
}
